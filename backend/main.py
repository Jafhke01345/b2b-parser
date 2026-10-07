import base64
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, BackgroundTasks, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3
import os
import re
import json
import hmac
import hashlib
import httpx
import uvicorn
from datetime import datetime

DB_PATH = os.getenv("B2B_PARSER_DB_PATH", "alerts.db")

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                alert_type TEXT,
                detail TEXT
            )
        """)
    return conn

init_db()

MASTER_SIGNING_SECRET = os.getenv("B2B_PARSER_SIGNING_SECRET", "default-dev-secret")

async def verify_local_license(x_license_key: str = Header(None)):
    if not x_license_key:
        raise HTTPException(status_code=401, detail="Missing license key header")
    
    try:
        payload, signature = x_license_key.split('.')
        expected_sig = hmac.new(
            MASTER_SIGNING_SECRET.encode(), 
            payload.encode(), 
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(signature, expected_sig):
            raise HTTPException(status_code=403, detail="Invalid license signature")
    except (ValueError, AttributeError):
        raise HTTPException(status_code=400, detail="Malformed license key")

app = FastAPI(title="Deterministic Workflow Engine")

# Configurable Local Webhook Endpoint
WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL", "http://localhost:5000/alerts")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AlertManager:
    """Monitors parsed results for critical issues and PII leakage."""
    
    PII_PATTERNS = {
        "email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    }

    @staticmethod
    async def dispatch_alert(alert_type: str, detail: dict):
        """Deterministic POST request to local alerting endpoint and SQLite persistence."""
        payload = {"event": "SECURITY_ALERT", "type": alert_type, "detail": detail}
        
        # Local Persistence Layer
        try:
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute(
                    "INSERT INTO metrics (timestamp, alert_type, detail) VALUES (?, ?, ?)",
                    (datetime.utcnow().isoformat(), alert_type, json.dumps(detail))
                )
        except Exception as db_e:
            print(f"Database Persistence Failed: {db_e}")

        try:
            async with httpx.AsyncClient() as client:
                await client.post(WEBHOOK_URL, json=payload, timeout=2.0)
        except Exception as e:
            print(f"Webhook Dispatch Failed: {e}")

    async def check_results(self, results: dict, rules: dict = None):
        """Analyzes output for critical levels or redaction failures."""
        if results.get("level") == "CRITICAL":
            await self.dispatch_alert("CRITICAL_ERROR", {"level": "CRITICAL", "message": results.get("message", "No message provided")})
        
        parsed_str = json.dumps(results)
        for pii_type, pattern in self.PII_PATTERNS.items():
            is_enabled = rules.get(pii_type, True) if rules else True
            if is_enabled and re.search(pattern, parsed_str):
                await self.dispatch_alert("PII_LEAKAGE", {"leakage_type": pii_type})

alert_manager = AlertManager()

class AuditRecord(BaseModel):
    source_quote: str
    parsed_data: dict
    status: str

def run_geometric_anchor_check(file_metadata: dict) -> bool:
    baseline_x = file_metadata.get("baseline_x", 0)
    current_x = file_metadata.get("current_x", 0)
    if baseline_x == 0: return True
    return (abs(current_x - baseline_x) / baseline_x) <= 0.05

@app.post("/api/v1/parse", dependencies=[Depends(verify_local_license)])
async def parse_document(background_tasks: BackgroundTasks, file: UploadFile = File(...), rules: str = Form("{}")):
    try:
        raw_contents = await file.read()
        string_payload = raw_contents.decode("utf-8", errors="ignore")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Ingestion Error: {str(e)}")

    # Red Team Logic: Trigger based on payload content to test alerting system
    parsed_results = {"status": "SUCCESS", "level": "INFO", "message": "Processed normally"}
    if "CRITICAL" in string_payload:
        parsed_results["level"] = "CRITICAL"
        parsed_results["message"] = "Critical failure detected."
    if "leak_pii" in string_payload:
        parsed_results["data"] = {"leaked_email": "redteam@example.com"}

    try:
        rules_dict = json.loads(rules)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid rules JSON")
        
    background_tasks.add_task(alert_manager.check_results, parsed_results, rules_dict)

    return {
        "filename": file.filename,
        "status": "SUCCESS",
        "results": parsed_results,
        "audit": {"source_quote": string_payload[:100], "parsed_data": parsed_results.get("data", {})}
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
