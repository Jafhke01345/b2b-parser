from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
import json

app = FastAPI(title="Deterministic Workflow Engine")

# Enable CORS for local React development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AuditRecord(BaseModel):
    source_quote: str
    parsed_data: dict
    status: str

def run_geometric_anchor_check(file_metadata: dict) -> bool:
    """
    Enforces the >5% Column Shift Guardrail.
    Returns True if stable, False triggers a LAYOUT_ERROR.
    """
    # Example logic: Compare coordinate anchors against baseline
    baseline_x = file_metadata.get("baseline_x", 0)
    current_x = file_metadata.get("current_x", 0)
    
    if baseline_x == 0:
        return True
        
    variance = abs(current_x - baseline_x) / baseline_x
    if variance > 0.05:
        return False
    return True

@app.post("/api/v1/parse")
async def parse_document(file: UploadFile = File(...)):
    # 1. Enforce Strict String-First Ingestion
    try:
        raw_contents = await file.read()
        # Decode as raw string text to preserve leading zeros
        string_payload = raw_contents.decode("utf-8", errors="ignore")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Ingestion Error: {str(e)}")

    # Mock metadata calculation for geometric boundaries
    mock_metadata = {"baseline_x": 100, "current_x": 106}  # 6% shift
    
    # 2. Trigger Circuit Breaker on Anchor Shift
    if not run_geometric_anchor_check(mock_metadata):
        raise HTTPException(
            status_code=422, 
            detail="LAYOUT_ERROR: Column shift detected greater than 5% threshold."
        )

    # 3. Process Deterministic Parsing Logic (Example)
    # This is where your Pattern Architect regex logic will sit
    sanitized_output = {}
    
    return {
        "filename": file.filename,
        "status": "SUCCESS",
        "audit": {
            "source_quote": string_payload[:100],  # Auditable snippet
            "parsed_data": sanitized_output
        }
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
