import json
import re

def parse_cloudtrail(text: str):
    """
    Deterministic CloudTrail JSON parser.
    Ensures high-precision IDs and timestamps remain strings.
    """
    records = []
    try:
        # CloudTrail logs can be a single object or a list of 'Records'
        data = json.loads(text)
        events = data.get('Records', [data]) if isinstance(data, dict) else (data if isinstance(data, list) else [])
        
        for event in events:
            # Extract strictly as strings to avoid float precision loss on timestamps/IDs
            timestamp = str(event.get('eventTime', 'UNKNOWN'))
            level = "INFO"
            msg = f"Event {event.get('eventName', 'unknown')}: {event.get('sourceIpAddress', 'N/A')}"
            category = "AWS_AUDIT"
            
            # Detect specific error patterns for level mapping
            if "ErrorCode" in event or "errorMessage" in event:
                level = "ERROR"
                category = "SECURITY_ALERT"
            
            records.append({
                "timestamp": timestamp,
                "level": level,
                "message": msg,
                "category": category # Added for compliance metrics aggregation
            })
    except json.JSONDecodeError:
        records.append({
            "timestamp": "ERROR",
            "level": "CRITICAL",
            "message": "Invalid CloudTrail JSON format",
            "category": "FORMAT_ERROR"
        })
    return records

def parse_hl7(text: str):
    """
    Deterministic HL7 v2 parser based on segment delimiters.
    Preserves strict string representation of Patient IDs and Timestamps.
    """
    records = []
    # HL7 segments are usually separated by \n or \r, fields by |
    segments = text.strip().splitlines()
    
    for seg in segments:
        fields = seg.split('|')
        seg_type = fields[0] if fields else "UNKNOWN"
        
        # Extract only specific safe markers to demonstrate deterministic parsing
        if seg_type == 'MSH': # Message Header
            timestamp = fields[6] if len(fields) > 6 else "UNKNOWN"
            records.append({
                "timestamp": timestamp,
                "level": "INFO",
                "message": f"HL7 Message Received: {seg_type}",
                "category": "HEALTHCARE_INFRA"
            })
        elif seg_type == 'PID': # Patient Identification
            # Strictly string-based ID extraction to avoid coercion of long IDs
            patient_id = fields[3] if len(fields) > 3 else "UNKNOWN"
            records.append({
                "timestamp": "CURRENT",
                "level": "INFO",
                "message": f"Patient Record Access: {patient_id}",
                "category": "HIPAA_SENSITIVE"
            })
        elif 'ERR' in seg_type or 'ACK' in seg_type and 'AE' in seg:
            records.append({
                "timestamp": "CURRENT",
                "level": "ERROR",
                "message": f"HL7 Processing Error in segment {seg_type}",
                "category": "DATA_INTEGRITY"
            })
    
    return records

def parse_kubernetes(text: str):
    """
    Deterministic Kubernetes JSON log parser.
    Handles clusters of JSON logs, ensuring content remains strings.
    """
    records = []
    lines = text.strip().splitlines()
    for line in lines:
        if not line.strip(): continue
        try:
            # K8s logs are typically JSON-per-line (JSONL)
            log_entry = json.loads(line)
            timestamp = str(log_entry.get('time', 'UNKNOWN'))
            message = str(log_entry.get('log', 'No log content'))
            stream = str(log_entry.get('stream', 'stdout'))
            pod = str(log_entry.get('pod_name', 'unknown-pod')) if isinstance(log_entry, dict) else 'unknown'
            level = "INFO"
            if any(word in message.upper() for word in ["ERROR", "CRITICAL", "FATAL"]):
                level = "ERROR"
            elif "WARN" in message.upper():
                level = "WARNING"
            records.append({
                "timestamp": timestamp,
                "level": level,
                "message": f"[{pod}] {stream}: {message}",
                "category": "K8S_INFRA"
            })
        except json.JSONDecodeError:
            # Treat non-JSON lines as raw log messages (fallback)
            records.append({
                "timestamp": "UNKNOWN",
                "level": "INFO",
                "message": line,
                "category": "K8S_RAW"
            })
    return records

def detect_format(text: str) -> str:

    """Heuristic to determine if content is JSON (CloudTrail) or HL7."""
    stripped = text.strip()
    if stripped.startswith('{') or stripped.startswith('['):
        # Distinguish CloudTrail from K8s based on known keys
        if '"Records"' in stripped or 'eventTime' in stripped:
            return 'cloudtrail'
        if '"log"' in stripped and ('stream' in stripped or 'time' in stripped):
            return 'kubernetes'
        return 'cloudtrail' # Default JSON to cloudtrail logic for consistency
    if '|' in stripped and ('MSH|' in stripped or 'PID|' in stripped):
        return 'hl7'
    return 'generic'

def process_payload(text: str):
    """Orchestrates deterministic parsing based on detected format."""
    fmt = detect_format(text)
    if fmt == 'cloudtrail':
        return parse_cloudtrail(text)
    elif fmt == 'kubernetes':
        return parse_kubernetes(text)
    elif fmt == 'hl7':
        return parse_hl7(text)
    else:
        # Generic fallback parser for standard logs
        lines = text.splitlines()
        return [
            {"timestamp": "UNKNOWN", "level": "INFO", "message": line, "category": "GENERIC"} 
            for line in lines if line.strip()
        ]
