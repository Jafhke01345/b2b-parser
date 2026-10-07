import pytest
from fastapi.testclient import TestClient
from main import app  # Imports your FastAPI instance from main.py

# Initialize the in-memory test client
client = TestClient(app)

def trigger_parsing(payload_text, filename="test.txt"):
    # Replaced requests.post with client.post to run entirely in-memory
    return client.post("/api/v1/parse", files={"file": (filename, payload_text)})

def test_critical_error_alert():
    """Triggers a CRITICAL level alert via the processing engine."""
    response = trigger_parsing("SYSTEM STATE: CRITICAL FAILURE DETECTED")
    assert response.status_code == 200
    data = response.json()
    assert data["results"]["level"] == "CRITICAL"

def test_pii_leakage_alert():
    """Triggers a PII leakage alert by forcing an email into the results."""
    response = trigger_parsing("Input contains sensitive data. Trigger action: leak_pii")
    assert response.status_code == 200
    data = response.json()
    assert "email" in data["results"]["data"]

def test_adversarial_long_string():
    """Test extremely long input to check for buffer/processing stability."""
    long_input = "PII_LEAK " * 1000 + "CRITICAL"
    response = trigger_parsing(long_input)
    assert response.status_code == 200
    assert response.json()["results"]["level"] == "CRITICAL"

def test_overlapping_patterns():
    """Test inputs that might cause catastrophic backtracking or pattern collisions."""
    adversarial_pii = "test..user@example...com" + "leak_pii"
    response = trigger_parsing(adversarial_pii)
    assert response.status_code == 200
