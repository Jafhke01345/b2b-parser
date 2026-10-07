import pytest
import requests
import time

BASE_URL = "http://localhost:8000/api/v1/parse"

def trigger_parsing(payload_text, filename="test.txt"):
    return requests.post(BASE_URL, files={"file": (filename, payload_text)})

def test_critical_error_alert():
    """Triggers a CRITICAL level alert via the processing engine."""
    # The 'CRITICAL' keyword is mapped to trigger a CRITICAL result in our mock backend
    response = trigger_parsing("SYSTEM STATE: CRITICAL FAILURE DETECTED")
    assert response.status_code == 200
    data = response.json()
    assert data["results"]["level"] == "CRITICAL"

def test_pii_leakage_alert():
    """Triggers a PII leakage alert by forcing an email into the results."""
    # The 'leak_pii' keyword forces a leaked email in our mock backend
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
    # Overlapping patterns (e.g., email-like structure with multiple dots)
    adversarial_pii = "test..user@example...com" + "leak_pii"
    response = trigger_parsing(adversarial_pii)
    assert response.status_code == 200
