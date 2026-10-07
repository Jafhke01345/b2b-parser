import os
import sys

def validate_environment():
    """
    Ensures required environment variables are set for the B2B Parser to operate securely.
    Replaces old string-obfuscation logic with runtime configuration verification.
    """
    required_vars = {
        "B2B_PARSER_DB_PATH": "Path to the SQLite metrics database",
        "B2B_PARSER_SIGNING_SECRET": "Secret key for license signature verification",
        "ALERT_WEBHOOK_URL": "Endpoint for security alerts",
    }
    
    missing = []
    for var, desc in required_vars.items():
        if var not in os.environ:
            print(f"[!] Missing Config: {var} - {desc}")
            missing.append(var)
        else:
            print(f"[+] Found: {var}")

    if missing:
        print("\nCritical environment configuration is missing.")
        print("Please set these variables before running the backend.")
        return False
    
    print("\nEnvironment validated. System ready for startup.")
    return True

if __name__ == "__main__":
    if not validate_environment():
        sys.exit(1)
