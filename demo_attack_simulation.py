import requests
import json
import time

BASE_URL = "http://localhost:8000"

def run_test(name, url, method="GET", payload=None):
    print(f"\n--- Testing: {name} ---")
    print(f"URL: {url}")
    print(f"Payload: {payload}")
    
    try:
        if method == "GET":
            response = requests.get(url, params=payload)
        else:
            response = requests.post(url, data=payload)
            
        print(f"Status Code: {response.status_code}")
        print("Response Preview:")
        # Print first 200 chars to avoid flooding
        content = response.text[:300] + "..." if len(response.text) > 300 else response.text
        print(content)
        
        # Check for deception (simple check)
        if "error" in response.text.lower() or "syntax" in response.text.lower():
            print("[SUCCESS] DECEPTION DETECTED: Fake error message returned.")
        elif "dashboard" in response.text.lower() or "login" in response.text.lower():
            print("[SUCCESS] DECEPTION DETECTED: Fake portal page returned.")
        else:
            print("[INFO] Response received (Verify content manually).")
            
    except Exception as e:
        print(f"[FAIL] Test Failed: {e}")

print("STARTING ATTACK SIMULATION DEMO")
print("Target: " + BASE_URL)

# 1. SQL Injection
run_test(
    "SQL Injection Attack", 
    f"{BASE_URL}/search", 
    payload={"q": "' OR 1=1--"}
)

# 2. XSS Attack
run_test(
    "XSS Attack", 
    f"{BASE_URL}/search", 
    payload={"q": "<script>alert('HACKED')</script>"}
)

# 3. Path Traversal
run_test(
    "Path Traversal (Fake /etc/passwd)", 
    f"{BASE_URL}/search", 
    payload={"q": "../../etc/passwd"}
)

# 4. Admin Probe
run_test(
    "Admin Panel Probe", 
    f"{BASE_URL}/admin"
)

# 5. Login Attempt
run_test(
    "Fake Login Attempt",
    f"{BASE_URL}/login",
    method="POST",
    payload={"username": "admin", "password": "password123"}
)

print("\nSIMULATION COMPLETE")
