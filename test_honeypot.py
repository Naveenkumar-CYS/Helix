"""
Test Script for Enhanced AI Honeypot
Tests all intelligence features including behavioral analysis, deception, and correlation.
"""

import requests
import time
from datetime import datetime


BASE_URL = "http://localhost:8000"


def print_section(title):
    """Print formatted section header."""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


def test_basic_sqli():
    """Test basic SQL injection detection and response."""
    print_section("Test 1: Basic SQL Injection (Novice Attack)")
    
    payloads = [
        "' OR 1=1--",
        "admin'--",
        "' UNION SELECT * FROM users--"
    ]
    
    for payload in payloads:
        print(f"Payload: {payload}")
        response = requests.get(f"{BASE_URL}/search", params={"q": payload})
        print(f"Status: {response.status_code}")
        print(f"Response preview: {response.text[:200]}...")
        print()
        time.sleep(0.5)


def test_advanced_sqli():
    """Test advanced SQL injection with tool signatures."""
    print_section("Test 2: Advanced SQL Injection (Automated Tool)")
    
    # Simulate sqlmap-like payloads
    payloads = [
        "' AND 1=1 UNION ALL SELECT NULL,NULL,NULL--",
        "' AND SLEEP(5)--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    ]
    
    headers = {
        "User-Agent": "sqlmap/1.0"
    }
    
    for payload in payloads:
        print(f"Payload: {payload}")
        response = requests.get(
            f"{BASE_URL}/search",
            params={"q": payload},
            headers=headers
        )
        print(f"Status: {response.status_code}")
        print(f"Response preview: {response.text[:200]}...")
        print()
        time.sleep(0.5)


def test_session_hijacking():
    """Test session hijacking and canary token tracking."""
    print_section("Test 3: Session Hijacking & Canary Tokens")
    
    # First, extract session via SQLi
    print("Step 1: Extract session ID via SQLi")
    response = requests.get(f"{BASE_URL}/search", params={"q": "' OR 1=1--"})
    print(f"Response: {response.text[:300]}...")
    
    time.sleep(1)
    
    # Try to use extracted session
    print("\nStep 2: Attempt to use extracted session")
    response = requests.get(f"{BASE_URL}/admin", params={"session": "sess_abc123"})
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text[:300]}...")
    print()


def test_admin_commands():
    """Test interactive admin commands."""
    print_section("Test 4: Interactive Admin Commands")
    
    # Get admin access first
    print("Getting admin access...")
    response = requests.get(f"{BASE_URL}/admin", params={"session": "adm_9f3c2a1b7e"})
    print(f"Admin panel: {response.text[:200]}...")
    
    time.sleep(1)
    
    # Test shell commands
    commands = [
        "ls /var/www/html",
        "cat /var/www/html/config.php",
        "SELECT * FROM users",
        "SHOW DATABASES",
        "help",
        "status"
    ]
    
    for cmd in commands:
        print(f"\nCommand: {cmd}")
        response = requests.get(f"{BASE_URL}/admin", params={"cmd": cmd, "session": "adm_9f3c2a1b7e"})
        print(f"Response: {response.text[:300]}...")
        time.sleep(0.5)


def test_multi_vector_attack():
    """Test multi-vector coordinated attack detection."""
    print_section("Test 5: Multi-Vector Coordinated Attack")
    
    print("Launching coordinated attack across multiple vectors...")
    
    # SQLi on search
    print("\n1. SQL Injection on /search")
    requests.get(f"{BASE_URL}/search", params={"q": "' OR 1=1--"})
    time.sleep(0.3)
    
    # XSS attempt
    print("2. XSS attempt on /search")
    requests.get(f"{BASE_URL}/search", params={"q": "<script>alert('xss')</script>"})
    time.sleep(0.3)
    
    # Admin access
    print("3. Admin panel access")
    response = requests.get(f"{BASE_URL}/admin", params={"session": "adm_9f3c2a1b7e"})
    
    # Check for coordinated attack warning
    if "Multiple attack vectors" in response.text:
        print("✓ Coordinated attack detected!")
    else:
        print("✗ Coordinated attack not detected")
    
    print(f"\nResponse: {response.text[:300]}...")


def test_deception_features():
    """Test deception engine features."""
    print_section("Test 6: Deception Features (Delays & Errors)")
    
    print("Testing realistic timing delays...")
    start = time.time()
    response = requests.get(f"{BASE_URL}/search", params={"q": "' OR 1=1--"})
    elapsed = time.time() - start
    
    print(f"Response time: {elapsed:.2f}s (should include realistic delay)")
    print(f"Response: {response.text[:200]}...")
    
    # Test multiple requests to trigger rate limiting
    print("\nTesting fake rate limiting...")
    for i in range(5):
        response = requests.get(f"{BASE_URL}/search", params={"q": f"test{i}"})
        if "rate limit" in response.text.lower() or "warning" in response.text.lower():
            print(f"✓ Rate limit warning triggered on request {i+1}")
            break
    else:
        print("Rate limit warnings may appear randomly")


def test_threat_intelligence():
    """Test threat intelligence and profiling."""
    print_section("Test 7: Threat Intelligence & Profiling")
    
    print("Sending requests with different characteristics...")
    
    # VPN-like user agent
    headers_vpn = {"User-Agent": "Mozilla/5.0 (NordVPN)"}
    response = requests.get(f"{BASE_URL}/search", params={"q": "test"}, headers=headers_vpn)
    print("Request with VPN user agent sent")
    
    # Tor-like pattern
    headers_tor = {"User-Agent": "Mozilla/5.0 (Tor Browser)"}
    response = requests.get(f"{BASE_URL}/search", params={"q": "test"}, headers=headers_tor)
    print("Request with Tor user agent sent")
    
    # Automated tool
    headers_tool = {"User-Agent": "sqlmap/1.0"}
    response = requests.get(f"{BASE_URL}/search", params={"q": "' OR 1=1--"}, headers=headers_tool)
    print("Request with sqlmap user agent sent")
    
    print("\n✓ Threat intelligence data collected (check logs for details)")


def test_personalized_content():
    """Test personalized content generation."""
    print_section("Test 8: Personalized Content & Canary Tokens")
    
    print("Each attacker should receive unique canary tokens...")
    
    # Simulate two different attackers
    session1 = requests.Session()
    session2 = requests.Session()
    
    print("\nAttacker 1:")
    resp1 = session1.get(f"{BASE_URL}/search", params={"q": "' OR 1=1--"})
    print(f"Response: {resp1.text[:300]}...")
    
    print("\nAttacker 2:")
    resp2 = session2.get(f"{BASE_URL}/search", params={"q": "' OR 1=1--"})
    print(f"Response: {resp2.text[:300]}...")
    
    if resp1.text != resp2.text:
        print("\n✓ Personalized content confirmed (responses differ)")
    else:
        print("\n⚠ Responses are identical (may be using same attacker ID)")


def run_all_tests():
    """Run all test suites."""
    print(f"\n{'#'*60}")
    print(f"  AI HONEYPOT INTELLIGENCE TEST SUITE")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'#'*60}")
    
    try:
        # Check if server is running
        response = requests.get(f"{BASE_URL}/health", timeout=2)
        if response.status_code != 200:
            print("\n❌ Error: Honeypot server is not responding correctly")
            return
    except requests.exceptions.RequestException:
        print("\n❌ Error: Cannot connect to honeypot server")
        print(f"   Make sure the server is running at {BASE_URL}")
        print("   Run: python app.py")
        return
    
    print("\n✓ Server is running\n")
    
    # Run all tests
    test_basic_sqli()
    test_advanced_sqli()
    test_session_hijacking()
    test_admin_commands()
    test_multi_vector_attack()
    test_deception_features()
    test_threat_intelligence()
    test_personalized_content()
    
    print(f"\n{'#'*60}")
    print(f"  TEST SUITE COMPLETED")
    print(f"  Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'#'*60}\n")
    
    print("📊 Check the following files for detailed logs:")
    print("   - attacks.log (human-readable)")
    print("   - attacks.json (structured data)")
    print("\n💡 Review logs to see:")
    print("   - Behavioral analysis (skill levels)")
    print("   - Attack campaigns and correlation")
    print("   - Threat intelligence data")
    print("   - Canary token tracking")


if __name__ == "__main__":
    run_all_tests()
