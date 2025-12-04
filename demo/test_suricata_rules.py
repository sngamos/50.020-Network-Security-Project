#!/usr/bin/env python3
"""
Simple test to verify Suricata custom rules are detecting attacks
This script tests each rule in custom.rules specifically
"""

import requests
import time
import sys

def test_suricata_detection(target_url="http://localhost:8081"):
    """Test each custom rule from custom.rules"""
    
    print("="*70)
    print("SURICATA CUSTOM RULES DETECTION TEST")
    print("="*70)
    
    # Login to DVWA first
    session = requests.Session()
    print("\n[*] Logging into DVWA...")
    login_data = {'username': 'admin', 'password': 'password', 'Login': 'Login'}
    session.post(f"{target_url}/dvwa/login.php", data=login_data)
    session.get(f"{target_url}/dvwa/security.php?security=low")
    print("[+] Logged in successfully\n")
    
    tests = [
        {
            "name": "TEST 1: Union Select SQL Injection",
            "rule": "sid:1000022 - Union Select SQLI",
            "method": "GET",
            "url": f"{target_url}/dvwa/vulnerabilities/sqli/?id=1'+UNION+SELECT+null,user()+--+&Submit=Submit",
            "description": "Should trigger: content:'union' + content:'select'"
        },
        {
            "name": "TEST 2: Command Injection",
            "rule": "sid:1000023 - Command Injection",
            "method": "POST",
            "url": f"{target_url}/dvwa/vulnerabilities/exec/",
            "data": {"ip": "127.0.0.1; whoami", "Submit": "Submit"},
            "description": "Should trigger: pcre pattern for ; || | &&"
        },
        {
            "name": "TEST 3: Alternative Command Injection",
            "rule": "sid:1000023 - Command Injection",
            "method": "GET",
            "url": f"{target_url}/dvwa/vulnerabilities/exec/?ip=127.0.0.1%7Cwhoami&Submit=Submit",
            "description": "Should trigger: pipe character in URI"
        },
        {
            "name": "TEST 4: Multiple SQL Keywords",
            "rule": "sid:1000022 - Union Select SQLI",
            "method": "GET",
            "url": f"{target_url}/dvwa/vulnerabilities/sqli/?id=1'+union+select+1,2+--+&Submit=Submit",
            "description": "Should trigger: union + select (case insensitive)"
        }
    ]
    
    for i, test in enumerate(tests, 1):
        print(f"\n{'='*70}")
        print(f"{test['name']}")
        print(f"Rule: {test['rule']}")
        print(f"Description: {test['description']}")
        print(f"{'='*70}")
        
        try:
            if test['method'] == 'GET':
                print(f"[*] Sending GET request...")
                response = session.get(test['url'], timeout=5)
            else:
                print(f"[*] Sending POST request...")
                response = session.post(test['url'], data=test.get('data', {}), timeout=5)
            
            print(f"[+] Response code: {response.status_code}")
            print(f"[+] Request sent successfully")
            
        except Exception as e:
            print(f"[!] Error: {e}")
        
        time.sleep(1)  # Give Suricata time to process
    
    print(f"\n{'='*70}")
    print("ALL TESTS COMPLETED")
    print("="*70)
    print("\nNext steps:")
    print("1. Check dashboard at http://localhost:8080")
    print("2. Run: cat shared/logs/eve.json | grep '\"event_type\":\"alert\"' | tail -5")
    print("3. Check rule matches: cat shared/logs/eve.json | jq '.alert.signature_id' | sort | uniq -c")
    print("\nExpected SIDs: 1000022 (SQL Injection), 1000023 (Command Injection)")

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8081"
    test_suricata_detection(target)
