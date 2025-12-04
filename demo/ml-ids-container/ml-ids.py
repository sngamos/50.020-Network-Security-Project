#!/usr/bin/env python3

import pickle
import pandas as pd
import numpy as np
from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime
import json
import sys
import os
import re
from urllib.parse import unquote
from collections import defaultdict, deque
import time

class MultiAttackDetector:
    """Comprehensive attack detection using patterns and ML"""
    
    def __init__(self):
        # SQL Injection patterns
        self.sqli_patterns = [
            r"(\bUNION\b.*\bSELECT\b)", r"(\bOR\b\s+\d+\s*=\s*\d+)",
            r"('\s*OR\s*'.*'=')", r"(--\s*$)", r"(#.*$)", r"(/\*.*\*/)",
            r"(\bDROP\b.*\bTABLE\b)", r"(\binformation_schema\b)",
            # Obfuscated
            r"(un%69on|un%u0069on)", r"(u\s*n\s*i\s*o\s*n)",
            r"(un/\*\*/ion)", r"(0x75%6E%69%6F%6E)",
        ]
        
        # Command Injection patterns
        self.cmdi_patterns = [
            r"(;\s*(ls|cat|wget|curl|nc|bash|sh))",
            r"(\|\s*(ls|cat|wget|curl|nc|bash|sh))",
            r"(\$\(.*\))", r"(`.*`)", r"(/bin/)", r"(/etc/passwd)",
            r"(&&|\|\|)", r"(%0a|%0d)", r"(>|<|>>)",
        ]
        
        # XSS patterns
        self.xss_patterns = [
            r"(<script[^>]*>.*</script>)",
            r"(javascript:)", r"(on\w+\s*=)",
            r"(<iframe)", r"(<object)", r"(<embed)",
        ]
        
        # File Inclusion patterns
        self.fi_patterns = [
            r"(\.\./)", r"(\.\.\\)",
            r"(/etc/passwd)", r"(/windows/system32)",
            r"(php://)", r"(file://)", r"(data://)",
        ]
        
        # Compile all patterns
        self.compiled_sqli = [re.compile(p, re.IGNORECASE) for p in self.sqli_patterns]
        self.compiled_cmdi = [re.compile(p, re.IGNORECASE) for p in self.cmdi_patterns]
        self.compiled_xss = [re.compile(p, re.IGNORECASE) for p in self.xss_patterns]
        self.compiled_fi = [re.compile(p, re.IGNORECASE) for p in self.fi_patterns]
        
        # Connection tracking for port scans and brute force
        self.connections = defaultdict(lambda: {'count': 0, 'first_seen': None, 'ports': set()})
        self.http_requests = defaultdict(lambda: {'count': 0, 'first_seen': None})
        
    def detect_pattern(self, payload, patterns, attack_type):
        """Generic pattern detection"""
        if not payload:
            return False, []
        
        try:
            decoded = unquote(payload).lower()
        except:
            decoded = payload.lower()
        
        detected = []
        for i, pattern in enumerate(patterns):
            if pattern.search(decoded):
                detected.append(i)
        
        return len(detected) > 0, detected
    
    def detect_sqli(self, payload):
        """SQL Injection detection"""
        return self.detect_pattern(payload, self.compiled_sqli, "SQLI")
    
    def detect_cmdi(self, payload):
        """Command Injection detection"""
        return self.detect_pattern(payload, self.compiled_cmdi, "CMDI")
    
    def detect_xss(self, payload):
        """XSS detection"""
        return self.detect_pattern(payload, self.compiled_xss, "XSS")
    
    def detect_file_inclusion(self, payload):
        """File Inclusion detection"""
        return self.detect_pattern(payload, self.compiled_fi, "FILE_INCLUSION")
    
    def detect_port_scan(self, src_ip, dst_port):
        """Port scan detection"""
        conn = self.connections[src_ip]
        
        if conn['first_seen'] is None:
            conn['first_seen'] = time.time()
        
        conn['ports'].add(dst_port)
        
        # Check if scanning multiple ports in short time
        time_window = time.time() - conn['first_seen']
        if time_window < 60 and len(conn['ports']) > 50:
            return True, len(conn['ports'])
        
        # Reset if time window exceeded
        if time_window > 60:
            conn['first_seen'] = time.time()
            conn['ports'] = {dst_port}
        
        return False, 0
    
    def detect_brute_force(self, src_ip, is_http_post=False):
        """Brute force detection"""
        if is_http_post:
            req = self.http_requests[src_ip]
            
            if req['first_seen'] is None:
                req['first_seen'] = time.time()
            
            req['count'] += 1
            
            # Check for rapid POST requests
            time_window = time.time() - req['first_seen']
            if time_window < 30 and req['count'] > 20:
                return True, req['count']
            
            # Reset if time window exceeded
            if time_window > 30:
                req['first_seen'] = time.time()
                req['count'] = 1
        
        return False, 0
    
    def detect_http_flood(self, src_ip):
        """HTTP flood detection"""
        conn = self.connections[src_ip]
        
        if conn['first_seen'] is None:
            conn['first_seen'] = time.time()
        
        conn['count'] += 1
        
        # Check for high request rate
        time_window = time.time() - conn['first_seen']
        if time_window < 10 and conn['count'] > 100:
            return True, conn['count']
        
        # Reset if time window exceeded
        if time_window > 10:
            conn['first_seen'] = time.time()
            conn['count'] = 1
        
        return False, 0
    
    def extract_features(self, payload):
        """Extract features for ML model"""
        if not payload:
            return None
        
        try:
            decoded = unquote(payload).lower()
        except:
            decoded = payload.lower()
        
        features = {}
        
        # Length features
        features['payload_length'] = len(payload)
        features['decoded_length'] = len(decoded)
        
        # Character frequency
        features['single_quote'] = decoded.count("'")
        features['double_quote'] = decoded.count('"')
        features['semicolon'] = decoded.count(';')
        features['dash'] = decoded.count('-')
        features['equals'] = decoded.count('=')
        features['percent'] = decoded.count('%')
        features['ampersand'] = decoded.count('&')
        features['pipe'] = decoded.count('|')
        features['slash'] = decoded.count('/')
        features['backslash'] = decoded.count('\\')
        features['angle_brackets'] = decoded.count('<') + decoded.count('>')
        features['parenthesis'] = decoded.count('(') + decoded.count(')')
        
        # SQL keywords
        sql_keywords = ['select', 'union', 'insert', 'update', 'delete', 'drop', 
                       'exec', 'cast', 'concat', 'char', 'where', 'from', 'table']
        features['sql_keyword_count'] = sum(1 for k in sql_keywords if k in decoded)
        
        # Command keywords
        cmd_keywords = ['ls', 'cat', 'wget', 'curl', 'bash', 'sh', 'nc', 'chmod', 'echo']
        features['cmd_keyword_count'] = sum(1 for k in cmd_keywords if k in decoded)
        
        # Special patterns
        features['has_union'] = 1 if 'union' in decoded else 0
        features['has_select'] = 1 if 'select' in decoded else 0
        features['has_script'] = 1 if 'script' in decoded else 0
        features['has_comment'] = 1 if ('--' in decoded or '/*' in decoded or '#' in decoded) else 0
        features['has_encoding'] = 1 if '%' in payload else 0
        
        # Entropy
        features['entropy'] = self.calculate_entropy(decoded)
        
        return features
    
    def calculate_entropy(self, text):
        """Calculate Shannon entropy"""
        if not text:
            return 0
        prob = [text.count(c) / len(text) for c in set(text)]
        entropy = -sum(p * np.log2(p) for p in prob if p > 0)
        return entropy


class MLIDS:
    def __init__(self, model_path, alert_file='/var/log/ml_ids_alerts.json'):
        self.model = None
        self.model_path = model_path
        
        # Load ML model if exists
        if os.path.exists(model_path):
            try:
                with open(model_path, 'rb') as f:
                    self.model = pickle.load(f)
                print(f"[+] ML model loaded from {model_path}")
            except Exception as e:
                print(f"[!] Error loading model: {e}")
                print("[!] Using pattern-based detection only")
        else:
            print(f"[!] Model not found: {model_path}")
            print("[!] Using pattern-based detection only")
        
        self.detector = MultiAttackDetector()
        self.alert_file = alert_file
        self.alerts = []
        
        # Tracking
        self.packet_count = 0
        self.slow_connections = {}  # For slowloris detection
        
        print(f"[+] ML-IDS initialized")
        print(f"[+] Alert file: {alert_file}")
    
    def generate_alert(self, packet, alert_type, details, confidence=None, severity='medium'):
        """Generate and save alert"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'alert_type': alert_type,
            'severity': severity,
            'src_ip': packet[IP].src if IP in packet else 'unknown',
            'dst_ip': packet[IP].dst if IP in packet else 'unknown',
            'src_port': packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else 0),
            'dst_port': packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else 0),
            'protocol': 'TCP' if TCP in packet else ('UDP' if UDP in packet else 'other'),
            'details': details,
            'confidence': confidence,
            'detection_method': 'ML' if confidence else 'Pattern'
        }
        
        self.alerts.append(alert)
        
        # Save alerts
        try:
            with open(self.alert_file, 'w') as f:
                json.dump(self.alerts, f, indent=2)
        except Exception as e:
            print(f"[!] Error saving alerts: {e}")
        
        # Console output
        conf_str = f" (conf: {confidence:.2%})" if confidence else ""
        print(f"[{severity.upper()}] {alert_type}: {details}{conf_str}")
        
        return alert
    
    def extract_http_payload(self, packet):
        """Extract HTTP payload"""
        if Raw in packet:
            try:
                return packet[Raw].load.decode('utf-8', errors='ignore')
            except:
                pass
        return None
    
    def analyze_packet(self, packet):
        """Main packet analysis"""
        try:
            self.packet_count += 1
            
            if not (IP in packet):
                return
            
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # TCP analysis
            if TCP in packet:
                dst_port = packet[TCP].dport
                flags = packet[TCP].flags
                
                # Port scan detection (SYN packets)
                if flags & 0x02:  # SYN flag
                    is_scan, port_count = self.detector.detect_port_scan(src_ip, dst_port)
                    if is_scan:
                        self.generate_alert(
                            packet, 'PORT_SCAN',
                            f'Port scanning detected: {port_count} ports scanned',
                            severity='high'
                        )
                
                # HTTP traffic analysis
                if dst_port == 80 or dst_port == 8080:
                    payload = self.extract_http_payload(packet)
                    
                    if payload:
                        # Check for POST requests (brute force)
                        if 'POST' in payload:
                            is_brute, count = self.detector.detect_brute_force(src_ip, True)
                            if is_brute:
                                self.generate_alert(
                                    packet, 'BRUTE_FORCE',
                                    f'Brute force detected: {count} rapid POST requests',
                                    severity='high'
                                )
                        
                        # SQL Injection detection
                        is_sqli, _ = self.detector.detect_sqli(payload)
                        if is_sqli:
                            self.generate_alert(
                                packet, 'SQL_INJECTION',
                                'SQL injection pattern detected',
                                severity='critical'
                            )
                        
                        # Command Injection detection
                        is_cmdi, _ = self.detector.detect_cmdi(payload)
                        if is_cmdi:
                            self.generate_alert(
                                packet, 'COMMAND_INJECTION',
                                'Command injection pattern detected',
                                severity='critical'
                            )
                        
                        # XSS detection
                        is_xss, _ = self.detector.detect_xss(payload)
                        if is_xss:
                            self.generate_alert(
                                packet, 'XSS',
                                'Cross-site scripting pattern detected',
                                severity='high'
                            )
                        
                        # File Inclusion detection
                        is_fi, _ = self.detector.detect_file_inclusion(payload)
                        if is_fi:
                            self.generate_alert(
                                packet, 'FILE_INCLUSION',
                                'File inclusion pattern detected',
                                severity='high'
                            )
                        
                        # HTTP Flood detection
                        is_flood, count = self.detector.detect_http_flood(src_ip)
                        if is_flood:
                            self.generate_alert(
                                packet, 'HTTP_FLOOD',
                                f'HTTP flood detected: {count} requests in 10 seconds',
                                severity='high'
                            )
                        
                        # ML-based detection (if model available)
                        if self.model and self.packet_count % 5 == 0:  # Every 5th packet
                            features = self.detector.extract_features(payload)
                            if features:
                                try:
                                    df = pd.DataFrame([features])
                                    prediction = self.model.predict(df)
                                    
                                    if hasattr(self.model, 'predict_proba'):
                                        proba = self.model.predict_proba(df)[0]
                                        confidence = proba[1] if len(proba) > 1 else proba[0]
                                    else:
                                        confidence = None
                                    
                                    if prediction[0] == 1:
                                        self.generate_alert(
                                            packet, 'ML_DETECTION',
                                            'Malicious traffic detected by ML model',
                                            confidence, 'high'
                                        )
                                except Exception as e:
                                    pass  # Silent fail for ML predictions
                
                # Slowloris detection (incomplete HTTP requests)
                if dst_port == 80 and (flags & 0x18) == 0x18:  # PSH+ACK
                    payload = self.extract_http_payload(packet)
                    if payload and 'GET' in payload and '\r\n\r\n' not in payload:
                        # Track incomplete requests
                        conn_id = f"{src_ip}:{packet[TCP].sport}"
                        if conn_id not in self.slow_connections:
                            self.slow_connections[conn_id] = {'count': 0, 'start': time.time()}
                        
                        self.slow_connections[conn_id]['count'] += 1
                        
                        # Check for slowloris pattern
                        if self.slow_connections[conn_id]['count'] > 5:
                            elapsed = time.time() - self.slow_connections[conn_id]['start']
                            if elapsed > 10:  # Slow, incomplete requests over time
                                self.generate_alert(
                                    packet, 'SLOWLORIS',
                                    f'Slowloris DoS attack detected from {src_ip}',
                                    severity='critical'
                                )
                                del self.slow_connections[conn_id]
        
        except Exception as e:
            print(f"[!] Error analyzing packet: {e}")
    
    def start(self, interface='eth0'):
        """Start packet sniffing"""
        print(f"[+] Starting ML-IDS on interface: {interface}")
        print("[+] Monitoring all attack types...")
        print("[+] Press Ctrl+C to stop\n")
        
        try:
            sniff(iface=interface, prn=self.analyze_packet, store=False, filter="tcp port 80 or tcp port 8080")
        except KeyboardInterrupt:
            print(f"\n[+] Stopping ML-IDS")
            print(f"[+] Total packets analyzed: {self.packet_count}")
            print(f"[+] Total alerts generated: {len(self.alerts)}")
        except Exception as e:
            print(f"[!] Error: {e}")


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python3 ml_ids.py <model_path> <interface>")
        sys.exit(1)
    
    model_path = sys.argv[1]
    interface = sys.argv[2]
    
    ids = MLIDS(model_path)
    ids.start(interface)