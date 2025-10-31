# demo/ml-ids/app.py
"""
Standalone ML-based IDS
Monitors traffic and detects intrusions using Random Forest model
"""
import pickle
import sys
from scapy.all import sniff, IP, TCP, Raw
import numpy as np
from collections import defaultdict
from datetime import datetime
import time

class MLIDS:
    def __init__(self, model_path, scaler_path):
        print("[ML-IDS] Loading Random Forest model...")
        with open(model_path, 'rb') as f:
            self.model = pickle.load(f)
        
        with open(scaler_path, 'rb') as f:
            self.scaler = pickle.load(f)
        
        self.flow_cache = defaultdict(lambda: {
            'packets': [],
            'timestamps': [],
            'payload_sizes': [],
            'flags': []
        })
        
        self.attack_labels = {
            0: 'BENIGN',
            1: 'DDoS',
            2: 'PortScan',
            3: 'Bot',
            4: 'Infiltration',
            5: 'Web Attack',
            6: 'Brute Force'
        }
        
        print("[ML-IDS] Model loaded successfully!")
        print("[ML-IDS] Monitoring network traffic...")
        print("="*60)
    
    def extract_flow_features(self, flow_data):
        """Extract CICIDS2017-compatible features from flow"""
        packets = flow_data['packets']
        timestamps = flow_data['timestamps']
        payloads = flow_data['payload_sizes']
        
        if len(packets) < 5:  # Need minimum packets
            return None
        
        # Calculate key features (matching paper's top features)
        features = {
            'flow_duration': timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0,
            'total_fwd_packets': len(packets),
            'total_bwd_packets': 0,  # Simplified
            'total_length_fwd_packets': sum(packets),
            'fwd_packet_length_max': max(packets) if packets else 0,
            'fwd_packet_length_min': min(packets) if packets else 0,
            'fwd_packet_length_mean': np.mean(packets) if packets else 0,
            'fwd_packet_length_std': np.std(packets) if packets else 0,
            'bwd_packet_length_max': 0,
            'flow_bytes_per_s': sum(packets) / (timestamps[-1] - timestamps[0]) if (timestamps[-1] - timestamps[0]) > 0 else 0,
            'flow_packets_per_s': len(packets) / (timestamps[-1] - timestamps[0]) if (timestamps[-1] - timestamps[0]) > 0 else 0,
            'flow_iat_mean': np.mean(np.diff(timestamps)) if len(timestamps) > 1 else 0,
            'flow_iat_std': np.std(np.diff(timestamps)) if len(timestamps) > 1 else 0,
            'flow_iat_max': max(np.diff(timestamps)) if len(timestamps) > 1 else 0,
            'flow_iat_min': min(np.diff(timestamps)) if len(timestamps) > 1 else 0,
            'fwd_iat_total': timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0,
            'fwd_iat_mean': np.mean(np.diff(timestamps)) if len(timestamps) > 1 else 0,
            'fwd_iat_std': np.std(np.diff(timestamps)) if len(timestamps) > 1 else 0,
            'fwd_iat_max': max(np.diff(timestamps)) if len(timestamps) > 1 else 0,
            'fwd_iat_min': min(np.diff(timestamps)) if len(timestamps) > 1 else 0,
            'fwd_psh_flags': flow_data['flags'].count(0x08),
            'fwd_urg_flags': flow_data['flags'].count(0x20),
            'fwd_header_length': len(packets) * 20,  # Approximate
            'fwd_packets_per_s': len(packets) / (timestamps[-1] - timestamps[0]) if (timestamps[-1] - timestamps[0]) > 0 else 0,
            'min_packet_length': min(packets) if packets else 0,
            'max_packet_length': max(packets) if packets else 0,
            'packet_length_mean': np.mean(packets) if packets else 0,
            'packet_length_std': np.std(packets) if packets else 0,
            'packet_length_variance': np.var(packets) if packets else 0,
            'average_packet_size': np.mean(packets) if packets else 0,
            'avg_fwd_segment_size': np.mean(payloads) if payloads else 0,
            'init_win_bytes_forward': packets[0] if packets else 0,
            'active_mean': np.mean(timestamps) if timestamps else 0,
            'idle_mean': 0,
        }
        
        # Convert to array matching training format (30 key features)
        feature_vector = [
            features['average_packet_size'],
            features['bwd_packet_length_max'],
            features['flow_iat_max'],
            features['fwd_packet_length_max'],
            features['fwd_packet_length_mean'],
            features['packet_length_mean'],
            features['flow_duration'],
            features['flow_iat_mean'],
            features['fwd_iat_mean'],
            features['packet_length_std'],
            features['fwd_packet_length_std'],
            features['flow_iat_std'],
            features['fwd_iat_std'],
            features['max_packet_length'],
            features['min_packet_length'],
            features['total_length_fwd_packets'],
            features['fwd_header_length'],
            features['flow_bytes_per_s'],
            features['flow_packets_per_s'],
            features['fwd_packets_per_s'],
            features['packet_length_variance'],
            features['fwd_iat_total'],
            features['init_win_bytes_forward'],
            features['fwd_psh_flags'],
            features['fwd_urg_flags'],
            features['avg_fwd_segment_size'],
            features['active_mean'],
            features['idle_mean'],
            features['fwd_iat_max'],
            features['fwd_iat_min']
        ]
        
        return np.array(feature_vector)
    
    def predict(self, feature_vector):
        """Make prediction using Random Forest model"""
        # Normalize
        feature_vector_normalized = self.scaler.transform([feature_vector])
        
        # Predict
        prediction = self.model.predict(feature_vector_normalized)[0]
        probabilities = self.model.predict_proba(feature_vector_normalized)[0]
        confidence = max(probabilities)
        
        return prediction, confidence
    
    def packet_handler(self, packet):
        """Handle each captured packet"""
        if IP in packet and TCP in packet:
            # Create flow identifier
            flow_key = (
                packet[IP].src,
                packet[TCP].sport,
                packet[IP].dst,
                packet[TCP].dport
            )
            
            # Store packet info
            flow = self.flow_cache[flow_key]
            flow['packets'].append(len(packet))
            flow['timestamps'].append(packet.time)
            flow['flags'].append(packet[TCP].flags)
            
            if Raw in packet:
                flow['payload_sizes'].append(len(packet[Raw].load))
            
            # Analyze after sufficient packets
            if len(flow['packets']) >= 10:
                feature_vector = self.extract_flow_features(flow)
                
                if feature_vector is not None:
                    prediction, confidence = self.predict(feature_vector)
                    attack_type = self.attack_labels[prediction]
                    
                    # Alert on attacks
                    if attack_type != 'BENIGN' and confidence > 0.85:
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        print(f"\n{'='*60}")
                        print(f"🚨 [ML-IDS ALERT]")
                        print(f"{'='*60}")
                        print(f"Timestamp:    {timestamp}")
                        print(f"Attack Type:  {attack_type}")
                        print(f"Confidence:   {confidence:.2%}")
                        print(f"Source:       {packet[IP].src}:{packet[TCP].sport}")
                        print(f"Destination:  {packet[IP].dst}:{packet[TCP].dport}")
                        print(f"Packets:      {len(flow['packets'])}")
                        print(f"{'='*60}\n")
                        
                        # Log to file
                        with open('/var/log/ml-ids/alerts.log', 'a') as f:
                            f.write(f"{timestamp} | {attack_type} | "
                                  f"{confidence:.2%} | "
                                  f"{packet[IP].src} -> {packet[IP].dst}\n")
                        
                        # Clear this flow
                        del self.flow_cache[flow_key]
    
    def start_monitoring(self, interface='eth0'):
        """Start packet capture"""
        print(f"[ML-IDS] Starting capture on interface: {interface}")
        
        try:
            sniff(
                iface=interface,
                prn=self.packet_handler,
                store=False,
                filter="tcp port 80"  # Only HTTP traffic
            )
        except KeyboardInterrupt:
            print("\n[ML-IDS] Stopping...")
        except Exception as e:
            print(f"[ML-IDS] Error: {e}")

if __name__ == "__main__":
    import os
    
    model_path = os.environ.get('MODEL_PATH', '/app/models/random_forest.pkl')
    scaler_path = os.environ.get('SCALER_PATH', '/app/models/scaler.pkl')
    interface = os.environ.get('INTERFACE', 'eth0')
    
    # Create log directory
    os.makedirs('/var/log/ml-ids', exist_ok=True)
    
    ids = MLIDS(model_path, scaler_path)
    ids.start_monitoring(interface)