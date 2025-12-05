from flask import Flask, render_template_string, jsonify
from flask_cors import CORS
import json
import os
from datetime import datetime
import subprocess

app = Flask(__name__)
CORS(app)

# Paths to log files (will be mounted from containers)
SURICATA_LOG = '/shared/logs/eve.json'
ML_IDS_LOG = '/shared/logs/ml_ids_alerts.json'

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>IDS Comparison Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            background: linear-gradient(135deg, #0a0e27 0%, #1a1e3a 100%);
            color: #00ff00;
            padding: 20px;
            min-height: 100vh;
        }
        .header {
            text-align: center;
            padding: 40px;
            background: linear-gradient(135deg, #1a1e3a 0%, #2a2e4a 100%);
            border-radius: 15px;
            margin-bottom: 30px;
            border: 2px solid #00ff00;
            box-shadow: 0 0 20px rgba(0, 255, 0, 0.3);
        }
        .header h1 {
            font-size: 3em;
            color: #00ff00;
            text-shadow: 0 0 10px #00ff00, 0 0 20px #00ff00;
            margin-bottom: 10px;
        }
        .header .subtitle {
            color: #00ffff;
            font-size: 1.2em;
        }
        .comparison-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            margin-bottom: 30px;
        }
        .stats-panel {
            background: #1a1e3a;
            padding: 30px;
            border-radius: 15px;
            border: 2px solid;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
        }
        .suricata-panel {
            border-color: #ff6b6b;
            box-shadow: 0 0 20px rgba(255, 107, 107, 0.2);
        }
        .ml-panel {
            border-color: #4ecdc4;
            box-shadow: 0 0 20px rgba(78, 205, 196, 0.2);
        }
        .panel-header {
            font-size: 1.8em;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 2px solid;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .suricata-panel .panel-header {
            color: #ff6b6b;
            border-color: #ff6b6b;
        }
        .ml-panel .panel-header {
            color: #4ecdc4;
            border-color: #4ecdc4;
        }
        .stat-row {
            display: flex;
            justify-content: space-between;
            padding: 15px;
            margin: 10px 0;
            background: rgba(0, 0, 0, 0.3);
            border-radius: 8px;
            border-left: 4px solid;
        }
        .suricata-panel .stat-row {
            border-left-color: #ff6b6b;
        }
        .ml-panel .stat-row {
            border-left-color: #4ecdc4;
        }
        .stat-label {
            color: #aaa;
            font-size: 1.1em;
        }
        .stat-value {
            font-size: 1.5em;
            font-weight: bold;
        }
        .comparison-section {
            background: #1a1e3a;
            padding: 30px;
            border-radius: 15px;
            border: 2px solid #ffd93d;
            box-shadow: 0 0 20px rgba(255, 217, 61, 0.2);
            margin-bottom: 30px;
        }
        .comparison-section h2 {
            color: #ffd93d;
            font-size: 2em;
            margin-bottom: 20px;
            text-align: center;
        }
        .comparison-bars {
            display: grid;
            gap: 20px;
        }
        .bar-container {
            margin: 20px 0;
        }
        .bar-label {
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
            font-size: 1.1em;
        }
        .bar-wrapper {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
        }
        .bar {
            height: 40px;
            border-radius: 8px;
            transition: width 0.5s ease;
            display: flex;
            align-items: center;
            padding: 0 15px;
            font-weight: bold;
            box-shadow: 0 0 15px rgba(0, 0, 0, 0.5);
        }
        .bar-suricata {
            background: linear-gradient(90deg, #ff6b6b 0%, #ff8787 100%);
            color: white;
        }
        .bar-ml {
            background: linear-gradient(90deg, #4ecdc4 0%, #6fdbcf 100%);
            color: white;
        }
        .alerts-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
        }
        .alerts-panel {
            background: #1a1e3a;
            padding: 25px;
            border-radius: 15px;
            border: 2px solid;
            max-height: 600px;
            overflow-y: auto;
        }
        .alerts-panel::-webkit-scrollbar {
            width: 10px;
        }
        .alerts-panel::-webkit-scrollbar-track {
            background: #0a0e27;
            border-radius: 5px;
        }
        .alerts-panel::-webkit-scrollbar-thumb {
            background: #00ff00;
            border-radius: 5px;
        }
        .alert-item {
            background: rgba(0, 0, 0, 0.4);
            padding: 15px;
            margin: 10px 0;
            border-radius: 8px;
            border-left: 4px solid;
            animation: slideIn 0.3s ease-out;
        }
        @keyframes slideIn {
            from {
                transform: translateX(-20px);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
        .suricata-alert {
            border-left-color: #ff6b6b;
        }
        .ml-alert {
            border-left-color: #4ecdc4;
        }
        .alert-time {
            color: #888;
            font-size: 0.9em;
            margin-bottom: 8px;
        }
        .alert-type {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 15px;
            font-size: 0.85em;
            font-weight: bold;
            margin: 5px 0;
        }
        .pattern-detection {
            background: #ff6b6b;
            color: white;
        }
        .ml-detection {
            background: #4ecdc4;
            color: white;
        }
        .controls {
            text-align: center;
            margin: 30px 0;
        }
        button {
            background: linear-gradient(135deg, #00ff00 0%, #00cc00 100%);
            color: #0a0e27;
            border: none;
            padding: 15px 40px;
            border-radius: 10px;
            cursor: pointer;
            font-size: 1.1em;
            font-weight: bold;
            margin: 0 10px;
            transition: all 0.3s;
            box-shadow: 0 5px 15px rgba(0, 255, 0, 0.3);
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(0, 255, 0, 0.4);
        }
        .winner-badge {
            display: inline-block;
            padding: 5px 15px;
            background: #ffd93d;
            color: #0a0e27;
            border-radius: 20px;
            font-weight: bold;
            margin-left: 10px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ IDS COMPARISON DASHBOARD</h1>
        <div class="subtitle">XGBoost ML-IDS vs Suricata Signature-Based IDS</div>
        <div class="subtitle" style="font-size: 0.9em; margin-top: 10px; color: #888;">
            Network Security Project - Intrusion Detection System Performance Analysis
        </div>
    </div>

    <div class="controls">
        <button onclick="refreshData()">🔄 Refresh Data</button>
        <button onclick="clearLogs()">🗑️ Clear Logs</button>
    </div>

    <div class="comparison-grid">
        <div class="stats-panel suricata-panel">
            <div class="panel-header">
                <span>📋 Suricata IDS</span>
                <span style="font-size: 0.6em; color: #888;">(Signature-Based)</span>
            </div>
            <div class="stat-row">
                <span class="stat-label">Total Alerts</span>
                <span class="stat-value" id="suricata-total">0</span>
            </div>
            <div class="stat-row">
                <span class="stat-label">Unique Source IPs</span>
                <span class="stat-value" id="suricata-ips">0</span>
            </div>
            <div class="stat-row">
                <span class="stat-label">Avg Response Time</span>
                <span class="stat-value" id="suricata-response">0ms</span>
            </div>
            <div class="stat-row">
                <span class="stat-label">Detection Rate</span>
                <span class="stat-value" id="suricata-rate">0%</span>
            </div>
        </div>

        <div class="stats-panel ml-panel">
            <div class="panel-header">
                <span>🤖 XGBoost ML-IDS</span>
                <span style="font-size: 0.6em; color: #888;">(Machine Learning)</span>
            </div>
            <div class="stat-row">
                <span class="stat-label">Total Alerts</span>
                <span class="stat-value" id="ml-total">0</span>
            </div>
            <div class="stat-row">
                <span class="stat-label">Unique Source IPs</span>
                <span class="stat-value" id="ml-ips">0</span>
            </div>
            <div class="stat-row">
                <span class="stat-label">Avg Confidence</span>
                <span class="stat-value" id="ml-confidence">0%</span>
            </div>
            <div class="stat-row">
                <span class="stat-label">Detection Rate</span>
                <span class="stat-value" id="ml-rate">0%</span>
            </div>
        </div>
    </div>

    <div class="comparison-section">
        <h2>📊 Detection Performance Comparison</h2>
        <div class="comparison-bars">
            <div class="bar-container">
                <div class="bar-label">
                    <span>Total Threat Detections</span>
                </div>
                <div class="bar-wrapper">
                    <div class="bar bar-suricata" id="bar-total-suricata" style="width: 0%;">
                        <span id="bar-total-suricata-text">0</span>
                    </div>
                    <div class="bar bar-ml" id="bar-total-ml" style="width: 0%;">
                        <span id="bar-total-ml-text">0</span>
                    </div>
                </div>
            </div>

            <div class="bar-container">
                <div class="bar-label">
                    <span>Unique Threats Identified</span>
                </div>
                <div class="bar-wrapper">
                    <div class="bar bar-suricata" id="bar-unique-suricata" style="width: 0%;">
                        <span id="bar-unique-suricata-text">0</span>
                    </div>
                    <div class="bar bar-ml" id="bar-unique-ml" style="width: 0%;">
                        <span id="bar-unique-ml-text">0</span>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="alerts-grid">
        <div class="alerts-panel suricata-panel">
            <div class="panel-header">
                <span>🚨 Suricata Alerts</span>
            </div>
            <div id="suricata-alerts"></div>
        </div>

        <div class="alerts-panel ml-panel">
            <div class="panel-header">
                <span>🤖 ML-IDS Alerts</span>
            </div>
            <div id="ml-alerts"></div>
        </div>
    </div>

    <script>
        function formatTime(timestamp) {
            const date = new Date(timestamp);
            return date.toLocaleTimeString();
        }

        function updateStats(suricataAlerts, mlAlerts) {
            // Count alerts
            const suricataTotal = suricataAlerts.length;
            const mlTotal = mlAlerts.length;

            // Count unique source IPs
            const suricataIPs = new Set(suricataAlerts.map(a => a.src_ip)).size;
            const mlIPs = new Set(mlAlerts.map(a => a.src_ip)).size;

            // Calculate average confidence for ML alerts
            const avgConfidence = mlAlerts.length > 0 
                ? (mlAlerts.reduce((sum, a) => sum + (a.confidence || 0), 0) / mlAlerts.length * 100).toFixed(1)
                : 0;

            // Update displays
            document.getElementById('suricata-total').textContent = suricataTotal;
            document.getElementById('suricata-ips').textContent = suricataIPs;
            document.getElementById('suricata-response').textContent = '< 10ms';
            
            document.getElementById('ml-total').textContent = mlTotal;
            document.getElementById('ml-ips').textContent = mlIPs;
            document.getElementById('ml-confidence').textContent = avgConfidence + '%';

            // Calculate detection rates (baseline: total malicious attacks in suite)
            const totalAttacks = 50; // Approximate from attack suite
            const suricataRate = ((suricataTotal / totalAttacks) * 100).toFixed(1);
            const mlRate = ((mlTotal / totalAttacks) * 100).toFixed(1);

            document.getElementById('suricata-rate').textContent = suricataRate + '%';
            document.getElementById('ml-rate').textContent = mlRate + '%';

            // Update comparison bars - Total Detections
            const maxValue = Math.max(suricataTotal, mlTotal, 1);
            
            const suricataPercentTotal = (suricataTotal / maxValue * 100);
            const mlPercentTotal = (mlTotal / maxValue * 100);
            
            document.getElementById('bar-total-suricata').style.width = suricataPercentTotal + '%';
            document.getElementById('bar-total-ml').style.width = mlPercentTotal + '%';
            document.getElementById('bar-total-suricata-text').textContent = suricataTotal;
            document.getElementById('bar-total-ml-text').textContent = mlTotal;

            // Update comparison bars - Unique Threats
            const maxUnique = Math.max(suricataIPs, mlIPs, 1);
            const suricataPercentUnique = (suricataIPs / maxUnique * 100);
            const mlPercentUnique = (mlIPs / maxUnique * 100);
            
            document.getElementById('bar-unique-suricata').style.width = suricataPercentUnique + '%';
            document.getElementById('bar-unique-ml').style.width = mlPercentUnique + '%';
            document.getElementById('bar-unique-suricata-text').textContent = suricataIPs;
            document.getElementById('bar-unique-ml-text').textContent = mlIPs;
        }

        function displayAlerts(suricataAlerts, mlAlerts) {
            // Suricata alerts - show recent 30
            const suricataContainer = document.getElementById('suricata-alerts');
            suricataContainer.innerHTML = suricataAlerts.slice(-30).reverse().map(alert => `
                <div class="alert-item suricata-alert">
                    <div class="alert-time">${formatTime(alert.timestamp)}</div>
                    <div><strong>${alert.alert?.signature || 'Network Threat Detected'}</strong></div>
                    <div style="color: #aaa; font-size: 0.9em; margin-top: 5px;">
                        ${alert.src_ip}:${alert.src_port} → ${alert.dest_ip}:${alert.dest_port}
                    </div>
                    <div style="font-size: 0.85em; margin-top: 5px; color: #ff6b6b;">
                        Category: ${alert.alert?.category || 'General'}
                    </div>
                    <span class="alert-type pattern-detection">SIGNATURE</span>
                </div>
            `).join('');

            // ML alerts - show recent 30
            const mlContainer = document.getElementById('ml-alerts');
            mlContainer.innerHTML = mlAlerts.slice(-30).reverse().map(alert => `
                <div class="alert-item ml-alert">
                    <div class="alert-time">${formatTime(alert.timestamp)}</div>
                    <div><strong>${alert.alert_type || 'Anomaly Detected'}</strong></div>
                    <div style="color: #aaa; font-size: 0.9em; margin-top: 5px;">
                        ${alert.src_ip}:${alert.src_port} → ${alert.dst_ip}:${alert.dst_port}
                    </div>
                    ${alert.details ? `<div style="font-size: 0.85em; margin-top: 5px;">${alert.details}</div>` : ''}
                    ${alert.confidence ? `<div style="font-size: 0.85em; color: #4ecdc4; margin-top: 5px;">
                        Confidence: ${(alert.confidence * 100).toFixed(1)}%
                    </div>` : ''}
                    <span class="alert-type ml-detection">ML</span>
                </div>
            `).join('');

            updateStats(suricataAlerts, mlAlerts);
        }

        function refreshData() {
            fetch('/api/alerts')
                .then(response => response.json())
                .then(data => {
                    displayAlerts(data.suricata_alerts, data.ml_alerts);
                })
                .catch(error => console.error('Error:', error));
        }

        function clearLogs() {
            if (confirm('Clear all logs? This cannot be undone.')) {
                fetch('/api/clear', {method: 'POST'})
                    .then(() => refreshData())
                    .catch(error => console.error('Error:', error));
            }
        }

        // Auto-refresh every 5 seconds
        setInterval(refreshData, 5000);
        refreshData();
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return DASHBOARD_HTML

@app.route('/api/alerts')
def get_alerts():
    suricata_alerts = []
    ml_alerts = []
    
    # Read Suricata alerts
    if os.path.exists(SURICATA_LOG):
        try:
            with open(SURICATA_LOG, 'r') as f:
                line_num = 0
                for line in f:
                    line_num += 1
                    try:
                        event = json.loads(line)
                        if event.get('event_type') == 'alert':
                            suricata_alerts.append(event)
                    except Exception as parse_error:
                        if line_num <= 5:  # Only log first few errors to avoid spam
                            print(f"Error parsing Suricata line {line_num}: {parse_error}")
        except Exception as e:
            print(f"Error reading Suricata log: {e}")
    else:
        print(f"Suricata log not found at: {SURICATA_LOG}")
    
    # Read ML alerts
    if os.path.exists(ML_IDS_LOG):
        try:
            with open(ML_IDS_LOG, 'r') as f:
                ml_alerts = json.load(f)
        except Exception as e:
            print(f"Error reading ML log: {e}")
    
    return jsonify({
        'suricata_alerts': suricata_alerts,
        'ml_alerts': ml_alerts
    })

@app.route('/api/clear', methods=['POST'])
def clear_alerts():
    try:
        # Clear Suricata log
        if os.path.exists(SURICATA_LOG):
            open(SURICATA_LOG, 'w').close()
        
        # Clear ML log
        if os.path.exists(ML_IDS_LOG):
            with open(ML_IDS_LOG, 'w') as f:
                json.dump([], f)
        
        return jsonify({'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)