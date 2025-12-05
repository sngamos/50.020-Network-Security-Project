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
            font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
            background: #ffffff;
            color: #000000;
            padding: 20px;
            min-height: 100vh;
        }
        .header {
            text-align: center;
            padding: 40px;
            background: #000000;
            border-radius: 8px;
            margin-bottom: 30px;
            border: 2px solid #000000;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.15);
        }
        .header h1 {
            font-size: 2.5em;
            color: #ffffff;
            margin-bottom: 10px;
            font-weight: 600;
            letter-spacing: 1px;
        }
        .header .subtitle {
            color: #cccccc;
            font-size: 1.1em;
        }
        .comparison-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            margin-bottom: 30px;
        }
        .stats-panel {
            background: #ffffff;
            padding: 30px;
            border-radius: 8px;
            border: 2px solid;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
        }
        .suricata-panel {
            border-color: #333333;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
        }
        .ml-panel {
            border-color: #666666;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
        }
        .panel-header {
            font-size: 1.6em;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 2px solid;
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-weight: 600;
        }
        .suricata-panel .panel-header {
            color: #000000;
            border-color: #000000;
        }
        .ml-panel .panel-header {
            color: #000000;
            border-color: #333333;
        }
        .stat-row {
            display: flex;
            justify-content: space-between;
            padding: 15px;
            margin: 10px 0;
            background: #f5f5f5;
            border-radius: 4px;
            border-left: 4px solid;
        }
        .suricata-panel .stat-row {
            border-left-color: #000000;
        }
        .ml-panel .stat-row {
            border-left-color: #666666;
        }
        .stat-label {
            color: #666666;
            font-size: 1.1em;
        }
        .stat-value {
            font-size: 1.5em;
            font-weight: bold;
        }
        .comparison-section {
            background: #ffffff;
            padding: 30px;
            border-radius: 8px;
            border: 2px solid #333333;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            margin-bottom: 30px;
        }
        .comparison-section h2 {
            color: #000000;
            font-size: 1.8em;
            margin-bottom: 20px;
            text-align: center;
            font-weight: 600;
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
            border-radius: 4px;
            transition: width 0.5s ease;
            display: flex;
            align-items: center;
            padding: 0 15px;
            font-weight: 600;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        .bar-suricata {
            background: #333333;
            color: white;
        }
        .bar-ml {
            background: #666666;
            color: white;
        }
        .alerts-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
        }
        .alerts-panel {
            background: #ffffff;
            padding: 25px;
            border-radius: 8px;
            border: 2px solid;
            max-height: 600px;
            overflow-y: auto;
        }
        .alerts-panel::-webkit-scrollbar {
            width: 10px;
        }
        .alerts-panel::-webkit-scrollbar-track {
            background: #f5f5f5;
            border-radius: 5px;
        }
        .alerts-panel::-webkit-scrollbar-thumb {
            background: #999999;
            border-radius: 5px;
        }
        .alert-item {
            background: #f9f9f9;
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
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
            border-left-color: #000000;
        }
        .ml-alert {
            border-left-color: #666666;
        }
        .alert-time {
            color: #666666;
            font-size: 0.9em;
            margin-bottom: 8px;
        }
        .alert-type {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 3px;
            font-size: 0.85em;
            font-weight: 600;
            margin: 5px 0;
        }
        .pattern-detection {
            background: #333333;
            color: white;
        }
        .ml-detection {
            background: #666666;
            color: white;
        }
        .controls {
            text-align: center;
            margin: 30px 0;
        }
        button {
            background: #000000;
            color: #ffffff;
            border: 2px solid #000000;
            padding: 12px 32px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 1em;
            font-weight: 600;
            margin: 0 10px;
            transition: all 0.2s;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        button:hover {
            background: #333333;
            border-color: #333333;
            box-shadow: 0 2px 6px rgba(0, 0, 0, 0.2);
        }
        .winner-badge {
            display: inline-block;
            padding: 5px 15px;
            background: #000000;
            color: #ffffff;
            border-radius: 3px;
            font-weight: 600;
            margin-left: 10px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>IDS COMPARISON DASHBOARD</h1>
        <div class="subtitle">XGBoost ML-IDS vs Suricata Signature-Based IDS</div>
        <div class="subtitle" style="font-size: 0.9em; margin-top: 10px; color: #888;">
            Network Security Project - Intrusion Detection System Performance Analysis
        </div>
    </div>

    <div class="controls">
        <button onclick="refreshData()">Refresh Data</button>
        <button onclick="clearLogs()">Clear Logs</button>
    </div>

    <div class="comparison-grid">
        <div class="stats-panel suricata-panel">
            <div class="panel-header">
                <span>Suricata IDS</span>
                <span style="font-size: 0.6em; color: #888;">(Signature-Based)</span>
            </div>
            <div class="stat-row">
                <span class="stat-label">Total Alerts</span>
                <span class="stat-value" id="suricata-total">0</span>
            </div>
        </div>

        <div class="stats-panel ml-panel">
            <div class="panel-header">
                <span>XGBoost ML-IDS</span>
                <span style="font-size: 0.6em; color: #888;">(Machine Learning)</span>
            </div>
            <div class="stat-row">
                <span class="stat-label">Total Alerts</span>
                <span class="stat-value" id="ml-total">0</span>
            </div>
        </div>
    </div>

    <div class="comparison-section">
        <h2>Detection Performance Comparison</h2>
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
                <span>Suricata Alerts</span>
            </div>
            <div id="suricata-alerts"></div>
        </div>

        <div class="alerts-panel ml-panel">
            <div class="panel-header">
                <span>ML-IDS Alerts</span>
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

            // Update displays
            document.getElementById('suricata-total').textContent = suricataTotal;
            document.getElementById('ml-total').textContent = mlTotal;

            // Update comparison bars - Total Detections
            const maxValue = Math.max(suricataTotal, mlTotal, 1);
            
            const suricataPercentTotal = (suricataTotal / maxValue * 100);
            const mlPercentTotal = (mlTotal / maxValue * 100);
            
            document.getElementById('bar-total-suricata').style.width = suricataPercentTotal + '%';
            document.getElementById('bar-total-ml').style.width = mlPercentTotal + '%';
            document.getElementById('bar-total-suricata-text').textContent = suricataTotal;
            document.getElementById('bar-total-ml-text').textContent = mlTotal;

            // Update comparison bars - Unique Threats
            const suricataIPs = new Set(suricataAlerts.map(a => a.src_ip)).size;
            const mlIPs = new Set(mlAlerts.map(a => a.src_ip)).size;
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