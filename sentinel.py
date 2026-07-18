#!/usr/bin/env python3
from flask import Flask, render_template_string, jsonify, send_file, request
import subprocess
import threading
import time
import json
import os
import zipfile
from datetime import datetime
from io import BytesIO

app = Flask(__name__)
LOG_FILE = "/var/log/sentinel/alerts.log"
DETECTORS_DIR = "/root/sentinel/src/bpf"
os.makedirs("/var/log/sentinel", exist_ok=True)

alerts = {
    'process': [],
    'module': [],
    'file': [],
    'network': [],
    'syscall': []
}

last_position = 0
lock = threading.Lock()
detector_processes = []

def start_detectors():
    detectors = [
        ('process', 'process_detector.py'),
        ('module', 'module_detector.py'),
        ('file', 'file_detector.py'),
        ('network', 'network_detector.py'),
        ('syscall', 'syscall_monitor.py'),
    ]
    print("\n[*] Starting detectors...")
    for name, script in detectors:
        script_path = os.path.join(DETECTORS_DIR, script)
        if os.path.exists(script_path):
            proc = subprocess.Popen(['python3', script_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            detector_processes.append(proc)
            print(f"    ✓ Started {name} detector")
        else:
            print(f"    ✗ {script} not found")
    print("[*] All detectors started\n")

def tail_log():
    global last_position
    while True:
        try:
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, 'r') as f:
                    f.seek(last_position)
                    for line in f:
                        line = line.strip()
                        if line:
                            parse_alert(line)
                    last_position = f.tell()
        except:
            pass
        time.sleep(1)

def parse_alert(line):
    try:
        parts = line.split(' | ')
        if len(parts) >= 4:
            timestamp = parts[0]
            detector = parts[1].lower()
            alert_type = parts[2]
            details = ' | '.join(parts[3:])
            if detector in alerts:
                with lock:
                    alerts[detector].append({
                        'time': timestamp,
                        'type': alert_type,
                        'details': details,
                    })
                    if len(alerts[detector]) > 200:
                        alerts[detector] = alerts[detector][-200:]
    except:
        pass

threading.Thread(target=tail_log, daemon=True).start()
start_detectors()

HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SENTINEL | Rootkit Detection Framework</title>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; user-select: none; -webkit-tap-highlight-color: transparent; }

        body {
            background: radial-gradient(ellipse at 20% 30%, #0a1519, #020a0c);
            font-family: 'Orbitron', 'Courier New', monospace;
            min-height: 100vh;
            color: #00d9ff;
            padding: 20px;
            cursor: default;
            position: relative;
        }

        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-image:
                linear-gradient(rgba(0,217,255,0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0,217,255,0.03) 1px, transparent 1px);
            background-size: 30px 30px;
            pointer-events: none;
            z-index: 0;
        }

        .bg-animation {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -1;
            overflow: hidden;
        }

        .bg-animation::before {
            content: '';
            position: absolute;
            width: 200%;
            height: 200%;
            background: repeating-linear-gradient(
                45deg,
                rgba(0,217,255, 0.02) 0px,
                rgba(0,217,255, 0.02) 2px,
                transparent 2px,
                transparent 8px
            );
            animation: scan 20s linear infinite;
        }

        @keyframes scan {
            0% { transform: translate(0, 0); }
            100% { transform: translate(50%, 50%); }
        }

        .header {
            text-align: center;
            margin-bottom: 30px;
            position: relative;
            z-index: 1;
        }

        h1 {
            font-size: 56px;
            background: linear-gradient(135deg, #00d9ff, #0088aa, #005566);
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
            text-shadow: 0 0 30px rgba(0,217,255,0.3);
            letter-spacing: 4px;
            animation: pulse 2s ease-in-out infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; text-shadow: 0 0 20px rgba(0,217,255,0.3); }
            50% { opacity: 0.9; text-shadow: 0 0 40px rgba(0,217,255,0.6); }
        }

        .subtitle {
            color: #66aacc;
            margin-top: 10px;
            font-size: 14px;
            letter-spacing: 2px;
        }

        .status-dot {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #00d9ff;
            box-shadow: 0 0 10px #00d9ff;
            animation: blink 1s infinite;
            margin-right: 8px;
        }

        @keyframes blink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.3; }
        }

        /* Stats Grid */
        .stats-grid {
            display: flex;
            justify-content: center;
            gap: 15px;
            margin-bottom: 30px;
            flex-wrap: wrap;
            position: relative;
            z-index: 1;
        }

        .stat-card {
            background: linear-gradient(135deg, rgba(30,0,10,0.85), rgba(20,0,10,0.95));
            backdrop-filter: blur(10px);
            border: 1px solid rgba(0,217,255,0.3);
            border-radius: 15px;
            padding: 15px 25px;
            text-align: center;
            transition: all 0.3s ease;
            min-width: 110px;
            position: relative;
            overflow: hidden;
            cursor: pointer;
        }

        .stat-card::after {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(0,217,255,0.1), transparent);
            opacity: 0;
            transition: opacity 0.3s;
        }

        .stat-card:hover::after {
            opacity: 1;
        }

        .stat-card:hover {
            transform: translateY(-3px);
            border-color: #00d9ff;
            box-shadow: 0 0 20px rgba(0,217,255,0.2);
        }

        .stat-icon { font-size: 28px; margin-bottom: 5px; }
        .stat-number { font-size: 36px; font-weight: bold; color: #ffaa44; text-shadow: 0 0 5px rgba(255,170,68,0.3); }
        .stat-label { font-size: 10px; color: #88bbcc; margin-top: 5px; text-transform: uppercase; letter-spacing: 1px; }

        /* Main Tab Bar */
        .main-tab-bar {
            display: flex;
            gap: 10px;
            margin-bottom: 25px;
            flex-wrap: wrap;
            justify-content: center;
            position: relative;
            z-index: 1;
        }

        .main-tab {
            background: rgba(30,0,10,0.8);
            backdrop-filter: blur(5px);
            border: 1px solid rgba(0,217,255,0.3);
            padding: 12px 28px;
            border-radius: 12px;
            font-family: 'Orbitron', monospace;
            font-size: 14px;
            font-weight: bold;
            transition: all 0.3s ease;
            color: #00d9ff;
            cursor: pointer;
        }

        .main-tab:hover {
            transform: translateY(-2px);
            background: rgba(0,217,255,0.1);
            border-color: #00d9ff;
        }

        .main-tab.active {
            background: #00d9ff;
            color: #0a1519;
            box-shadow: 0 0 20px rgba(0,217,255,0.5);
        }

        .main-panel {
            display: none;
            position: relative;
            z-index: 1;
        }

        .main-panel.active {
            display: block;
            animation: fadeSlide 0.4s ease;
        }

        @keyframes fadeSlide {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        /* Dashboard Grid - Centered Charts */
        .dashboard-grid {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 30px;
            margin-bottom: 30px;
            flex-wrap: wrap;
        }

        .dashboard-card {
            flex: 1;
            min-width: 380px;
            max-width: 500px;
            background: rgba(30,0,10,0.6);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(0,217,255,0.2);
            border-radius: 20px;
            padding: 20px;
            transition: all 0.3s ease;
        }

        .dashboard-card:hover {
            border-color: rgba(0,217,255,0.5);
            box-shadow: 0 0 20px rgba(0,217,255,0.1);
        }

        .dashboard-card h3 {
            color: #00d9ff;
            margin-bottom: 15px;
            font-size: 16px;
            border-bottom: 1px solid rgba(0,217,255,0.3);
            padding-bottom: 10px;
            text-align: center;
        }

        .chart-container {
            position: relative;
            height: 280px;
            width: 100%;
            padding: 15px;
            display: flex;
            justify-content: center;
            align-items: center;
        }

        canvas {
            max-height: 250px;
            width: auto !important;
        }

        /* Alert Mini Cards */
        .alert-cards-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }

        .alert-mini-card {
            background: rgba(30,0,10,0.5);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(0,217,255,0.2);
            border-radius: 12px;
            padding: 12px;
            text-align: center;
            transition: all 0.3s ease;
            cursor: pointer;
        }

        .alert-mini-card:hover {
            transform: translateY(-3px);
            border-color: #00d9ff;
            background: rgba(0,217,255,0.05);
        }

        .alert-mini-card .icon { font-size: 28px; margin-bottom: 5px; }
        .alert-mini-card .count { font-size: 28px; font-weight: bold; color: #ffaa44; }
        .alert-mini-card .name { font-size: 10px; color: #88bbcc; margin-top: 5px; text-transform: uppercase; }

        .threat-stat {
            display: flex;
            justify-content: space-between;
            padding: 10px 0;
            border-bottom: 1px solid rgba(0,217,255,0.1);
        }

        .threat-stat .label { color: #88bbcc; font-size: 13px; }
        .threat-stat .value { color: #ffaa44; font-weight: bold; font-size: 18px; }

        /* Alert Container - Glowing Amber Alerts */
        .alert-container {
            display: none;
            background: rgba(10,0,8,0.7);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 20px;
            min-height: 450px;
            max-height: 500px;
            overflow-y: auto;
            border: 1px solid rgba(0,217,255,0.2);
        }

        .alert-container.active {
            display: block;
            animation: fadeSlide 0.4s ease;
        }

        .alert-item {
            background: linear-gradient(90deg, rgba(255,0,0,0.15), rgba(255,0,0,0.05));
            border-left: 4px solid #ff0000;
            padding: 14px 18px;
            margin-bottom: 12px;
            border-radius: 10px;
            transition: all 0.3s ease;
            box-shadow: 0 0 10px rgba(255,0,0,0.2);
            animation: redGlow 2s ease-in-out infinite;
        }

        @keyframes redGlow {
            0% { box-shadow: 0 0 5px rgba(255,0,0,0.2); border-left-color: #ff0000; }
            50% { box-shadow: 0 0 20px rgba(255,0,0,0.5); border-left-color: #ff4444; }
            100% { box-shadow: 0 0 5px rgba(255,0,0,0.2); border-left-color: #ff0000; }
        }

        .alert-item:hover {
            transform: translateX(8px);
            background: linear-gradient(90deg, rgba(255,0,0,0.25), rgba(255,0,0,0.1));
            box-shadow: 0 0 25px rgba(255,0,0,0.6);
        }

        .alert-time { color: #ff8888; font-size: 11px; margin-bottom: 8px; }
        .alert-message { color: #ff4444; font-size: 13px; word-break: break-word; font-weight: bold; }
        .alert-badge { background: #ff0000; color: white; padding: 2px 10px; border-radius: 12px; font-size: 10px; margin-left: 10px; }

        .no-alerts {
            text-align: center;
            padding: 60px;
            color: #336677;
            font-size: 14px;
        }

        /* Sub Tabs */
        .sub-tab-bar {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            flex-wrap: wrap;
            justify-content: center;
        }

        .sub-tab {
            background: rgba(30,0,10,0.6);
            border: 1px solid rgba(0,217,255,0.2);
            padding: 8px 20px;
            border-radius: 20px;
            font-family: 'Orbitron', monospace;
            font-size: 12px;
            cursor: pointer;
            transition: all 0.3s ease;
            color: #00d9ff;
        }

        .sub-tab:hover {
            background: rgba(0,217,255,0.1);
        }

        .sub-tab.active {
            background: #00d9ff;
            color: #0a1519;
        }

        .footer {
            text-align: center;
            margin-top: 25px;
            padding-top: 15px;
            border-top: 1px solid rgba(0,217,255,0.2);
            font-size: 11px;
            color: #447788;
        }

        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: rgba(30,0,10,0.5); border-radius: 10px; }
        ::-webkit-scrollbar-thumb { background: #00d9ff; border-radius: 10px; }

        .export-container {
            text-align: center;
            margin-bottom: 25px;
        }

        .export-btn {
            background: linear-gradient(135deg, #1a2323, #0f1c1f);
            border: 1px solid #00d9ff;
            color: #00d9ff;
            padding: 12px 35px;
            border-radius: 40px;
            font-family: 'Orbitron', monospace;
            font-size: 14px;
            font-weight: bold;
            transition: all 0.3s ease;
            cursor: pointer;
        }

        .export-btn:hover {
            background: #00d9ff;
            color: #0a1519;
            transform: translateY(-2px);
            box-shadow: 0 0 30px rgba(0,217,255,0.5);
        }

        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.9);
            backdrop-filter: blur(8px);
            justify-content: center;
            align-items: center;
        }

        .modal.active { display: flex; }

        .modal-content {
            background: linear-gradient(135deg, #0a1a1f, #051012);
            border: 2px solid #00d9ff;
            border-radius: 20px;
            padding: 25px;
            min-width: 350px;
            animation: modalFade 0.3s ease;
        }

        @keyframes modalFade {
            from { opacity: 0; transform: scale(0.9); }
            to { opacity: 1; transform: scale(1); }
        }

        .modal-content h3 { color: #00d9ff; text-align: center; margin-bottom: 20px; }
        .checkbox-label {
            display: block;
            padding: 10px;
            margin: 5px 0;
            background: rgba(30,0,10,0.5);
            border-radius: 8px;
            cursor: pointer;
        }
        .checkbox-label:hover { background: rgba(0,217,255,0.15); transform: translateX(5px); }
        .checkbox-label input { margin-right: 12px; accent-color: #00d9ff; }
        .modal-buttons { display: flex; gap: 15px; justify-content: center; margin-top: 20px; }
        .modal-btn { padding: 8px 20px; border-radius: 8px; font-weight: bold; cursor: pointer; }
        .export-submit { background: #00d9ff; color: #0a1519; border: none; }
        .close-btn { background: transparent; border: 1px solid #ffaa44; color: #ffaa44; }
        .select-all { margin-bottom: 15px; border-bottom: 1px solid rgba(0,217,255,0.3); padding-bottom: 10px; }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        let selectedDetectors = { process: false, module: false, file: false, network: false, syscall: false };
        let alertChart = null;
        let severityChart = null;

        function openExportModal() { document.getElementById('exportModal').classList.add('active'); }
        function closeExportModal() { document.getElementById('exportModal').classList.remove('active'); }

        function toggleSelectAll() {
            const all = document.getElementById('selectAllCheckbox').checked;
            for (let key in selectedDetectors) {
                selectedDetectors[key] = all;
                const chk = document.getElementById(`chk_${key}`);
                if (chk) chk.checked = all;
            }
        }

        function updateDetector(detector) {
            selectedDetectors[detector] = document.getElementById(`chk_${detector}`).checked;
            const all = Object.values(selectedDetectors).every(v => v === true);
            const any = Object.values(selectedDetectors).some(v => v === true);
            document.getElementById('selectAllCheckbox').checked = all;
            document.getElementById('exportSubmit').disabled = !any;
        }

        function submitExport() {
            const selected = [];
            for (let key in selectedDetectors) if (selectedDetectors[key]) selected.push(key);
            if (selected.length === 0) return;
            window.location.href = `/export?detectors=${selected.join(',')}`;
            closeExportModal();
        }

        function switchMainTab(tabName, element) {
            document.querySelectorAll('.main-panel').forEach(p => p.classList.remove('active'));
            document.querySelectorAll('.main-tab').forEach(t => t.classList.remove('active'));
            document.getElementById(`panel-${tabName}`).classList.add('active');
            element.classList.add('active');
        }

        function switchAlertTab(tabName, element) {
            document.querySelectorAll('.alert-container').forEach(c => c.classList.remove('active'));
            document.querySelectorAll('.sub-tab').forEach(t => t.classList.remove('active'));
            document.getElementById(`alerts-${tabName}`).classList.add('active');
            element.classList.add('active');
        }

        function updateDashboard(data) {
            // Update mini-cards and stat cards
            for (let detector in data.counts) {
                const el = document.getElementById(`stat-${detector}`);
                if (el) el.innerText = data.counts[detector];
                const miniEl = document.getElementById(`mini-${detector}`);
                if (miniEl) miniEl.innerText = data.counts[detector];
            }

            const total = Object.values(data.counts).reduce((a,b)=>a+b,0);
            const critical = data.counts.network + data.counts.syscall;
            const high = data.counts.process + data.counts.module;
            const medium = data.counts.file;

            document.getElementById('total-threats').innerText = total;
            document.getElementById('critical-threats').innerText = critical;
            document.getElementById('high-threats').innerText = high;
            document.getElementById('medium-threats').innerText = medium;

            // Update Bar Chart
            const barCtx = document.getElementById('alertChart').getContext('2d');
            if (alertChart) {
                alertChart.data.datasets[0].data = [data.counts.process, data.counts.module, data.counts.file, data.counts.network, data.counts.syscall];
                alertChart.update();
            } else {
                alertChart = new Chart(barCtx, {
                    type: 'bar',
                    data: { labels: ['PROCESS', 'MODULE', 'FILE', 'NETWORK', 'SYSCALL'], datasets: [{ label: 'Alert Count', data: [0,0,0,0,0], backgroundColor: '#00d9ff', borderRadius: 8, barPercentage: 0.6 }] },
                    options: { responsive: true, maintainAspectRatio: true, plugins: { legend: { labels: { color: '#00d9ff', font: { family: 'Orbitron' } } } }, scales: { y: { grid: { color: 'rgba(0,217,255,0.1)' }, ticks: { color: '#00d9ff' } }, x: { ticks: { color: '#00d9ff', font: { family: 'Orbitron' } } } } }
                });
            }

            // Update Pie Chart
            const pieCtx = document.getElementById('severityChart').getContext('2d');
            if (severityChart) {
                severityChart.data.datasets[0].data = [critical, high, medium];
                severityChart.update();
            } else {
                severityChart = new Chart(pieCtx, {
                    type: 'doughnut',
                    data: { labels: ['Critical (Network/Syscall)', 'High (Process/Module)', 'Medium (File)'], datasets: [{ data: [0,0,0], backgroundColor: ['#ff0000', '#ff8c00', '#ffdd44'], borderWidth: 0 }] },
                    options: { responsive: true, maintainAspectRatio: true, plugins: { legend: { labels: { color: '#00d9ff', font: { family: 'Orbitron' } } } } }
                });
            }

            // Update alert containers with glowing amber alerts
            for (let detector of ['process', 'module', 'file', 'network', 'syscall']) {
                const container = document.getElementById(`alerts-${detector}`);
                const alerts = data.alerts[detector];
                if (container) {
                    if (alerts.length === 0) {
                        container.innerHTML = '<div class="no-alerts">🔒 No threats detected</div>';
                    } else {
                        let html = '';
                        for (let i = alerts.length-1; i >= 0; i--) {
                            html += `<div class="alert-item"><div class="alert-time">⚠️ ${alerts[i].time}</div><div class="alert-message">🚨 <span class="alert-badge">${escapeHtml(alerts[i].type)}</span> ${escapeHtml(alerts[i].details)}</div></div>`;
                        }
                        container.innerHTML = html;
                    }
                }
            }
        }

        function escapeHtml(text) { return text.replace(/[&<>]/g, function(m){if(m==='&') return '&amp;'; if(m==='<') return '&lt;'; if(m==='>') return '&gt;'; return m;}); }

        function refresh() { fetch('/api/alerts').then(r=>r.json()).then(data=>updateDashboard(data)).catch(e=>console.error(e)); }

        setInterval(refresh, 2000);
        refresh();
    </script>
</head>
<body>
    <div class="bg-animation"></div>

    <div class="header">
        <h1>💀 SENTINEL</h1>
        <div class="subtitle"><span class="status-dot"></span> eBPF Real-Time Rootkit Detection</div>
    </div>

    <div class="export-container">
        <button class="export-btn" onclick="openExportModal()">📤 EXPORT ALERTS</button>
    </div>

    <div class="main-tab-bar">
        <div class="main-tab active" onclick="switchMainTab('dashboard', this)">📊 SIEM DASHBOARD</div>
        <div class="main-tab" onclick="switchMainTab('alerts', this)">🚨 ALERTS</div>
    </div>

    <!-- Dashboard Panel -->
    <div id="panel-dashboard" class="main-panel active">
        <!-- Top Stats Cards -->
        <div class="stats-grid">
            <div class="stat-card"><div class="stat-icon">📊</div><div class="stat-number" id="total-threats">0</div><div class="stat-label">TOTAL</div></div>
            <div class="stat-card"><div class="stat-icon">🔴</div><div class="stat-number" id="critical-threats">0</div><div class="stat-label">CRITICAL</div></div>
            <div class="stat-card"><div class="stat-icon">🟠</div><div class="stat-number" id="high-threats">0</div><div class="stat-label">HIGH</div></div>
            <div class="stat-card"><div class="stat-icon">🟡</div><div class="stat-number" id="medium-threats">0</div><div class="stat-label">MEDIUM</div></div>
        </div>

        <!-- Charts Row - Centered -->
        <div class="dashboard-grid">
            <div class="dashboard-card"><h3>📈 ALERTS BY DETECTOR</h3><div class="chart-container"><canvas id="alertChart"></canvas></div></div>
            <div class="dashboard-card"><h3>🥧 SEVERITY DISTRIBUTION</h3><div class="chart-container"><canvas id="severityChart"></canvas></div></div>
        </div>

        <!-- Detector Mini Cards -->
        <div class="alert-cards-row">
            <div class="alert-mini-card" onclick="switchMainTab('alerts', document.querySelector('.main-tab:last-child')); setTimeout(()=>{document.querySelector('.sub-tab').click();},100)">
                <div class="icon">🔍</div><div class="count" id="mini-process">0</div><div class="name">PROCESS</div>
            </div>
            <div class="alert-mini-card" onclick="switchMainTab('alerts', document.querySelector('.main-tab:last-child')); setTimeout(()=>{document.querySelectorAll('.sub-tab')[1].click();},100)">
                <div class="icon">📦</div><div class="count" id="mini-module">0</div><div class="name">MODULE</div>
            </div>
            <div class="alert-mini-card" onclick="switchMainTab('alerts', document.querySelector('.main-tab:last-child')); setTimeout(()=>{document.querySelectorAll('.sub-tab')[2].click();},100)">
                <div class="icon">📁</div><div class="count" id="mini-file">0</div><div class="name">FILE</div>
            </div>
            <div class="alert-mini-card" onclick="switchMainTab('alerts', document.querySelector('.main-tab:last-child')); setTimeout(()=>{document.querySelectorAll('.sub-tab')[3].click();},100)">
                <div class="icon">🌐</div><div class="count" id="mini-network">0</div><div class="name">NETWORK</div>
            </div>
            <div class="alert-mini-card" onclick="switchMainTab('alerts', document.querySelector('.main-tab:last-child')); setTimeout(()=>{document.querySelectorAll('.sub-tab')[4].click();},100)">
                <div class="icon">⚙️</div><div class="count" id="mini-syscall">0</div><div class="name">SYSCALL</div>
            </div>
        </div>
    </div>

    <!-- Alerts Panel -->
    <div id="panel-alerts" class="main-panel">
        <div class="sub-tab-bar">
            <div class="sub-tab active" onclick="switchAlertTab('process', this)">🔍 PROCESS</div>
            <div class="sub-tab" onclick="switchAlertTab('module', this)">📦 MODULE</div>
            <div class="sub-tab" onclick="switchAlertTab('file', this)">📁 FILE</div>
            <div class="sub-tab" onclick="switchAlertTab('network', this)">🌐 NETWORK</div>
            <div class="sub-tab" onclick="switchAlertTab('syscall', this)">⚙️ SYSCALL</div>
        </div>

        <div id="alerts-process" class="alert-container active"><div class="no-alerts">🔒 No threats detected</div></div>
        <div id="alerts-module" class="alert-container"><div class="no-alerts">🔒 No threats detected</div></div>
        <div id="alerts-file" class="alert-container"><div class="no-alerts">🔒 No threats detected</div></div>
        <div id="alerts-network" class="alert-container"><div class="no-alerts">🔒 No threats detected</div></div>
        <div id="alerts-syscall" class="alert-container"><div class="no-alerts">🔒 No threats detected</div></div>
    </div>

    <div class="footer">
        <p>SENTINEL v3.0 | eBPF Real-Time Monitoring | Auto-refresh every 2 seconds | Glowing alerts = Active threats</p>
    </div>

    <!-- Export Modal -->
    <div id="exportModal" class="modal" onclick="if(event.target===this)closeExportModal()">
        <div class="modal-content">
            <h3>📤 SELECT DETECTORS TO EXPORT</h3>
            <div class="select-all"><label class="checkbox-label"><input type="checkbox" id="selectAllCheckbox" onchange="toggleSelectAll()"><span>✅ SELECT ALL</span></label></div>
            <label class="checkbox-label"><input type="checkbox" id="chk_process" onchange="updateDetector('process')"><span>🔍 PROCESS DETECTOR</span></label>
            <label class="checkbox-label"><input type="checkbox" id="chk_module" onchange="updateDetector('module')"><span>📦 MODULE DETECTOR</span></label>
            <label class="checkbox-label"><input type="checkbox" id="chk_file" onchange="updateDetector('file')"><span>📁 FILE DETECTOR</span></label>
            <label class="checkbox-label"><input type="checkbox" id="chk_network" onchange="updateDetector('network')"><span>🌐 NETWORK DETECTOR</span></label>
            <label class="checkbox-label"><input type="checkbox" id="chk_syscall" onchange="updateDetector('syscall')"><span>⚙️ SYSCALL MONITOR</span></label>
            <div class="modal-buttons"><button class="modal-btn export-submit" id="exportSubmit" onclick="submitExport()" disabled>📥 EXPORT</button><button class="modal-btn close-btn" onclick="closeExportModal()">❌ CANCEL</button></div>
        </div>
    </div>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(HTML)

@app.route('/api/alerts')
def get_alerts():
    with lock:
        counts = {k: len(v) for k, v in alerts.items()}
        return jsonify({'alerts': alerts, 'counts': counts})

@app.route('/export')
def export_custom():
    detectors_param = request.args.get('detectors', '')
    selected = detectors_param.split(',') if detectors_param else []
    date_str = datetime.now().strftime('%Y%m%d_%H%M%S')

    with lock:
        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            total = 0
            for det in selected:
                if det in alerts and alerts[det]:
                    content = [f"SENTINEL - {det.upper()} ALERTS", "="*60, f"Export Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", f"Total: {len(alerts[det])}", "="*60 + "\n"]
                    for a in alerts[det]:
                        content.append(f"[{a['time']}] [{a['type']}] {a['details']}")
                    zip_file.writestr(f"{det}_alerts_{date_str}.txt", "\n".join(content))
                    total += len(alerts[det])
            if total == 0:
                zip_file.writestr("no_alerts.txt", "No alerts found")
        zip_buffer.seek(0)
        return send_file(zip_buffer, mimetype='application/zip', as_attachment=True, download_name=f"sentinel_alerts_{date_str}.zip")

if __name__ == '__main__':
    print("="*60)
    print("🛡️ SENTINEL DASHBOARD")
    print("="*60)
    print("[*] Detectors starting automatically...")
    print("[*] Dashboard: http://localhost:5000")
    print("="*60)
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
