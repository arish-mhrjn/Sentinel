#!/usr/bin/env python3
"""Smoke test for the SENTINEL dashboard additions.

Runs the real Flask app against a temp log dir (no root, no BCC needed) and
exercises: severity assignment, the correlation rules, /api/health,
/api/timeline and the /api/alerts filters.
"""
import os
import sys
import tempfile
import time
from datetime import datetime, timedelta

TMP = tempfile.mkdtemp(prefix="sentinel-test-")
EMPTY = tempfile.mkdtemp(prefix="sentinel-nodetectors-")
os.environ["SENTINEL_LOG_DIR"] = TMP
os.environ["SENTINEL_DETECTORS_DIR"] = EMPTY

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import Sentinel as S  # noqa: E402

FAILURES = []
fed = 0  # alerts pushed through parse_alert so far


def check(name, cond, extra=""):
    if cond:
        print(f"  ✓ {name}")
    else:
        print(f"  ✗ {name} {extra}")
        FAILURES.append(name)


def ts(offset_seconds=0):
    return (datetime.now() + timedelta(seconds=offset_seconds)).strftime('%Y-%m-%d %H:%M:%S')


def feed(line):
    global fed
    S.parse_alert(line)
    fed += 1


client = S.app.test_client()
with client.session_transaction() as sess:
    sess['logged_in'] = True

print("\n[1] Auth still enforced on the new endpoints")
anon = S.app.test_client()
for ep in ('/api/health', '/api/timeline', '/api/correlations', '/api/alerts'):
    r = anon.get(ep)
    check(f"{ep} redirects when logged out", r.status_code == 302, f"got {r.status_code}")

print("\n[2] Base severity is assigned server-side")
# Fed alone, so no correlation rule can fire and change the severity yet.
feed(f"{ts()} | FILE | HIDDEN_FILE | /tmp/.hidden-payload invisible to readdir")
check("file alert stored", len(S.alerts['file']) == 1)
check("file base severity = MEDIUM", S.alerts['file'][0]['severity'] == 'MEDIUM',
      S.alerts['file'][0].get('severity'))
check("epoch parsed from log timestamp",
      abs(S.alerts['file'][0]['epoch'] - time.time()) < 120)
check("no correlations from a single detector", len(S.correlations) == 0,
      [c['rule'] for c in S.correlations])

print("\n[3] process+file within 60s escalates the file alert")
feed(f"{ts()} | PROCESS | HIDDEN_PID | pid=1337 hidden from /proc")
check("process base severity = HIGH", S.alerts['process'][0]['severity'] == 'HIGH')
check("STEALTH_FOOTPRINT raised",
      'STEALTH_FOOTPRINT' in [c['rule'] for c in S.correlations],
      [c['rule'] for c in S.correlations])
check("file alert escalated MEDIUM -> HIGH", S.alerts['file'][0]['severity'] == 'HIGH',
      S.alerts['file'][0]['severity'])
check("file alert tagged with the rule",
      'STEALTH_FOOTPRINT' in S.alerts['file'][0].get('correlated', []),
      S.alerts['file'][0].get('correlated'))

print("\n[4] Correlation engine fires LKM_ROOTKIT on module+syscall")
feed(f"{ts()} | MODULE | HIDDEN_MODULE | rootkit_lkm not in /proc/modules")
feed(f"{ts()} | SYSCALL | TABLE_MISMATCH | __x64_sys_getdents64 invoked=1043 handled=1039")
lkm = next((c for c in S.correlations if c['rule'] == 'LKM_ROOTKIT'), None)
check("LKM_ROOTKIT raised", lkm is not None, [c['rule'] for c in S.correlations])
check("correlation is CRITICAL", lkm and lkm['severity'] == 'CRITICAL')
check("correlation cites both detectors",
      lkm and {c['detector'] for c in lkm['contributors']} == {'module', 'syscall'},
      lkm and [c['detector'] for c in lkm['contributors']])
check("contributing module alert tagged",
      'LKM_ROOTKIT' in S.alerts['module'][0].get('correlated', []),
      S.alerts['module'][0].get('correlated'))

print("\n[5] Four detectors inside the window trigger MULTI_VECTOR")
check("MULTI_VECTOR raised",
      'MULTI_VECTOR' in [c['rule'] for c in S.correlations],
      [c['rule'] for c in S.correlations])
check("file alert escalated again to CRITICAL",
      S.alerts['file'][0]['severity'] == 'CRITICAL', S.alerts['file'][0]['severity'])

print("\n[6] Cooldown suppresses duplicate correlations")
feed(f"{ts()} | NETWORK | HIDDEN_SOCKET | 10.0.0.5:4444 not visible to ss")
before = len([c for c in S.correlations if c['rule'] == 'LKM_ROOTKIT'])
feed(f"{ts()} | MODULE | HIDDEN_MODULE | rootkit_lkm still hidden")
feed(f"{ts()} | SYSCALL | TABLE_MISMATCH | __x64_sys_kill invoked=91 handled=88")
after = len([c for c in S.correlations if c['rule'] == 'LKM_ROOTKIT'])
check("no duplicate LKM_ROOTKIT within cooldown", before == after, f"{before} -> {after}")

print("\n[7] /api/alerts filtering")
d = client.get('/api/alerts').get_json()
check("unfiltered returns everything", sum(d['total_counts'].values()) == fed,
      f"{sum(d['total_counts'].values())} != {fed}")
check("filtered flag false", d['filtered'] is False)
check("severity_counts present", 'CRITICAL' in d['severity_counts'])
check("severity_counts sum to the alert total",
      sum(d['severity_counts'].values()) == fed, d['severity_counts'])

d = client.get('/api/alerts?severity=CRITICAL').get_json()
sevs = {a['severity'] for items in d['alerts'].values() for a in items}
check("severity filter returns only CRITICAL", sevs <= {'CRITICAL'}, sevs)
check("filtered flag true", d['filtered'] is True)

d = client.get('/api/alerts?q=4444').get_json()
hits = [a for items in d['alerts'].values() for a in items]
check("text search matches details", len(hits) == 1 and '4444' in hits[0]['details'], len(hits))

d = client.get('/api/alerts?q=HIDDEN_MODULE').get_json()
check("text search matches alert type",
      sum(d['counts'].values()) == 2, sum(d['counts'].values()))

d = client.get('/api/alerts?q=NOTHINGMATCHESTHIS').get_json()
check("no-match search returns zero", sum(d['counts'].values()) == 0)

d = client.get('/api/alerts?minutes=5').get_json()
check("recent window keeps all fresh alerts", sum(d['counts'].values()) == fed,
      sum(d['counts'].values()))

feed(f"{ts(-7200)} | PROCESS | OLD_ALERT | two hours ago")
d = client.get('/api/alerts?minutes=5').get_json()
check("time window excludes the 2h-old alert", sum(d['counts'].values()) == fed - 1,
      sum(d['counts'].values()))
d = client.get('/api/alerts').get_json()
check("unfiltered still includes it", sum(d['counts'].values()) == fed)

d = client.get('/api/alerts?detector=module').get_json()
check("detector filter isolates one detector",
      sum(d['counts'].values()) == d['counts']['module'] and d['counts']['module'] == 2,
      d['counts'])

d = client.get('/api/alerts?severity=BOGUS').get_json()
check("invalid severity ignored rather than 500", sum(d['counts'].values()) == fed,
      sum(d['counts'].values()))

d = client.get('/api/alerts?q=hidden&severity=CRITICAL&minutes=5').get_json()
combo = [a for items in d['alerts'].values() for a in items]
check("filters combine (AND, not OR)",
      all(a['severity'] == 'CRITICAL' and 'hidden' in
          f"{a['type']} {a['details']}".lower() for a in combo) and len(combo) > 0,
      len(combo))

print("\n[8] /api/timeline")
d = client.get('/api/timeline?minutes=30&bucket=60').get_json()
check("timeline has 30 buckets", len(d['labels']) == 30, len(d['labels']))
check("all detectors present in series", set(d['series']) == set(S.alerts))
check("bucket lengths match labels",
      all(len(v) == len(d['labels']) for v in d['series'].values()))
total_binned = sum(sum(v) for v in d['series'].values())
check("recent alerts landed in buckets (2h-old one excluded)",
      total_binned == fed - 1, f"{total_binned} != {fed - 1}")
check("newest alerts land in the final bucket",
      sum(d['series'][k][-1] for k in d['series']) > 0,
      {k: v[-1] for k, v in d['series'].items()})
d = client.get('/api/timeline?minutes=1440&bucket=300').get_json()
check("24h window includes the 2h-old alert",
      sum(sum(v) for v in d['series'].values()) == fed, fed)
d = client.get('/api/timeline?minutes=abc&bucket=abc').get_json()
check("bad timeline params fall back to defaults", len(d['labels']) == 30)

print("\n[9] /api/health")
d = client.get('/api/health').get_json()
check("reports all five detectors", d['total'] == 5, d['total'])
check("missing scripts reported as 'missing'",
      all(x['status'] == 'missing' for x in d['detectors']),
      [x['status'] for x in d['detectors']])
check("all_healthy false when detectors are down", d['all_healthy'] is False)
proc_entry = next(x for x in d['detectors'] if x['name'] == 'process')
check("alert counts tracked per detector", proc_entry['alert_count'] == 2,
      proc_entry['alert_count'])
check("last_alert recorded", proc_entry['last_alert'] is not None)

print("\n[10] Detector-down raises a correlation")
S.record_detector_down('syscall', -9, 42.0)
downs = [c for c in S.correlations if c['rule'] == 'DETECTOR_DOWN']
check("DETECTOR_DOWN correlation raised", len(downs) == 1)
check("DETECTOR_DOWN is CRITICAL", downs[0]['severity'] == 'CRITICAL')

print("\n[11] /api/correlations and export")
d = client.get('/api/correlations').get_json()
check("correlations endpoint returns list", d['count'] == len(S.correlations))
check("every correlation is JSON-safe",
      all('_contributing_alerts' not in c for c in d['correlations']))

r = client.get('/export?detectors=process,module,file,network,syscall')
check("export returns a zip", r.status_code == 200 and r.data[:2] == b'PK', r.status_code)
import io, zipfile  # noqa: E402
zf = zipfile.ZipFile(io.BytesIO(r.data))
names = zf.namelist()
check("export includes a correlation report",
      any(n.startswith('correlations_') for n in names), names)
proc_txt = zf.read(next(n for n in names if n.startswith('process_'))).decode()
check("export lines carry severity", '[HIGH]' in proc_txt or '[CRITICAL]' in proc_txt)

print("\n[12] Dashboard HTML renders")
r = client.get('/')
check("index 200", r.status_code == 200, r.status_code)
body = r.get_data(as_text=True)
for marker in ('health-strip', 'timelineChart', 'filter-q', 'corr-container',
               'panel-correlations', 'filter-severity', 'filter-minutes',
               'correlated-threats', 'timeline-range'):
    check(f"template contains #{marker}", marker in body)
check("correlations list is not a .alert-container (would be blanked by tab switch)",
      'id="corr-container" class="corr-list"' in body)
check("no unrendered Jinja braces left in output", '{{' not in body)

print("\n" + "=" * 58)
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s): {', '.join(FAILURES)}")
    sys.exit(1)
print(f"ALL CHECKS PASSED ({fed} alerts fed, {len(S.correlations)} correlations raised)")
sys.exit(0)
