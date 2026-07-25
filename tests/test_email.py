#!/usr/bin/env python3
"""Tests for SENTINEL's email alerting.

These run against a real SMTP server (tests/fake_smtp.py) bound to 127.0.0.1 on
an ephemeral port, so smtplib does the genuine EHLO/AUTH/MAIL/RCPT/DATA
handshake. Nothing is mocked and nothing leaves the machine — a passing run
means the real send path works, not that a stub was called.
"""
import os
import sys
import tempfile
import time

TMP = tempfile.mkdtemp(prefix="sentinel-mail-log-")
DET = tempfile.mkdtemp(prefix="sentinel-mail-det-")   # empty: no detectors spawn

os.environ["SENTINEL_LOG_DIR"] = TMP
os.environ["SENTINEL_DETECTORS_DIR"] = DET
# Short digest interval so the real digest thread is testable in seconds.
os.environ["SENTINEL_EMAIL_INTERVAL"] = "5"

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fake_smtp import FakeSMTPServer  # noqa: E402
import Sentinel as S  # noqa: E402

FAILURES = []


def check(name, cond, extra=""):
    if cond:
        print(f"  ✓ {name}")
    else:
        print(f"  ✗ {name} {extra}")
        FAILURES.append(name)


def wait_for(pred, timeout=10.0):
    """Poll until pred() is truthy. Used for the threaded send paths."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(0.05)
    return pred()


server = FakeSMTPServer()
server.start()

GOOD = {
    "enabled": True,
    "smtp_host": server.host,
    "smtp_port": server.port,
    "smtp_username": "sentinel@example.test",
    "smtp_password": "hunter2",
    "use_tls": False,          # the fake server is plaintext on loopback
    "from_addr": "sentinel@example.test",
    "to_addrs": ["soc@example.test", "oncall@example.test"],
    "digest_interval": 5,
    "immediate_detectors": ["network", "syscall"],
}

client = S.app.test_client()
with client.session_transaction() as sess:
    sess['logged_in'] = True


# ------------------------------------------------------------------ config --
print("\n[1] Config persistence and password handling")

S.update_email_config(dict(GOOD))
check("config round-trips through disk",
      S.load_email_config()['smtp_username'] == GOOD['smtp_username'])
check("config file was actually written", os.path.exists(S.EMAIL_CONFIG_FILE))
check("no .tmp file left behind",
      not os.path.exists(S.EMAIL_CONFIG_FILE + ".tmp"))
mode = oct(os.stat(S.EMAIL_CONFIG_FILE).st_mode & 0o777)
check("config file is 0600 (holds an SMTP password)", mode == '0o600', mode)

got = client.get('/api/email-config').get_json()
check("GET /api/email-config never returns the password",
      'smtp_password' not in got, list(got))
check("...but does report that one is set", got['smtp_password_set'] is True)
check("GET returns the host/port", got['smtp_host'] == server.host
      and got['smtp_port'] == server.port)

# Blank password must mean "keep existing", not "wipe it".
client.post('/api/email-config', json={'smtp_password': '', 'from_addr': 'x@y.z'})
check("blank password field leaves the stored password intact",
      S.get_email_config()['smtp_password'] == 'hunter2',
      S.get_email_config()['smtp_password'])
S.update_email_config({'from_addr': GOOD['from_addr']})

r = client.post('/api/email-config', json={'smtp_port': 'not-a-number'})
check("non-numeric smtp_port is rejected with 400", r.status_code == 400,
      r.status_code)
r = client.post('/api/email-config', json={'digest_interval': 1})
check("digest_interval is floored at 5s",
      S.get_email_config()['digest_interval'] >= 5,
      S.get_email_config()['digest_interval'])
client.post('/api/email-config', json={'to_addrs': 'a@b.c,  d@e.f , '})
check("comma-separated recipients are parsed and trimmed",
      S.get_email_config()['to_addrs'] == ['a@b.c', 'd@e.f'],
      S.get_email_config()['to_addrs'])
client.post('/api/email-config', json={'immediate_detectors': 'network,bogus,file'})
check("unknown detector names are dropped from immediate_detectors",
      S.get_email_config()['immediate_detectors'] == ['file', 'network'],
      S.get_email_config()['immediate_detectors'])

S.update_email_config(dict(GOOD))


# -------------------------------------------------------------- send_email --
print("\n[2] send_email against a real SMTP conversation")

server.reset()
err = S.send_email("Test subject", "Test body line", cfg=S.get_email_config())
check("send_email reports no error", err is None, err)
check("the server actually received a message", len(server.messages) == 1,
      len(server.messages))

if server.messages:
    msg = server.messages[0]
    check("subject is correct", msg['Subject'] == "Test subject", msg['Subject'])
    check("From is set", msg['From'] == GOOD['from_addr'], msg['From'])
    check("both recipients are on the message",
          'soc@example.test' in msg['To'] and 'oncall@example.test' in msg['To'],
          msg['To'])
    check("body survived the wire",
          "Test body line" in msg.get_payload(), msg.get_payload()[:80])
check("credentials were sent and match the config",
      server.logins == [(GOOD['smtp_username'], GOOD['smtp_password'])],
      server.logins)

print("\n[3] send_email refuses to send when it shouldn't")

server.reset()
off = dict(GOOD, enabled=False)
check("returns None when alerting is disabled",
      S.send_email("s", "b", cfg=off) is None)
check("...and sends nothing", len(server.messages) == 0, len(server.messages))

for missing in ('smtp_username', 'smtp_password', 'to_addrs'):
    server.reset()
    bad = dict(GOOD)
    bad[missing] = [] if missing == 'to_addrs' else ''
    e = S.send_email("s", "b", cfg=bad)
    check(f"missing {missing} returns an error string", isinstance(e, str), e)
    check(f"...and sends nothing with {missing} missing",
          len(server.messages) == 0)

print("\n[4] SMTP failures are reported, not raised")

server.reset()
server.fail_auth = True
e = S.send_email("s", "b", cfg=S.get_email_config())
server.fail_auth = False
check("auth rejection returns an error string instead of raising",
      isinstance(e, str) and e, e)
check("...and no message is recorded", len(server.messages) == 0)

server.reset()
server.fail_data = True
e = S.send_email("s", "b", cfg=S.get_email_config())
server.fail_data = False
check("a server-side DATA rejection is reported",
      isinstance(e, str) and e, e)

server.reset()
dead = dict(GOOD, smtp_port=1)   # nothing listening
e = S.send_email("s", "b", cfg=dead)
check("an unreachable SMTP host returns an error rather than hanging",
      isinstance(e, str) and e, e)


# ------------------------------------------------------------- /api/email-test
print("\n[5] The dashboard's 'Send test email' button")

S.update_email_config(dict(GOOD))
server.reset()
r = client.post('/api/email-test')
body = r.get_json()
check("POST /api/email-test returns 200", r.status_code == 200,
      f"{r.status_code} {body}")
check("...with ok:true", body.get('ok') is True, body)
check("...and a real email arrives", wait_for(lambda: len(server.messages) == 1),
      len(server.messages))
if server.messages:
    check("the test email is recognisable",
          'SENTINEL' in server.messages[0]['Subject'],
          server.messages[0]['Subject'])

server.reset()
S.update_email_config({'to_addrs': []})
r = client.post('/api/email-test')
check("no recipients configured -> 400", r.status_code == 400, r.status_code)
check("...with a helpful message",
      'recipient' in (r.get_json().get('error') or '').lower(),
      r.get_json())

S.update_email_config({'to_addrs': GOOD['to_addrs'], 'smtp_password': ''})
r = client.post('/api/email-test')
check("no password configured -> 400", r.status_code == 400, r.status_code)

S.update_email_config(dict(GOOD))
server.fail_auth = True
r = client.post('/api/email-test')
server.fail_auth = False
check("SMTP rejection surfaces as 502", r.status_code == 502, r.status_code)
check("...with ok:false and the server's reason",
      r.get_json().get('ok') is False and r.get_json().get('error'),
      r.get_json())

# Regression: the test button used to return ok:true and send nothing when the
# "enabled" checkbox was off, because send_email() no-ops in that case and
# returns None -- the same value it returns on success. Users verify SMTP
# settings *before* switching alerting on, so this was the common path.
S.update_email_config(dict(GOOD, enabled=False))
server.reset()
r = client.post('/api/email-test')
check("test button still works with alerting disabled",
      r.status_code == 200, f"{r.status_code} {r.get_json()}")
check("...and really does send", wait_for(lambda: len(server.messages) == 1),
      len(server.messages))
check("...but reports that automatic alerting is off",
      r.get_json().get('alerting_enabled') is False, r.get_json())
if server.messages:
    check("...and says so in the email body too",
          'disabled' in server.messages[0].get_payload().lower(),
          server.messages[0].get_payload()[:200])

S.update_email_config(dict(GOOD))
server.reset()
r = client.post('/api/email-test')
check("with alerting enabled it reports alerting_enabled:true",
      r.get_json().get('alerting_enabled') is True, r.get_json())
wait_for(lambda: len(server.messages) == 1)


# ------------------------------------------------------------------ routing --
print("\n[6] Alert routing: immediate vs digest")

S.update_email_config(dict(GOOD, immediate_detectors=['network', 'syscall']))
with S.email_lock:
    for k in S.email_queue:
        S.email_queue[k] = []
server.reset()

crit = {'time': '2026-07-25 12:00:00', 'type': 'HIDDEN_CONNECTION',
        'details': 'HIDDEN_CONN|1.2.3.4:4444'}
S.queue_email_alert('network', crit)
check("a CRITICAL network alert is emailed immediately",
      wait_for(lambda: len(server.messages) == 1), len(server.messages))
if server.messages:
    check("...with the alert details in the body",
          '1.2.3.4:4444' in server.messages[0].get_payload(),
          server.messages[0].get_payload()[:120])
with S.email_lock:
    check("...and is not also queued for the digest",
          len(S.email_queue['network']) == 0, len(S.email_queue['network']))

server.reset()
low = {'time': '2026-07-25 12:00:01', 'type': 'HIDDEN_FILE_ACCESS',
       'details': 'HIDDEN_FILE|/tmp/.evil'}
S.queue_email_alert('file', low)
with S.email_lock:
    check("a non-immediate alert is queued, not sent",
          len(S.email_queue['file']) == 1, len(S.email_queue['file']))
check("...and no email went out yet",
      not wait_for(lambda: len(server.messages) > 0, timeout=1.5))

print(f"\n[7] Digest thread (waiting up to 20s for a "
      f"{S.get_email_config()['digest_interval']}s interval)")
server.reset()
check("the queued alert is delivered by the digest thread",
      wait_for(lambda: len(server.messages) >= 1, timeout=20),
      len(server.messages))
if server.messages:
    dig = server.messages[0]
    check("digest subject counts the alerts",
          'FILE' in dig['Subject'] and '1' in dig['Subject'], dig['Subject'])
    check("digest body contains the alert", '/tmp/.evil' in dig.get_payload(),
          dig.get_payload()[:160])
with S.email_lock:
    check("the queue is drained after sending",
          len(S.email_queue['file']) == 0, len(S.email_queue['file']))

server.reset()
S.update_email_config(dict(GOOD, enabled=False))
with S.email_lock:
    S.email_queue['file'].append(low)
check("nothing is sent while alerting is disabled",
      not wait_for(lambda: len(server.messages) > 0, timeout=8))
with S.email_lock:
    S.email_queue['file'] = []
S.update_email_config(dict(GOOD))

print("\n[7b] flush_email_digest does not hold the lock across the SMTP send")

# Regression: the digest used to send *inside* `with email_lock`, so every SMTP
# round trip (10s timeout) blocked the log-tail thread from enqueuing alerts,
# and any alert that landed mid-send was then wiped by the post-send clear.
server.reset()
with S.email_lock:
    S.email_queue['file'] = [low, dict(low, details='HIDDEN_FILE|/tmp/.evil2')]

lock_free_during_send = []
# flush_email_digest() resolves send_email in its own module namespace, so the
# probe has to replace it there -- rebinding the re-export on Sentinel would
# leave the real function in place.
real_send = S.emailer.send_email


def probing_send(subject, body, cfg=None):
    got = S.email_lock.acquire(blocking=False)
    lock_free_during_send.append(got)
    if got:
        # Simulate an alert arriving while the digest is being transmitted.
        S.email_queue['file'].append(dict(low, details='HIDDEN_FILE|/tmp/.during'))
        S.email_lock.release()
    return real_send(subject, body, cfg=cfg)


S.emailer.send_email = probing_send
try:
    n = S.flush_email_digest()
finally:
    S.emailer.send_email = real_send

check("flush_email_digest reports the digests it sent", n == 1, n)
check("the alert queue is writable during the SMTP send",
      lock_free_during_send == [True], lock_free_during_send)
check("both queued alerts made it into one digest",
      server.messages and '/tmp/.evil2' in server.messages[0].get_payload(),
      server.messages[0].get_payload()[:200] if server.messages else None)
with S.email_lock:
    check("an alert arriving mid-send is kept for the next digest, not dropped",
          [a['details'] for a in S.email_queue['file']]
          == ['HIDDEN_FILE|/tmp/.during'],
          [a['details'] for a in S.email_queue['file']])
    S.email_queue['file'] = []

check("flush is a no-op when there is nothing queued",
      S.flush_email_digest() == 0)
check("flush is a no-op when alerting is disabled",
      S.flush_email_digest(cfg=dict(GOOD, enabled=False)) == 0)


# -------------------------------------------------------------------- auth --
print("\n[8] Email endpoints require a session")

anon = S.app.test_client()
for method, path in (('get', '/api/email-config'),
                     ('post', '/api/email-config'),
                     ('post', '/api/email-test')):
    r = getattr(anon, method)(path, json={})
    check(f"{method.upper()} {path} is not open to anonymous callers",
          r.status_code in (301, 302, 401, 403), r.status_code)


# ------------------------------------------------------------------ cleanup --
server.stop()

print("\n" + "=" * 58)
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s):")
    for f in FAILURES:
        print(f"  - {f}")
    sys.exit(1)
print("EMAIL CHECKS PASSED")
sys.exit(0)
