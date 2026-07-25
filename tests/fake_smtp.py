"""A minimal real SMTP server for testing SENTINEL's email alerting.

Speaks enough of ESMTP (EHLO, AUTH PLAIN/LOGIN, MAIL, RCPT, DATA, QUIT) that
smtplib talks to it exactly as it would to a real provider, so the tests
exercise the actual wire path rather than a mocked-out smtplib.

Python 3.8's stdlib `smtpd` can't do AUTH and `aiosmtpd` isn't installed, hence
this. It listens on 127.0.0.1 on an ephemeral port and never touches the network.
"""
import base64
import email
import socket
import threading


class FakeSMTPServer(threading.Thread):
    def __init__(self, fail_auth=False, fail_data=False):
        super().__init__(daemon=True)
        self.messages = []       # parsed EmailMessage objects received
        self.logins = []         # (username, password) tuples seen
        self.auth_mechs = []     # mechanisms actually used by the client
        self.fail_auth = fail_auth
        self.fail_data = fail_data
        self._stop = threading.Event()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(8)
        self.sock.settimeout(0.5)
        self.port = self.sock.getsockname()[1]
        self.host = '127.0.0.1'

    # -- lifecycle ---------------------------------------------------------
    def run(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def stop(self):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass

    def reset(self):
        self.messages.clear()
        self.logins.clear()
        self.auth_mechs.clear()

    # -- protocol ----------------------------------------------------------
    def _serve(self, conn):
        rf = conn.makefile('rb')

        def send(line):
            conn.sendall(line.encode() + b'\r\n')

        def readline():
            return rf.readline().decode('utf-8', 'replace').rstrip('\r\n')

        send('220 fake.sentinel.test ESMTP ready')
        try:
            while True:
                line = readline()
                if not line:
                    break
                verb = line.split(' ')[0].upper()

                if verb == 'EHLO':
                    send('250-fake.sentinel.test')
                    send('250-AUTH PLAIN LOGIN')
                    send('250 HELP')
                elif verb == 'HELO':
                    send('250 fake.sentinel.test')
                elif verb == 'AUTH':
                    self._do_auth(line, send, readline)
                elif verb == 'MAIL':
                    send('250 2.1.0 Sender OK')
                elif verb == 'RCPT':
                    send('250 2.1.5 Recipient OK')
                elif verb == 'DATA':
                    if self.fail_data:
                        send('552 5.3.4 Message too big for system')
                        continue
                    send('354 End data with <CR><LF>.<CR><LF>')
                    chunks = []
                    while True:
                        raw = rf.readline()
                        if not raw or raw in (b'.\r\n', b'.\n'):
                            break
                        if raw.startswith(b'..'):
                            raw = raw[1:]        # undo SMTP dot-stuffing
                        chunks.append(raw)
                    self.messages.append(
                        email.message_from_bytes(b''.join(chunks)))
                    send('250 2.0.0 Ok: queued as FAKE1')
                elif verb == 'RSET':
                    send('250 2.0.0 Ok')
                elif verb == 'NOOP':
                    send('250 2.0.0 Ok')
                elif verb == 'QUIT':
                    send('221 2.0.0 Bye')
                    break
                else:
                    send('502 5.5.2 Command not recognized')
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _do_auth(self, line, send, readline):
        parts = line.split()
        mech = parts[1].upper() if len(parts) > 1 else ''
        self.auth_mechs.append(mech)

        if mech == 'PLAIN':
            if len(parts) > 2:
                blob = parts[2]
            else:
                send('334 ')
                blob = readline()
            try:
                decoded = base64.b64decode(blob).split(b'\x00')
                self.logins.append((decoded[1].decode(), decoded[2].decode()))
            except Exception:
                send('501 5.5.2 Cannot decode response')
                return
        elif mech == 'LOGIN':
            send('334 ' + base64.b64encode(b'Username:').decode())
            user = base64.b64decode(readline()).decode()
            send('334 ' + base64.b64encode(b'Password:').decode())
            pwd = base64.b64decode(readline()).decode()
            self.logins.append((user, pwd))
        else:
            send('504 5.5.4 Unrecognized authentication type')
            return

        if self.fail_auth:
            send('535 5.7.8 Username and Password not accepted')
        else:
            send('235 2.7.0 Authentication successful')
