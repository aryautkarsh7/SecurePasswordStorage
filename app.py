"""Local academic authentication application; Python 3.10+, no dependencies."""
import argparse
import hashlib
import hmac
import html
from http.cookies import SimpleCookie, CookieError
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
from pathlib import Path
import secrets
import sqlite3
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit

import database
from security import hash_password, verify_password, token_hash, validate, validate_password

ROOT = Path(__file__).resolve().parent
SESSION_SECONDS = 1800


def esc(value):
    return html.escape(str(value), quote=True)


def date(value):
    return datetime.fromtimestamp(value, timezone.utc).strftime('%d %b %Y, %H:%M:%S UTC')


HOW = '''<section class="card" id="how"><p class="eyebrow">THE CRYPTOGRAPHY</p>
<h2>How it works</h2><div class="explain">
<div><h3>01 · Hash, don’t encrypt</h3><p>Encryption can be reversed with a key. Password hashing derives a value for verification; there is no decryption step. Plaintext storage exposes every password if the database is stolen.</p></div>
<div><h3>02 · Add a unique salt</h3><p>Each password gets 16 random bytes. A salt is public, not a secret. Two users choosing the same password get different salts and hashes, defeating precomputed hash tables.</p></div>
<div><h3>03 · SHA-256 digest</h3><p>The salted password bytes are passed through SHA-256, producing a 32-byte (256-bit) digest. This is a one-way function: the original password cannot be recovered from the digest.</p></div>
<div><h3>04 · Verify without recovering</h3><p>At login, we concatenate the stored salt with the submitted password and hash again. A constant-time comparison checks the result against the stored digest.</p></div></div></section>'''


def password_field(name, label, autocomplete='new-password'):
    return f'''<label for="{name}">{label}</label><div class="password"><input id="{name}" name="{name}" type="password" autocomplete="{autocomplete}" required aria-describedby="password-help"><button type="button" class="reveal" data-target="{name}" aria-pressed="false">Show</button></div>'''


class Application(HTTPServer):
    # Single-request processing makes attempt checks + inserts atomic relative to
    # other requests. SQLite constraints still enforce uniqueness. Local demo only.
    def __init__(self, address, db_path, https=False, clock=time.time):
        self.db_path = str(db_path)
        database.initialize(self.db_path)
        self.clock = clock
        self.https = https
        self.csrf_key = secrets.token_bytes(32)
        self.dummy = hash_password(secrets.token_urlsafe(32))
        super().__init__(address, Handler)
        port = self.server_address[1]
        self.hosts = {f'127.0.0.1:{port}', f'localhost:{port}', '127.0.0.1', 'localhost', f'0.0.0.0:{port}'}
        allowed = os.environ.get('ALLOWED_HOSTS')
        if allowed:
            if allowed == '*':
                self.hosts = None
            else:
                self.hosts.update(h.strip() for h in allowed.split(','))
        self.scheme = 'https' if https else 'http'


class Handler(BaseHTTPRequestHandler):
    server_version = 'SecurePasswordStorage'
    sys_version = ''

    def log_message(self, *args):
        # No request bodies, paths, cookies, passwords, or tokens in console logs.
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def send(self, status, body='', location=None):
        self.send_response(status)
        self.send_header('Content-Type', getattr(self, 'mime', 'text/html; charset=utf-8'))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        # Preserve same-origin form Origin headers; no-referrer can produce
        # an opaque (null) Origin on browser POST navigation.
        self.send_header('Referrer-Policy', 'same-origin')
        self.send_header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
        self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        if self.server.https:
            self.send_header('Strict-Transport-Security', 'max-age=31536000')
        if getattr(self, 'cookie', None):
            self.send_header('Set-Cookie', self.cookie)
        if location:
            self.send_header('Location', location)
        if getattr(self, 'retry', None):
            self.send_header('Retry-After', str(self.retry))
        data = body.encode('utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def page(self, title, content, status=200, message=''):
        notice = f'<div class="notice" role="alert">{esc(message)}</div>' if message else ''
        body = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{esc(title)} · Secure Password Storage</title><link rel="stylesheet" href="/static/style.css"><script defer src="/static/app.js"></script></head><body><header><a class="brand" href="/">◈ <span>Secure<span class="mint">Pass</span></span></a><nav aria-label="Main navigation"><a href="/dashboard">Dashboard</a><a href="/#how">How it works</a></nav></header><main>{notice}{content}</main><footer>Alliance University · B.Tech CSE · Cryptography and Network Security<br>Academic demonstration · Local authentication system</footer></body></html>'''
        self.send(status, body)

    def trusted(self):
        hosts = self.headers.get_all('Host', [])
        if len(hosts) != 1 or (self.server.hosts is not None and hosts[0] not in self.server.hosts):
            self.send(400, 'Invalid Host header. Use the printed localhost URL.')
            return False
        origins = self.headers.get_all('Origin', [])
        if origins:
            if len(origins) != 1:
                self.send(403, 'Untrusted Origin.')
                return False
            valid_origins = {f'{self.server.scheme}://{hosts[0]}'}
            if self.server.hosts:
                for h in self.server.hosts:
                    valid_origins.add(f'{self.server.scheme}://{h}')
            if origins[0] not in valid_origins and self.server.hosts is not None:
                self.send(403, 'Untrusted Origin.')
                return False
        if self.headers.get('Sec-Fetch-Site') == 'cross-site':
            self.send(403, 'Cross-site request rejected.')
            return False
        return True

    def load_session(self, db):
        self.raw_token = ''
        try:
            cookies = SimpleCookie(self.headers.get('Cookie', ''))
            if 'session' in cookies:
                self.raw_token = cookies['session'].value
        except CookieError:
            pass
        self.session = db.execute('SELECT * FROM sessions WHERE token_hash=? AND expires>?',
                                  (token_hash(self.raw_token), self.server.clock())).fetchone()
        self.user = None
        if self.session and self.session['user_id']:
            self.user = db.execute('SELECT * FROM users WHERE id=?', (self.session['user_id'],)).fetchone()

    def new_session(self, db, user_id=None):
        db.execute('DELETE FROM sessions WHERE token_hash=? OR expires<=?',
                   (token_hash(self.raw_token), self.server.clock()))
        self.raw_token = secrets.token_urlsafe(32)
        db.execute('INSERT INTO sessions VALUES (?,?,?)',
                   (token_hash(self.raw_token), user_id, self.server.clock() + SESSION_SECONDS))
        self.cookie = f'session={self.raw_token}; Path=/; Max-Age=1800; HttpOnly; SameSite=Strict'
        if self.server.https:
            self.cookie += '; Secure'

    def csrf(self):
        return hmac.new(self.server.csrf_key, self.raw_token.encode(), hashlib.sha256).hexdigest()

    def hidden(self):
        return f'<input type="hidden" name="csrf" value="{self.csrf()}">'

    def event(self, db, user_id, name):
        db.execute('INSERT INTO activity(user_id,event,created) VALUES (?,?,?)',
                   (user_id, name, self.server.clock()))

    def limited(self, db, scope, account='', limit=5):
        now = self.server.clock()
        db.execute('DELETE FROM attempts WHERE created<=?', (now - 300,))
        buckets = [(f'{scope}:ip:{self.client_address[0]}', 30)]
        if account:
            buckets.append((f'{scope}:account:{token_hash(account.lower())}', limit))
        waits = []
        for bucket, maximum in buckets:
            rows = db.execute('SELECT created FROM attempts WHERE bucket=? ORDER BY created', (bucket,)).fetchall()
            if len(rows) >= maximum:
                waits.append(max(1, int(rows[0]['created'] + 300 - now) + 1))
        if waits:
            self.retry = max(waits)
            self.page('Cooldown', '<section class="card"><h1>Please wait before trying again</h1><p>Five verification attempts per account and 30 per client IP are allowed in a rolling five-minute window. Successful attempts count too.</p><a href="/login">Sign in</a> · <a href="/dashboard">Dashboard</a></section>', 429,
                      f'Too many attempts. Try again in {self.retry} seconds. Waiting does not extend the cooldown.')
            return True
        for bucket, _ in buckets:
            db.execute('INSERT INTO attempts VALUES (?,?)', (bucket, now))
        return False

    def auth_page(self, register=False, message='', status=200):
        title = 'Create your account' if register else 'Welcome back'
        path = '/register' if register else '/login'
        confirm = password_field('confirm', 'Confirm password') if register else ''
        content = f'''<div class="auth-layout"><section class="intro"><p class="eyebrow">SECURE PASSWORD STORAGE SYSTEM</p><h1>Your password.<br><span class="mint">Never stored.</span></h1><p class="lead">See cryptography at work. Create an account, sign in, and inspect exactly how your password is protected.</p><div class="chips"><span>SHA-256</span><span>Unique random salts</span><span>Constant-time verify</span></div><p>Authentication, not a password manager. Your original password cannot be retrieved from this interface.</p></section><section class="card"><p class="eyebrow">{'GET STARTED' if register else 'YOUR ACCOUNT'}</p><h2>{title}</h2><form method="post" action="{path}">{self.hidden()}<label for="username">Username</label><input id="username" name="username" autocomplete="username" required maxlength="30" aria-describedby="username-help"><p class="hint" id="username-help">3–30 letters, numbers, or underscores. Case-insensitive.</p>{password_field('password', 'Password', 'new-password' if register else 'current-password')}<p id="password-help" class="hint">15–128 characters. Spaces and Unicode are welcome.</p>{confirm}<button class="primary" type="submit">{'Create account' if register else 'Sign in →'}</button></form><p>{'<a href="/login">Already registered? Sign in</a>' if register else '<a href="/register">New here? Create an account</a>'}</p></section></div>{HOW}'''
        self.page(title, content, status, message)

    def dashboard(self, db, message='', status=200):
        user = self.user
        algorithm, salt, digest = user['password_value'].split('$')
        events = db.execute('SELECT event,created FROM activity WHERE user_id=? ORDER BY id DESC LIMIT 20', (user['id'],)).fetchall()
        rows = ''.join(f'<li><span>{esc(e["event"])}</span><time>{date(e["created"])}</time></li>' for e in events)
        content = f'''<section class="dashboard-heading"><div><p class="eyebrow">YOUR SECURITY DASHBOARD</p><h1>Welcome, {esc(user['username'])}.</h1><p>Account created {date(user['created'])}</p></div><form method="post" action="/logout">{self.hidden()}<button type="submit">Log out</button></form></section><div class="stats"><div class="card"><span>ALGORITHM</span><strong>SHA-256 (salted)</strong></div><div class="card"><span>DIGEST SIZE</span><strong>32 bytes (256 bits)</strong></div><div class="card"><span>SESSION LIFETIME</span><strong>30 minutes</strong></div></div><section class="card" id="inspector"><p class="eyebrow">01 / PASSWORD STORAGE INSPECTOR</p><h2>What the database actually stores</h2><p>Only your own record is shown. This inspector is for the academic demonstration and would normally be omitted from a production authentication interface.</p><dl><dt>Algorithm identifier</dt><dd>{esc(algorithm)}</dd><dt>Salt size</dt><dd>{len(bytes.fromhex(salt))} bytes (128 bits)</dd><dt>Hash size</dt><dd>{len(bytes.fromhex(digest))} bytes (256 bits)</dd><dt>Actual stored salt · hexadecimal</dt><dd><code>{esc(salt)}</code></dd><dt>Actual derived hash · hexadecimal</dt><dd><code>{esc(digest)}</code></dd><dt>Complete encoded database value</dt><dd><code>{esc(user['password_value'])}</code></dd></dl><p class="hint">Format: algorithm$salt_hex$hash_hex. No plaintext password is stored.</p></section><div class="columns"><section class="card" id="change"><p class="eyebrow">02 / CHANGE PASSWORD</p><h2>A fresh password. A fresh salt.</h2><p>Changing your password signs out every session for your account.</p><form method="post" action="/change-password">{self.hidden()}{password_field('current', 'Current password', 'current-password')}{password_field('new', 'New password')}<p class="hint" id="password-help">15–128 characters. Must differ from your current password.</p>{password_field('confirm', 'Confirm new password')}<button class="primary" type="submit">Change password</button></form></section><section class="card"><p class="eyebrow">03 / RECENT ACCOUNT ACTIVITY</p><h2>Your security timeline</h2><p>Most recent 20 events · UTC</p><ul class="activity">{rows}</ul></section></div>{HOW}'''
        self.page('Dashboard', content, status, message)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        if not self.trusted():
            return
        path = urlsplit(self.path).path
        if path in ('/static/style.css', '/static/app.js'):
            self.mime = 'text/css; charset=utf-8' if path.endswith('css') else 'text/javascript; charset=utf-8'
            self.send(200, (ROOT / path.lstrip('/')).read_text())
            return
        with database.connect(self.server.db_path) as db:
            self.load_session(db)
            if path == '/dashboard':
                if not self.user:
                    self.send(303, location='/login')
                else:
                    self.dashboard(db)
            elif path in ('/', '/login', '/register'):
                if self.user:
                    self.send(303, location='/dashboard')
                    return
                if not self.session:
                    self.new_session(db)
                messages = {'registered': 'Account created. Sign in to open your dashboard.',
                            'changed': 'Password changed. All sessions revoked. Sign in again.',
                            'logout': 'You have been signed out.'}
                flag = parse_qs(urlsplit(self.path).query).get('notice', [''])[0]
                self.auth_page(path == '/register', messages.get(flag, ''))
            else:
                self.send(404, 'Page not found.')

    def do_POST(self):
        if not self.trusted():
            return
        if self.headers.get('Transfer-Encoding') or len(self.headers.get_all('Content-Length', [])) != 1:
            self.send(400, 'Invalid request framing.')
            return
        try:
            length = int(self.headers['Content-Length'])
            if not 0 < length <= 8192:
                raise ValueError
            if self.headers.get_content_type() != 'application/x-www-form-urlencoded':
                raise ValueError
            body = self.rfile.read(length).decode('utf-8', errors='strict')
            form = parse_qs(body, keep_blank_values=True, max_num_fields=10, errors='strict')
            if any(len(v) != 1 for v in form.values()):
                raise ValueError
            form = {k: v[0] for k, v in form.items()}
        except (ValueError, UnicodeError):
            self.send(400, 'Invalid or oversized form.')
            return
        with database.connect(self.server.db_path) as db:
            self.load_session(db)
            supplied = form.get('csrf', '')
            if not self.session or not hmac.compare_digest(supplied.encode(), self.csrf().encode()):
                self.send(403, 'Invalid or expired CSRF token. Reload the form and try again.')
                return
            path = urlsplit(self.path).path
            username = form.get('username', '')
            password = form.get('password', '')
            if path == '/register':
                if self.limited(db, 'register'):
                    return
                error = validate(username, password, form.get('confirm', ''))
                if error:
                    self.auth_page(True, error, 400)
                    return
                try:
                    cur = db.execute('INSERT INTO users(username,password_value,created) VALUES (?,?,?)',
                                     (username, hash_password(password), self.server.clock()))
                except sqlite3.IntegrityError:
                    self.auth_page(True, 'That username is already registered.', 409)
                    return
                self.event(db, cur.lastrowid, 'Account created')
                self.send(303, location='/login?notice=registered')
            elif path == '/login':
                if self.limited(db, 'login', username or '<empty>'):
                    return
                user = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
                # Unknown users still run the same expensive password derivation.
                valid = verify_password(password, user['password_value'] if user else self.server.dummy)
                if not user or not valid or not 15 <= len(password) <= 128:
                    if user:
                        self.event(db, user['id'], 'Failed login')
                    self.auth_page(False, 'Invalid username or password', 401)
                    return
                self.new_session(db, user['id'])
                self.event(db, user['id'], 'Successful login')
                self.send(303, location='/dashboard')
            elif path in ('/change-password', '/logout'):
                if not self.user:
                    self.send(303, location='/login')
                    return
                uid = self.user['id']
                if path == '/logout':
                    db.execute('DELETE FROM sessions WHERE token_hash=?', (token_hash(self.raw_token),))
                    self.event(db, uid, 'Logout')
                    self.cookie = 'session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict' + ('; Secure' if self.server.https else '')
                    self.send(303, location='/login?notice=logout')
                    return
                if self.limited(db, 'change', self.user['username']):
                    return
                current = form.get('current', '')
                new = form.get('new', '')
                if not verify_password(current, self.user['password_value']):
                    self.dashboard(db, 'Current password is incorrect.', 400)
                    return
                error = validate_password(new, form.get('confirm', ''))
                if not error and new == current:
                    error = 'Choose a password different from your current password.'
                if error:
                    self.dashboard(db, error, 400)
                    return
                db.execute('UPDATE users SET password_value=? WHERE id=?', (hash_password(new), uid))
                db.execute('DELETE FROM sessions WHERE user_id=?', (uid,))
                self.event(db, uid, 'Password changed')
                self.new_session(db)
                self.send(303, location='/login?notice=changed')
            else:
                self.send(404, 'Page not found.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    default_port = int(os.environ.get('PORT', 8000))
    default_host = os.environ.get('HOST', '0.0.0.0')
    parser.add_argument('--host', default=default_host)
    parser.add_argument('--port', type=int, default=default_port)
    parser.add_argument('--db', type=Path, default=ROOT / 'data' / 'securepassword.sqlite3')
    parser.add_argument('--cert', help='Optional local TLS certificate PEM')
    parser.add_argument('--key', help='Optional local TLS private key PEM')
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error('Port must be between 1 and 65535.')
    if bool(args.cert) != bool(args.key):
        parser.error('Supply both --cert and --key to enable HTTPS.')
    try:
        server = Application((args.host, args.port), args.db, https=bool(args.cert))
        if args.cert:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(args.cert, args.key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
    except OSError as error:
        parser.exit(1, f'Cannot start server ({error.strerror or "TLS/file error"}). If the port is occupied, try: python3 app.py --port 8001\n')
    print(f'Secure Password Storage: http://localhost:{args.port} or http://127.0.0.1:{args.port}', flush=True)
    print('Press Ctrl+C to stop. Academic demonstration system.', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
