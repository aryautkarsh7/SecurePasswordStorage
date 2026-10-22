"""HTTP integration tests using isolated temporary databases and real SHA-256."""
import http.client
import io
import os
from http.cookies import SimpleCookie
from pathlib import Path
import re
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.parse import urlencode
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app
import database
from security import hash_password, verify_password, token_hash

IN_MEMORY = os.environ.get('SPS_IN_MEMORY_TESTS') == '1'


class MemorySocket:
    """Transport substitute only: application parsing and handlers are real."""
    def __init__(self, data):
        self.input = io.BytesIO(data)
        self.output = io.BytesIO()

    def makefile(self, mode, *args):
        return self.input

    def sendall(self, data):
        self.output.write(data)

    def settimeout(self, value):
        pass


PASSWORD = 'MyCollegeDemo@2026'
NEW = 'MyNewCollegeDemo@2026'


class Client:
    def __init__(self, server):
        self.server = server
        self.cookie = ''
        self.csrf = ''

    def request(self, path, data=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port)
        hdr = {'Cookie': self.cookie}
        if data is not None:
            hdr.update({'Content-Type': 'application/x-www-form-urlencoded',
                        'Origin': f'http://127.0.0.1:{self.server.server_port}'})
        hdr.update(headers or {})
        if IN_MEMORY:
            body = '' if data is None else urlencode(data)
            hdr.setdefault('Host', f'127.0.0.1:{self.server.server_port}')
            if data is not None:
                hdr['Content-Length'] = str(len(body.encode()))
            method = 'GET' if data is None else 'POST'
            wire = f'{method} {path} HTTP/1.1\r\n'
            wire += ''.join(f'{key}: {value}\r\n' for key, value in hdr.items())
            sock = MemorySocket((wire + '\r\n' + body).encode())
            app.Handler(sock, ('127.0.0.1', 10000), self.server)
            response = http.client.HTTPResponse(MemorySocket(sock.output.getvalue()))
            response.begin()
        else:
            connection.request('GET' if data is None else 'POST', path,
                               None if data is None else urlencode(data), hdr)
            response = connection.getresponse()
        text = response.read().decode()
        result = response.status, dict(response.getheaders()), text
        cookie = response.getheader('Set-Cookie')
        if cookie:
            self.cookie = cookie.split(';')[0]
        match = re.search('name="csrf" value="([a-f0-9]+)"', text)
        if match:
            self.csrf = match[1]
        connection.close()
        return result

    def post(self, path, **data):
        return self.request(path, {'csrf': self.csrf, **data})

    def register(self, name='student1', password=PASSWORD):
        self.request('/register')
        return self.post('/register', username=name, password=password, confirm=password)

    def login(self, name='student1', password=PASSWORD):
        self.request('/login')
        return self.post('/login', username=name, password=password)


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'test.sqlite3'
        self.now = 1_800_000_000.0
        if IN_MEMORY:
            with patch.object(app.HTTPServer, 'server_bind'), patch.object(app.HTTPServer, 'server_activate'):
                self.server = app.Application(('127.0.0.1', 8000), self.path, clock=lambda: self.now)
            self.server.server_port = 8000
        else:
            self.server = app.Application(('127.0.0.1', 0), self.path, clock=lambda: self.now)
            self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.thread.start()
        self.client = Client(self.server)

    def tearDown(self):
        if not IN_MEMORY:
            self.server.shutdown()
            self.thread.join()
        self.server.server_close()
        self.temp.cleanup()

    def rows(self, query, args=()):
        with database.connect(self.path) as db:
            return db.execute(query, args).fetchall()

    def signed_in(self):
        self.assertEqual(self.client.register()[0], 303)
        self.assertEqual(self.client.login()[0], 303)
        return self.client.request('/dashboard')

    def test_registration_duplicate_case_insensitive(self):
        self.assertEqual(self.client.register()[0], 303)
        self.assertEqual(self.client.register('STUDENT1')[0], 409)
        self.assertEqual(len(self.rows('SELECT * FROM users')), 1)

    def test_invalid_usernames_and_sql_injection(self):
        for name in ['ab', 'x'*31, 'bad space', "a' OR 1=1--", '<script>', 'ééé']:
            with self.subTest(name=name):
                self.assertEqual(self.client.register(name)[0], 400)
        self.assertEqual(self.rows('SELECT * FROM users'), [])
        self.assertEqual(self.client.login("' OR 1=1--")[0], 401)

    def test_password_validation_and_confirmation(self):
        self.client.request('/register')
        for password, confirm in [('x'*14,'x'*14), ('x'*129,'x'*129), (PASSWORD,'different')]:
            self.assertEqual(self.client.post('/register', username='valid', password=password, confirm=confirm)[0], 400)
        for index, password in enumerate(['x'*15, 'x'*128, '  meaningful passphrase  ', '🔒'*15]):
            self.assertEqual(self.client.register(f'valid{index}', password)[0], 303)
        stored = self.rows('SELECT password_value FROM users WHERE username=?', ('valid2',))[0][0]
        self.assertTrue(verify_password('  meaningful passphrase  ', stored))
        self.assertFalse(verify_password('meaningful passphrase', stored))

    def test_same_password_different_salts_and_verification(self):
        a, b = hash_password(PASSWORD), hash_password(PASSWORD)
        self.assertNotEqual(a.split('$')[1], b.split('$')[1])
        self.assertNotEqual(a.split('$')[2], b.split('$')[2])
        self.assertEqual(len(bytes.fromhex(a.split('$')[1])), 16)
        self.assertEqual(len(bytes.fromhex(a.split('$')[2])), 32)
        self.assertTrue(verify_password(PASSWORD, a))
        self.assertFalse(verify_password(NEW, a))

    def test_login_dashboard_session_rotation_and_cookies(self):
        self.client.register()
        old = self.client.cookie
        result = self.client.login('STUDENT1')
        self.assertEqual(result[0], 303)
        self.assertEqual(result[1]['Location'], '/dashboard')
        self.assertNotEqual(old, self.client.cookie)
        self.assertIn('HttpOnly', result[1]['Set-Cookie'])
        self.assertIn('SameSite=Strict', result[1]['Set-Cookie'])
        self.assertEqual(self.rows('SELECT * FROM sessions WHERE token_hash=?', (token_hash(old.split('=',1)[1]),)), [])
        status, headers, text = self.client.request('/dashboard')
        self.assertEqual(status, 200)
        for required in ['Welcome, student1', 'PASSWORD STORAGE INSPECTOR', 'CHANGE PASSWORD', 'RECENT ACCOUNT ACTIVITY', 'SHA-256']:
            self.assertIn(required, text)
        self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])
        self.assertEqual(headers['Referrer-Policy'], 'same-origin')
        raw = self.client.cookie.split('=',1)[1]
        self.assertNotIn(raw, str([tuple(r) for r in self.rows('SELECT * FROM sessions')]))

    def test_unauthenticated_and_expired_session(self):
        self.assertEqual(self.client.request('/dashboard')[1]['Location'], '/login')
        self.signed_in()
        self.now += 1801
        self.assertEqual(self.client.request('/dashboard')[1]['Location'], '/login')
        self.assertEqual(self.client.post('/logout')[0], 403)

    def test_csrf_every_state_change(self):
        self.signed_in()
        for path in ['/register', '/login', '/change-password', '/logout']:
            for csrf in ['', 'invalid', 'é']:
                self.assertEqual(self.client.request(path, {'csrf':csrf})[0], 403)
        other = Client(self.server)
        other.request('/register')
        self.assertEqual(self.client.request('/logout', {'csrf':other.csrf})[0], 403)
        self.assertEqual(self.client.request('/dashboard')[0], 200)

    def test_generic_errors_and_dummy_verification(self):
        self.client.register()
        for name in ['student1', 'unknown']:
            with patch('app.verify_password', wraps=verify_password) as verify:
                result = self.client.login(name, 'incorrect password')
                self.assertEqual(result[0], 401)
                self.assertIn('Invalid username or password', result[2])
                verify.assert_called_once()
        self.assertIn('Failed login', str([tuple(r) for r in self.rows('SELECT * FROM activity')]))

    def test_account_throttle_and_cooldown(self):
        self.client.register()
        for _ in range(5):
            self.assertEqual(self.client.login('STUDENT1', NEW)[0], 401)
        result = self.client.login()
        self.assertEqual(result[0], 429)
        self.assertIn('Retry-After', result[1])
        self.now += 301
        self.assertEqual(self.client.login()[0], 303)

    def test_ip_limit_independent_accounts(self):
        self.client.request('/login')
        # Populate only the first 30 timestamps to test the boundary without
        # 30 unrelated SHA-256 computations. Account limits tested over real HTTP.
        with database.connect(self.path) as db:
            db.executemany('INSERT INTO attempts VALUES (?,?)', [('login:ip:127.0.0.1', self.now)]*30)
        self.assertEqual(self.client.login('fresh_unknown')[0], 429)
        self.now += 301
        self.assertEqual(self.client.login('fresh_unknown')[0], 401)

    def test_password_change_rejects_invalid_values(self):
        self.signed_in()
        cases = [(NEW,NEW,NEW), (PASSWORD,'short','short'), (PASSWORD,NEW,'mismatch'), (PASSWORD,PASSWORD,PASSWORD)]
        for current, new, confirm in cases:
            self.assertEqual(self.client.post('/change-password', current=current, new=new, confirm=confirm)[0], 400)
        self.assertTrue(verify_password(PASSWORD, self.rows('SELECT password_value FROM users')[0][0]))

    def test_change_revokes_all_sessions_and_replaces_salt(self):
        self.signed_in()
        second = Client(self.server)
        self.assertEqual(second.login()[0], 303)
        second.request('/dashboard')
        old_cookie = self.client.cookie
        old_value = self.rows('SELECT password_value FROM users')[0][0]
        self.assertEqual(self.client.post('/change-password', current=PASSWORD, new=NEW, confirm=NEW)[0], 303)
        self.assertEqual(self.rows('SELECT * FROM sessions WHERE user_id IS NOT NULL'), [])
        self.assertEqual(second.request('/dashboard')[1]['Location'], '/login')
        replay = Client(self.server)
        replay.cookie = old_cookie
        self.assertEqual(replay.request('/dashboard')[1]['Location'], '/login')
        new_value = self.rows('SELECT password_value FROM users')[0][0]
        self.assertNotEqual(old_value.split('$')[1], new_value.split('$')[1])
        self.assertEqual(self.client.login(password=PASSWORD)[0], 401)
        self.assertEqual(self.client.login(password=NEW)[0], 303)

    def test_change_verification_throttle(self):
        self.signed_in()
        for _ in range(5):
            self.assertEqual(self.client.post('/change-password', current=NEW, new=NEW, confirm=NEW)[0], 400)
        self.assertEqual(self.client.post('/change-password', current=PASSWORD, new=NEW, confirm=NEW)[0], 429)

    def test_logout_invalidation_and_activity(self):
        self.signed_in()
        old = self.client.cookie
        self.assertEqual(self.client.post('/logout')[0], 303)
        self.client.cookie = old
        self.assertEqual(self.client.request('/dashboard')[1]['Location'], '/login')
        self.assertEqual(self.rows('SELECT event FROM activity ORDER BY id DESC')[0][0], 'Logout')

    def test_account_isolation_no_public_database(self):
        self.signed_in()
        other = Client(self.server)
        other.register('student2')
        other.login('student2')
        other.request('/dashboard')
        other.post('/change-password', current=PASSWORD, new=NEW, confirm=NEW)
        other_hash = self.rows('SELECT password_value FROM users WHERE username=?', ('student2',))[0][0]
        text = self.client.request('/dashboard?user_id=2')[2]
        self.assertNotIn(other_hash.split('$')[2], text)
        self.assertNotIn('Password changed', text)
        self.assertNotIn('student2', text)
        for path in ['/database', '/data/securepassword.sqlite3', '/static/../app.py']:
            self.assertEqual(self.client.request(path)[0], 404)

    def test_no_plaintext_in_records_or_database(self):
        self.signed_in()
        self.client.post('/change-password', current=PASSWORD, new=NEW, confirm=NEW)
        data = self.path.read_bytes()
        self.assertNotIn(PASSWORD.encode(), data)
        self.assertNotIn(NEW.encode(), data)
        for table in ['users','activity','sessions','attempts']:
            records = str([tuple(r) for r in self.rows('SELECT * FROM '+table)])
            self.assertNotIn(PASSWORD, records)
            self.assertNotIn(NEW, records)

    def test_host_origin_body_and_https_headers(self):
        self.client.request('/register')
        self.assertEqual(self.client.request('/', headers={'Host':'evil.test'})[0], 400)
        self.assertEqual(self.client.request('/register', {'csrf':self.client.csrf}, {'Origin':'https://evil.test'})[0], 403)
        self.assertEqual(self.client.request('/register', {'csrf':self.client.csrf}, {'Origin':'null'})[0], 403)
        self.assertEqual(self.client.request('/', headers={'Sec-Fetch-Site':'cross-site'})[0], 403)
        self.assertEqual(self.client.request('/register', {'x':'a'*9000})[0], 400)
        self.server.https = True
        fresh = Client(self.server)
        response = fresh.request('/login')
        self.assertIn('; Secure', response[1]['Set-Cookie'])
        self.assertIn('Strict-Transport-Security', response[1])
        # Header policy only; TLS handshake is not exercised in this test.


if __name__ == '__main__':
    unittest.main(verbosity=2)
