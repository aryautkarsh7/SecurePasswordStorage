# Secure Password Storage System

Alliance University · B.Tech CSE Semester 5 · Cryptography and Network Security

A standalone, standard-library Python authentication demonstration. It stores password verifiers, never recoverable passwords. This is not a password manager. No accounts are pre-created.

## Run on macOS

Requires Python 3.10+ with OpenSSL-backed `hashlib.pbkdf2_hmac` (tested interpreter: Python 3.14.2). No pip installation is needed.

```sh
cd /Users/aryautkarsh/SECUREPASSWORD/SecurePasswordStorage
python3 app.py
```

Open http://127.0.0.1:8000 in your browser. Click **Create an account**, register, then sign in. A successful login redirects to `/dashboard`, where the inspector, password change, activity, and logout are all visible. Suggested example: `student1` / `MyCollegeDemo@2026`. You must register this yourself; it is not a default credential.

Stop with Ctrl+C. If port 8000 is occupied:

```sh
python3 app.py --port 8001
```

Then open http://127.0.0.1:8001. Keep the same hostname throughout a session (localhost and 127.0.0.1 have separate cookies). After extracting the source ZIP elsewhere, change into its `SecurePasswordStorage` folder instead of using the absolute path above.

## Structure

- `app.py`: local HTTP server, HTML rendering, validation, CSRF, routes, sessions, throttling.
- `security.py`: password hashing and verification; token hashing and validation.
- `database.py`: SQLite schema and connections.
- `static/style.css`, `static/app.js`: responsive interface and accessible password visibility buttons.
- `tests/test_app.py`: isolated HTTP integration tests; optional in-memory transport.
- `DEMO_GUIDE.md`: classroom demonstration and viva preparation.
- `VALIDATION.md`: actual validation results and limitations.
- `data/securepassword.sqlite3`: automatically created at launch; not in the source ZIP.

HTML templates are small Python render functions, with all dynamic user values escaped by `html.escape`. This avoids a third-party template dependency. Static files are served only from an exact allowlist, never arbitrary filesystem paths.

## Security design

Passwords are 15–128 Python Unicode characters; whitespace is preserved. Usernames are ASCII letters, digits, and underscores, 3–30 characters; SQLite NOCASE uniqueness and lookups make them case-insensitive.

`pbkdf2_sha256$600000$salt_hex$hash_hex` is the complete encoded SQLite value. The salt is 16 random bytes from `secrets.token_bytes`; the derived key is 32 bytes. The identifier, iteration count, salt, and hash are all recoverable from this value. Password verification uses `hmac.compare_digest`. Different salts yield different verifiers even for identical passwords. Unknown usernames run the same expensive PBKDF2 calculation against a random dummy verifier.

Sessions use 32 random bytes from `secrets.token_urlsafe`. Only SHA-256 token hashes are persisted. Fast SHA-256 is appropriate for these high-entropy tokens; it is never used alone for passwords. Login deletes the previous session and creates a new token. Authenticated and anonymous form sessions expire absolutely 30 minutes after creation; activity does not extend them. Logout invalidates the current session. Password change revokes every authenticated session for that account, creates a fresh anonymous form session, and asks for sign-in again.

CSRF tokens are HMAC-SHA256 values bound to the current random session token and an ephemeral server-only random key. Every POST validates the session and CSRF token, including registration and login. Restarting the process invalidates old CSRF forms; reload to obtain a new one. No CSRF values are persisted. Exact Host checking restricts requests to localhost or 127.0.0.1 at the configured port. If Origin is present, it must exactly match that Host and scheme. Missing Origin is permitted for clients that omit it, but never bypasses CSRF. Cross-site Fetch Metadata is rejected. Forwarded headers are not trusted.

Login allows **five total verification attempts per account per rolling five minutes**, including successful logins. The sixth is rejected with HTTP 429 and Retry-After. Case variants share a bucket; unknown usernames are limited too. Additionally, 30 login attempts per client IP per five minutes are allowed. Password-change verification has independent limits of five per account and 30 per IP. Registration is limited to 30 submissions per IP per five minutes. Throttle buckets store a hash of the lowercased account input, not arbitrary submitted usernames. Rejected throttled requests do not extend the window. Limits persist across restarts in SQLite. All local browser windows share the loopback IP. Account lockouts can be abused to inconvenience a user; production systems need broader abuse controls.

Activity is scoped by authenticated user ID and records only fixed event names and UTC timestamps. No public database endpoint exists. Passwords, raw session tokens, and CSRF values are never written to logs or records. Passwords necessarily exist transiently in process memory while verifying; Python cannot guarantee secure memory erasure.

The database is created with owner-only permissions, within an owner-only directory when new. Database theft still permits offline guessing; iterations and long passphrases reduce that risk rather than eliminating it. Possession of local source/OS access is outside this demo's threat model.

## HTTP and HTTPS

Default HTTP is restricted to `127.0.0.1` for a local classroom demonstration. Cookies use HttpOnly, SameSite=Strict, Path=/, and a 30-minute Max-Age. Secure is intentionally omitted for this local HTTP mode. Do not expose this mode to a network.

Optional direct TLS mode uses your own trusted local certificate and private key:

```sh
python3 app.py --port 8443 --cert /absolute/path/cert.pem --key /absolute/path/key.pem
```

Open https://127.0.0.1:8443 (the certificate must cover that address). HTTPS mode adds Secure cookies and HSTS; minimum TLS is 1.2. Never package private keys. This implementation does not infer HTTPS from untrusted proxy headers. TLS handshake validation was not performed in the implementation environment; header policy is tested.

Security headers include a restrictive Content-Security-Policy, no-store, nosniff, frame denial, same-origin referrer policy, and disabled camera/microphone/geolocation permissions. No external assets or CDN calls are needed.

## Tests

Normal network integration suite (temporary databases, no demonstration DB changes):

```sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q app.py security.py database.py tests
```

Restricted environments that cannot bind a listening socket can exercise the exact HTTP parser and handlers using an in-memory transport:

```sh
SPS_IN_MEMORY_TESTS=1 python3 -m unittest discover -s tests -v
```

The latter verifies application behavior but is not a substitute for a live socket/browser test. Hashing uses the full 600,000 iterations in both modes. See VALIDATION.md for what actually ran.

## Scope and limitations

Python's `http.server` is used for a small local academic demonstration, not an internet deployment. The single-request server serializes verification and rate-limit updates; slow clients can block it until the 10-second socket timeout. It is not a high-throughput or multi-worker architecture. Request bodies are capped at 8192 bytes. The educational inspector exposes the signed-in user's hash deliberately and should be removed in production. There is no password recovery, email, MFA, breached-password service, or external identity provider. This is not a claim of production certification or complete protection from attack.

## Official references checked during implementation (21 October 2026)

- OWASP Password Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- OWASP CSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- Python hashlib / PBKDF2: https://docs.python.org/3/library/hashlib.html
- Python secrets: https://docs.python.org/3/library/secrets.html
- Python hmac / compare_digest: https://docs.python.org/3/library/hmac.html

OWASP generally prefers Argon2id for new systems. This assignment explicitly requires PBKDF2-HMAC-SHA256; its 600,000-iteration configuration follows OWASP's published PBKDF2 guidance. No claim of FIPS certification is made.
