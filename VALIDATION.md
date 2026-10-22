# Validation results — 21 October 2026

## Completed

- Python 3.14.2 on macOS.
- `SPS_IN_MEMORY_TESTS=1 python3 -W error::ResourceWarning -m unittest discover -s tests -v`: **17 tests passed in 7.253 seconds**, no resource warnings after fixing connection closure.
- `python3 -m compileall -q app.py security.py database.py tests`: passed.
- `node --check static/app.js`: passed.
- Source ZIP allowlist and archive integrity check: passed; no databases, cached bytecode, private keys, or temporary accounts packaged.

The in-memory test mode replaces only network transport with byte streams. Requests go through Python's actual HTTP request parser and the application's real request handlers. SQLite, sessions, CSRF, templates, and 600,000-iteration password hashing execute normally. Each test uses its own temporary database, deleted afterward. No demonstration accounts were created.

## Test coverage

| Test | Behaviors checked |
| --- | --- |
| Registration and duplicates | Valid creation; case-insensitive duplicate rejection |
| Invalid usernames and injection | Length, characters, Unicode username rejection; SQL-like input safe |
| Password validation | 14/129 rejected, 15/128 accepted; mismatched confirmation; whitespace preserved; Unicode accepted |
| Cryptographic verification | Independent salts and hashes for identical passwords; byte lengths; correct/incorrect verification |
| Login and dashboard | Correct redirect, usable dashboard sections, session rotation, hashed tokens, cookie and CSP policy |
| Unauthenticated/expired sessions | Protected dashboard redirects; expiry after 30 minutes; expired POST rejected |
| CSRF | Missing, invalid, Unicode, and other-session tokens rejected on all state-changing routes |
| Generic login failure | Same generic message; dummy derivation for unknown user; failed-login event |
| Account throttle | Five real failed verifications; sixth blocked, case-insensitive bucket, cooldown recovery |
| IP throttle | 30 existing attempt timestamps block a fresh account; cooldown recovery |
| Invalid password changes | Wrong current password, short new password, mismatch, reuse rejected |
| Valid password change | Fresh salt, every account session revoked, replay rejected, old password fails, new works |
| Change throttle | Five wrong current-password checks; sixth blocked |
| Logout | Session invalidated, replay rejected, Logout event persisted |
| Account isolation | Another user's hash and event not disclosed; user_id query ignored; database/source paths inaccessible |
| No plaintext records | Both old and new passwords absent from SQLite bytes and all application tables |
| Request/header policy | Host, Origin, cross-site metadata, oversized forms rejected; Secure and HSTS in HTTPS mode |

## Not completed / limitations

The initial normal socket integration run could not bind to localhost: `PermissionError: [Errno 1] Operation not permitted`. All 17 initial cases errored at server creation, before any assertions. They were not counted as passes. The later in-memory run passed all 17.

A direct `python3 app.py --db /tmp/securepassword-launch-check.sqlite3` launch was also attempted. It exited with the helpful “Cannot start server (Operation not permitted)” message. **No running server is claimed.** The demonstration database was not used for this check.

Live network operation, occupied-port handling against an actual listener, browser rendering, mobile visual layout, click-through browser flow, and a real TLS handshake could not be verified in this environment. HTTPS cookie/header policy was checked without a TLS handshake. Run the normal integration suite and classroom demonstration locally to complete these checks.

Ruff, mypy, and pyright were not installed, so dedicated lint/type checks were unavailable. Syntax checks are not presented as lint/type checks or proof of production security.

## Browser Origin correction

After a user screenshot showed “Untrusted Origin” following login, changed Referrer-Policy from no-referrer to same-origin. The former can make browser form POSTs carry an opaque Origin (null), which the server correctly rejects. Same-origin preserves same-origin referrer information without disclosing it cross-origin. Origin:null remains rejected, and CSRF verification remains mandatory. All 17 in-memory tests passed again, including added assertions for this policy and null-Origin rejection. Python syntax checks passed. A live browser retest is still pending a server restart.
