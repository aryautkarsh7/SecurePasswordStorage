# Classroom demonstration and viva guide

## Explain the project in 30 seconds

“This authentication system demonstrates secure password storage. At registration, it generates a random salt and derives a 32-byte hash using PBKDF2-HMAC-SHA256 with 600,000 iterations. SQLite stores this verifier rather than the password. At login, the server repeats the derivation and compares the hashes. The dashboard shows my own stored record, account activity, and a secure password-change feature.”

## Demonstration steps

1. Run `python3 app.py` and open http://127.0.0.1:8000.
2. Choose Create an account. Try username `ab` or a password such as `short`. Explain the server's helpful rejection. Try mismatched confirmation too.
3. Register `student1` with `MyCollegeDemo@2026`. This is an example you create, not a built-in account.
4. Sign in with `STUDENT1` and the same password. Show that username matching is case-insensitive and that login opens the complete dashboard.
5. Show the creation date and the inspector: algorithm, 600,000 iterations, 16-byte salt, 32-byte hash, and complete encoded value. Hex uses two characters per byte, so the salt has 32 hex characters and hash has 64.
6. Explain that only your current record is visible. A production interface normally hides even this educational inspector.
7. Show the activity timeline: Account created and Successful login. Sign out, attempt a wrong password, then sign in correctly to show Failed login and Logout events.
8. Read the How it works section and explain why a password is verified, not decrypted.

## Identical password, different hashes

Use a second browser or private window. Register `student2` with the exact same password `MyCollegeDemo@2026`. Sign in. Compare the two dashboards side by side: salts and hashes differ even though the passwords match. Neither account can browse the other's record. Avoid using real personal passwords for this demonstration.

## Throttling

Use a dedicated demo account, or wait five minutes after earlier login attempts. Submit five wrong logins in a rolling five-minute window. The next submission shows a cooldown with remaining seconds, status 429, and Retry-After. A correct password is also blocked during the cooldown. Existing successful attempts count toward the five, so the block may occur sooner after an earlier sign-in. Waiting five minutes releases the limit; clicking repeatedly does not extend it. Changing username capitalization cannot evade it. The IP limit additionally restricts attempts across accounts (30 per five minutes).

## Password change and all-session revocation

1. Sign into the same `student1` account in both a regular and private browser window. Two tabs in one window generally share one session and do not prove multi-session revocation.
2. In the first dashboard, enter an incorrect current password; show the rejection. Try reusing the current password; show the rejection.
3. Enter current `MyCollegeDemo@2026`, new `MyNewCollegeDemo@2026`, and matching confirmation. Submit.
4. The first window returns to sign-in with a revocation message. Refresh the second window's dashboard; it also returns to sign-in.
5. Attempt the old password; it fails. Sign in with the new password; it succeeds (respect the rolling login limit).
6. Show the new salt and hash, plus Password changed in activity. The old verifier has been replaced.
7. Log out. Revisiting `/dashboard` requires sign-in.

For a smooth classroom presentation, perform the throttling demonstration last so it does not interrupt password-change verification. Password-change verification also has its own five-attempt account limit.

## Likely viva questions

**Why not store plaintext?** A database leak would immediately reveal users' passwords, including passwords reused elsewhere.

**Why hashing instead of encryption?** Authentication needs a comparison, not recovery. Encryption introduces a decryption key whose compromise reveals passwords.

**What is PBKDF2?** A password-based key derivation function that repeatedly applies a pseudorandom function, here HMAC-SHA256, to make each guess more expensive.

**Is plain SHA-256 secure enough for passwords?** No. It is fast, helping attackers test guesses quickly. We use PBKDF2 with a salt and a high iteration count.

**Is the salt secret?** No. It is stored with the hash. Its job is uniqueness and preventing reuse of precomputed guesses across accounts.

**Why 16 salt bytes and 32 hash bytes?** The salt has 128 random bits; the derived result has 256 bits. These are the project's chosen parameters, not the password's length.

**Why compare_digest?** It avoids ordinary early-exit equality behavior during hash comparison, reducing timing leakage. It does not make the whole web request perfectly constant-time.

**How does the system verify an unknown username?** It performs a dummy PBKDF2 calculation and returns the same generic invalid-credentials message.

**What is a session?** A temporary authenticated state represented by a random cookie token. The server stores only the token's hash and an expiry time.

**Why can sessions use plain SHA-256?** Session tokens have 256 random bits and are not human-chosen passwords. Fast token hashing does not enable practical guessing of these high-entropy secrets.

**What is CSRF?** A malicious site tries to make the browser perform an action using the victim's cookies. This app requires a session-bound token on every POST, checks Origin when present, and uses SameSite cookies.

**What prevents SQL injection?** SQL parameters bind inputs as data rather than concatenating them into statements. Username validation is additional protection, not the only defense.

**What happens after password change?** A new random salt and verifier replace the old value, all account sessions are revoked, and the user must sign in again.

**Does salting prevent all password cracking?** No. A stolen verifier still allows offline guesses; long passphrases and expensive derivation improve resistance.

**Is this production-ready?** It is a local academic demonstration using Python's basic HTTP server. Internet deployment needs a production server, operational controls, TLS deployment, and a broader security review. The inspector would be removed.

**What did automated tests verify?** Read VALIDATION.md and describe only the checks recorded there. Do not claim a browser test passed unless it was actually performed.
