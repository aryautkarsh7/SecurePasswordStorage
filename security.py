"""Small, explicit cryptographic helpers. Passwords are never normalized."""
import hashlib
import hmac
import re
import secrets

ALGORITHM = 'sha256'


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    derived = hashlib.sha256(salt + password.encode('utf-8')).digest()
    return f'{ALGORITHM}${salt.hex()}${derived.hex()}'


def verify_password(password: str, encoded: str) -> bool:
    algorithm, salt, expected = encoded.split('$')
    if algorithm != ALGORITHM:
        return False
    actual = hashlib.sha256(bytes.fromhex(salt) + password.encode('utf-8')).digest()
    return hmac.compare_digest(actual, bytes.fromhex(expected))


def token_hash(token: str) -> str:
    # SHA-256 is appropriate for random 256-bit tokens.
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def validate(username: str, password: str, confirmation: str) -> str:
    if not re.fullmatch(r'[A-Za-z0-9_]{3,30}', username):
        return 'Username must contain 3–30 letters, numbers, or underscores.'
    return validate_password(password, confirmation)


def validate_password(password: str, confirmation: str) -> str:
    if not 15 <= len(password) <= 128:
        return 'Password must contain 15–128 characters. Spaces are preserved.'
    if password != confirmation:
        return 'Password confirmation does not match.'
    return ''
