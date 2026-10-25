"""Password-based authentication with hardened PBKDF2, opaque revocable sessions."""
import hashlib
import hmac
import secrets
import sqlite3
from datetime import timedelta
from database import connect, utcnow

ITERATIONS = 600_000
SESSION_DAYS = 7
COOKIE = 'codeniti_session'


def password_hash(password: str) -> str:
    salt = secrets.token_bytes(24)
    derived = hashlib.pbkdf2_hmac('sha256',password.encode('utf-8'),salt,ITERATIONS)
    return f'pbkdf2_sha256${ITERATIONS}${salt.hex()}${derived.hex()}'


def check_password(password: str, stored: str) -> bool:
    try:
        algorithm, rounds, salt, digest = stored.split('$')
        if algorithm != 'pbkdf2_sha256' or not 100_000 <= int(rounds) <= 1_000_000:
            return False
        computed = hashlib.pbkdf2_hmac('sha256',password.encode('utf-8'),bytes.fromhex(salt),int(rounds))
        return hmac.compare_digest(computed,bytes.fromhex(digest))
    except (ValueError, TypeError):
        return False

# Pre-computed dummy hash used to perform constant-time work for missing accounts (timing defence).
# Generated once at first use, not at import time, to avoid blocking startup and test collection.
_DUMMY_HASH: str | None = None

def _get_dummy_hash() -> str:
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = password_hash('different dummy account password')
    return _DUMMY_HASH


def create_user(name: str, email: str, password: str) -> int | None:
    try:
        with connect() as db:
            row = db.execute('INSERT INTO users(display_name,email,password_hash,created_at) VALUES (?,?,?,?)',
                             (name.strip(),email.lower().strip(),password_hash(password),utcnow().isoformat()))
            return row.lastrowid
    except sqlite3.IntegrityError:
        return None


def authenticate(email: str,password: str) -> dict | None:
    with connect() as db:
        row = db.execute('SELECT id,display_name,email,password_hash FROM users WHERE email=?',(email.lower().strip(),)).fetchone()
    if not check_password(password,row['password_hash'] if row else _get_dummy_hash()):
        return None
    return {k:row[k] for k in ('id','display_name','email')} if row else None


def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(36)
    hashed = hashlib.sha256(token.encode()).hexdigest()
    with connect() as db:
        db.execute('INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES (?,?,?,?)',
                   (hashed,user_id,(utcnow()+timedelta(days=SESSION_DAYS)).isoformat(),utcnow().isoformat()))
        db.execute('DELETE FROM sessions WHERE expires_at<?',(utcnow().isoformat(),))
    return token


def session_user(token: str) -> dict | None:
    if not token or len(token)>128:
        return None
    hashed = hashlib.sha256(token.encode()).hexdigest()
    with connect() as db:
        row = db.execute('''SELECT users.id,users.display_name,users.email FROM sessions
                            JOIN users ON users.id=sessions.user_id
                            WHERE sessions.token_hash=? AND sessions.expires_at>?''',
                         (hashed,utcnow().isoformat())).fetchone()
    return dict(row) if row else None


def revoke_session(token: str):
    if token:
        with connect() as db:
            db.execute('DELETE FROM sessions WHERE token_hash=?',(hashlib.sha256(token.encode()).hexdigest(),))
