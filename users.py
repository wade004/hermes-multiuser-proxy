"""
Multi-user reverse proxy for Hermes WebUI.
Per-user credentials with auto profile binding.
"""
import json
import hashlib
import hmac
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Optional

# Default data directory
DATA_DIR = Path(os.environ.get(
    "PROXY_DATA_DIR",
    os.path.expanduser("~/.hermes/webui")
))
USERS_FILE = DATA_DIR / "proxy_users.json"
SESSIONS_FILE = DATA_DIR / "proxy_sessions.json"

# PBKDF2 settings
PBKDF2_ITERATIONS = 600_000

# Session TTL (seconds) — default 7 days
SESSION_TTL = int(os.environ.get("SESSION_TTL", 86400 * 7))

# Rate limiting
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW = 60  # seconds

_lock = threading.Lock()


# ── Password hashing ────────────────────────────────────────────────────────

def _get_salt() -> bytes:
    """Load or create a persistent PBKDF2 salt."""
    salt_file = DATA_DIR / ".proxy_salt"
    if salt_file.exists():
        return salt_file.read_bytes()[:32]
    salt = secrets.token_bytes(32)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    salt_file.write_bytes(salt)
    salt_file.chmod(0o600)
    return salt


_SALT = _get_salt()


def hash_password(password: str) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), _SALT, PBKDF2_ITERATIONS)
    return dk.hex()


def verify_password(password: str, password_hash: str) -> bool:
    return hmac.compare_digest(hash_password(password), password_hash)


# ── Users CRUD ──────────────────────────────────────────────────────────────

def _load_users() -> dict:
    try:
        if USERS_FILE.exists():
            data = json.loads(USERS_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def _save_users(users: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    USERS_FILE.write_text(json.dumps(users, indent=2, ensure_ascii=False), encoding="utf-8")
    USERS_FILE.chmod(0o600)


def create_user(username: str, password: str, profile: str, role: str = "user") -> bool:
    """Create a new user. Returns False if username already exists."""
    with _lock:
        users = _load_users()
        if username in users:
            return False
        users[username] = {
            "password_hash": hash_password(password),
            "profile": profile,
            "role": role,  # "admin" or "user"
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        _save_users(users)
    return True


def update_user(username: str, password: str = None, profile: str = None, role: str = None) -> bool:
    """Update an existing user. Only updates non-None fields."""
    with _lock:
        users = _load_users()
        if username not in users:
            return False
        if password is not None:
            users[username]["password_hash"] = hash_password(password)
        if profile is not None:
            users[username]["profile"] = profile
        if role is not None:
            users[username]["role"] = role
        _save_users(users)
    return True


def delete_user(username: str) -> bool:
    with _lock:
        users = _load_users()
        if username not in users:
            return False
        del users[username]
        _save_users(users)
    return True


def list_users() -> dict:
    """Return users dict (without password hashes)."""
    users = _load_users()
    return {
        u: {k: v for k, v in info.items() if k != "password_hash"}
        for u, info in users.items()
    }


def authenticate(username: str, password: str) -> Optional[dict]:
    """Verify credentials. Returns user info dict on success, None on failure."""
    users = _load_users()
    user = users.get(username)
    if not user:
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    return {
        "username": username,
        "profile": user["profile"],
        "role": user["role"],
    }


def get_user(username: str) -> Optional[dict]:
    """Get user info (without password hash)."""
    users = _load_users()
    user = users.get(username)
    if not user:
        return None
    return {
        "username": username,
        "profile": user["profile"],
        "role": user["role"],
    }


# ── Session management ──────────────────────────────────────────────────────

def _load_sessions() -> dict:
    try:
        if SESSIONS_FILE.exists():
            data = json.loads(SESSIONS_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                now = time.time()
                return {t: exp for t, exp in data.items()
                        if isinstance(exp, (int, float)) and exp > now}
    except Exception:
        pass
    return {}


def _save_sessions(sessions: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SESSIONS_FILE.write_text(json.dumps(sessions), encoding="utf-8")
    SESSIONS_FILE.chmod(0o600)


_sessions = _load_sessions()  # token -> {"expiry": float, "username": str}


def create_session(username: str) -> str:
    """Create a session token for the given user."""
    token = secrets.token_hex(32)
    with _lock:
        _sessions[token] = {
            "expiry": time.time() + SESSION_TTL,
            "username": username,
        }
        _save_sessions({t: s["expiry"] for t, s in _sessions.items()})
    return token


def verify_session(token: str) -> Optional[str]:
    """Verify a session token. Returns username if valid, None otherwise."""
    with _lock:
        session = _sessions.get(token)
        if not session:
            return None
        if time.time() > session["expiry"]:
            _sessions.pop(token, None)
            _save_sessions({t: s["expiry"] for t, s in _sessions.items()})
            return None
        return session["username"]


def invalidate_session(token: str) -> None:
    with _lock:
        _sessions.pop(token, None)
        _save_sessions({t: s["expiry"] for t, s in _sessions.items() })


# ── Rate limiting ───────────────────────────────────────────────────────────

_login_attempts = {}  # ip -> [timestamp, ...]
_attempts_lock = threading.Lock()


def check_rate_limit(ip: str) -> bool:
    """Return True if the IP is allowed to attempt login."""
    with _attempts_lock:
        now = time.time()
        attempts = _login_attempts.get(ip, [])
        attempts = [t for t in attempts if now - t < LOGIN_WINDOW]
        _login_attempts[ip] = attempts
        return len(attempts) < MAX_LOGIN_ATTEMPTS


def record_login_attempt(ip: str) -> None:
    with _attempts_lock:
        _login_attempts.setdefault(ip, []).append(time.time())


def clear_rate_limit(ip: str) -> None:
    with _attempts_lock:
        _login_attempts.pop(ip, None)
