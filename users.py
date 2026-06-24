"""
Multi-user reverse proxy for Hermes WebUI.
Per-user credentials with auto profile binding.
"""
import subprocess
import logging
import json
import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

# Default data directory
DATA_DIR = Path(os.environ.get(
    "PROXY_DATA_DIR",
    os.path.expanduser("~/.hermes/webui")
))

logger = logging.getLogger("users")

# Legacy JSON files (migrated to SQLite on first run)
USERS_FILE = DATA_DIR / "proxy_users.json"
SESSIONS_FILE = DATA_DIR / "proxy_sessions.json"
LOGIN_LOG_FILE = DATA_DIR / "proxy_login_log.json"
REQUEST_LOG_FILE = DATA_DIR / "proxy_request_log.json"

# Unified SQLite database
DB_FILE = DATA_DIR / "proxy.db"
# Keep old name alive for any external references
REQUEST_DB_FILE = DB_FILE
# Legacy standalone request DB (from v1 migration), merged into proxy.db then removed
OLD_REQUEST_DB_FILE = DATA_DIR / "proxy_requests.db"

# ── SQLite init ──────────────────────────────────────────────────────────────
_db_lock = threading.Lock()
_req_db_lock = _db_lock
_login_log_lock = _db_lock

_DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    profile TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    expiry REAL NOT NULL,
    username TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS login_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT NOT NULL,
    username TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT
);

CREATE TABLE IF NOT EXISTS request_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT NOT NULL,
    date TEXT NOT NULL,
    username TEXT NOT NULL,
    message TEXT,
    session_id TEXT,
    model TEXT,
    input_tokens INTEGER DEFAULT 0,
    output_tokens INTEGER DEFAULT 0,
    cache_read_tokens INTEGER DEFAULT 0,
    cache_write_tokens INTEGER DEFAULT 0,
    reasoning_tokens INTEGER DEFAULT 0
);
"""


def _init_db() -> None:
    """Create the SQLite database and migrate legacy JSON data if present."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_FILE))
    try:
        conn.executescript(_DB_SCHEMA)
        conn.commit()

        # ── Migrate users ──
        row = conn.execute("SELECT COUNT(*) FROM users").fetchone()
        if row[0] == 0 and USERS_FILE.exists():
            try:
                data = json.loads(USERS_FILE.read_text(encoding="utf-8"))
                if isinstance(data, dict) and data:
                    for username, info in data.items():
                        conn.execute(
                            "INSERT OR IGNORE INTO users (username, password_hash, profile, role, created_at) VALUES (?, ?, ?, ?, ?)",
                            (
                                username,
                                info.get("password_hash", ""),
                                info.get("profile", username),
                                info.get("role", "user"),
                                info.get("created_at", ""),
                            ),
                        )
                    conn.commit()
                    logger.info("Migrated %d users from %s", len(data), USERS_FILE.name)
                    USERS_FILE.rename(USERS_FILE.with_suffix(".json.bak"))
            except Exception as e:
                logger.warning("Users JSON→SQLite migration failed: %s", e)

        # ── Migrate sessions ──
        row = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()
        if row[0] == 0 and SESSIONS_FILE.exists():
            try:
                data = json.loads(SESSIONS_FILE.read_text(encoding="utf-8"))
                if isinstance(data, dict) and data:
                    now = time.time()
                    for token, val in data.items():
                        if isinstance(val, dict) and "expiry" in val and "username" in val:
                            if val["expiry"] > now:
                                conn.execute(
                                    "INSERT OR IGNORE INTO sessions (token, expiry, username) VALUES (?, ?, ?)",
                                    (token, val["expiry"], val["username"]),
                                )
                    conn.commit()
                    logger.info("Migrated sessions from %s", SESSIONS_FILE.name)
                    SESSIONS_FILE.rename(SESSIONS_FILE.with_suffix(".json.bak"))
            except Exception as e:
                logger.warning("Sessions JSON→SQLite migration failed: %s", e)

        # ── Migrate login log ──
        row = conn.execute("SELECT COUNT(*) FROM login_log").fetchone()
        if row[0] == 0 and LOGIN_LOG_FILE.exists():
            try:
                legacy = json.loads(LOGIN_LOG_FILE.read_text(encoding="utf-8"))
                if isinstance(legacy, list) and legacy:
                    conn.executemany(
                        "INSERT INTO login_log (time, username, ip, user_agent) VALUES (?, ?, ?, ?)",
                        [
                            (
                                e.get("time", ""),
                                e.get("username", ""),
                                e.get("ip", ""),
                                e.get("user_agent", ""),
                            )
                            for e in legacy
                        ],
                    )
                    conn.commit()
                    logger.info("Migrated %d login log entries from %s", len(legacy), LOGIN_LOG_FILE.name)
                    LOGIN_LOG_FILE.rename(LOGIN_LOG_FILE.with_suffix(".json.bak"))
            except Exception as e:
                logger.warning("Login log JSON→SQLite migration failed: %s", e)

        # ── Migrate request log ──
        row = conn.execute("SELECT COUNT(*) FROM request_log").fetchone()
        if row[0] == 0 and REQUEST_LOG_FILE.exists():
            try:
                legacy = json.loads(REQUEST_LOG_FILE.read_text(encoding="utf-8"))
                if isinstance(legacy, list) and legacy:
                    conn.executemany(
                        """INSERT INTO request_log
                           (time, date, username, message, session_id, model,
                            input_tokens, output_tokens, cache_read_tokens,
                            cache_write_tokens, reasoning_tokens)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        [
                            (
                                e.get("time", ""),
                                e.get("date", e.get("time", "")[:10]),
                                e.get("username", "unknown"),
                                e.get("message", ""),
                                e.get("session_id", ""),
                                e.get("model", ""),
                                int(e.get("input_tokens", 0)),
                                int(e.get("output_tokens", 0)),
                                int(e.get("cache_read_tokens", 0)),
                                int(e.get("cache_write_tokens", 0)),
                                int(e.get("reasoning_tokens", 0)),
                            )
                            for e in legacy
                        ],
                    )
                    conn.commit()
                    logger.info("Migrated %d request log entries from %s", len(legacy), REQUEST_LOG_FILE.name)
                    REQUEST_LOG_FILE.rename(REQUEST_LOG_FILE.with_suffix(".json.bak"))
            except Exception as e:
                logger.warning("Request log JSON→SQLite migration failed: %s", e)

        # ── Migrate from legacy standalone proxy_requests.db ──
        if OLD_REQUEST_DB_FILE.exists() and OLD_REQUEST_DB_FILE != DB_FILE:
            try:
                old_conn = sqlite3.connect(str(OLD_REQUEST_DB_FILE))
                old_conn.row_factory = sqlite3.Row
                old_rows = old_conn.execute(
                    """SELECT time, date, username, message, session_id, model,
                              input_tokens, output_tokens, cache_read_tokens,
                              cache_write_tokens, reasoning_tokens FROM request_log"""
                ).fetchall()
                if old_rows:
                    conn.executemany(
                        """INSERT INTO request_log
                           (time, date, username, message, session_id, model,
                            input_tokens, output_tokens, cache_read_tokens,
                            cache_write_tokens, reasoning_tokens)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        [tuple(r) for r in old_rows],
                    )
                    conn.commit()
                    logger.info("Merged %d entries from legacy %s", len(old_rows), OLD_REQUEST_DB_FILE.name)
                old_conn.close()
                OLD_REQUEST_DB_FILE.rename(OLD_REQUEST_DB_FILE.with_suffix(".db.bak"))
            except Exception as e:
                logger.warning("Legacy DB merge failed: %s", e)

    finally:
        conn.close()
    DB_FILE.chmod(0o600)


_init_db()


# PBKDF2 settings
PBKDF2_ITERATIONS = 600_000

# Session TTL (seconds) — default 7 days
SESSION_TTL = int(os.environ.get("SESSION_TTL", 86400 * 7))

# Rate limiting
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW = 60  # seconds

_lock = threading.Lock()
_attempts_lock = threading.Lock()


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


# ── Users CRUD (SQLite) ─────────────────────────────────────────────────────

_HERMES_BIN = os.path.expanduser("~/.local/bin/hermes")


def _ensure_hermes_profile(profile: str) -> bool:
    """Create Hermes profile if it doesn't exist. Returns True on success."""
    try:
        # Check if profile already exists
        result = subprocess.run(
            [_HERMES_BIN, "profile", "list"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            # Parse text output: profile names are first column
            lines = result.stdout.strip().split("\n")
            for line in lines[1:]:  # skip header
                parts = line.split()
                if parts and parts[0].lstrip("◆●") == profile:
                    logger.info(f"Profile '{profile}' already exists")
                    return True

        # Create the profile
        result = subprocess.run(
            [_HERMES_BIN, "profile", "create", profile],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            logger.info(f"Created Hermes profile: {profile}")
            return True
        else:
            logger.error(f"Failed to create profile '{profile}': {result.stderr}")
            return False
    except Exception as e:
        logger.error(f"Error creating profile '{profile}': {e}")
        return False


def _clear_profile_sessions(profile_name: str) -> None:
    """Clear all sessions and messages from a profile's state.db.

    Called after cloning a profile to prevent the new user from seeing
    the source profile's chat history.
    """
    hermes_home = Path(os.path.expanduser("~/.hermes"))
    db_path = hermes_home / "profiles" / profile_name / "state.db"
    if not db_path.exists():
        return  # no db = nothing to clear
    try:
        conn = sqlite3.connect(str(db_path))
        cur = conn.cursor()
        for table in [
            "messages", "sessions",
            "messages_fts", "messages_fts_data", "messages_fts_idx",
            "messages_fts_content", "messages_fts_docsize",
            "messages_fts_trigram", "messages_fts_trigram_data",
            "messages_fts_trigram_idx", "messages_fts_trigram_content",
            "messages_fts_trigram_docsize",
        ]:
            try:
                cur.execute(f"DELETE FROM [{table}]")
            except Exception:
                pass
        conn.commit()
        conn.close()
        logger.info("Cleared inherited sessions for profile '%s'", profile_name)
    except Exception as e:
        logger.warning("Failed to clear sessions for profile '%s': %e", profile_name, e)


def create_user(username: str, password: str, profile: str, role: str = "user") -> bool:
    """Create a new user. Returns False if username already exists."""
    # Ensure Hermes profile exists
    if not _ensure_hermes_profile(profile):
        return False
    with _lock:
        conn = sqlite3.connect(str(DB_FILE))
        try:
            existing = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
            if existing:
                return False
            conn.execute(
                "INSERT INTO users (username, password_hash, profile, role, created_at) VALUES (?, ?, ?, ?, ?)",
                (username, hash_password(password), profile, role, time.strftime("%Y-%m-%d %H:%M:%S")),
            )
            conn.commit()
        except Exception as e:
            logger.warning("Failed to create user: %s", e)
            return False
        finally:
            conn.close()
    # Clear inherited sessions from cloned profile
    _clear_profile_sessions(profile)
    return True


def update_user(username: str, password: str = None, profile: str = None, role: str = None) -> bool:
    """Update an existing user. Only updates non-None fields."""
    with _lock:
        conn = sqlite3.connect(str(DB_FILE))
        try:
            row = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
            if not row:
                return False
            if password is not None:
                conn.execute("UPDATE users SET password_hash = ? WHERE username = ?",
                             (hash_password(password), username))
            if profile is not None:
                conn.execute("UPDATE users SET profile = ? WHERE username = ?", (profile, username))
            if role is not None:
                conn.execute("UPDATE users SET role = ? WHERE username = ?", (role, username))
            conn.commit()
        except Exception as e:
            logger.warning("Failed to update user: %s", e)
            return False
        finally:
            conn.close()
    return True


def delete_user(username: str) -> bool:
    with _lock:
        conn = sqlite3.connect(str(DB_FILE))
        try:
            row = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
            if not row:
                return False
            conn.execute("DELETE FROM users WHERE username = ?", (username,))
            conn.commit()
        except Exception as e:
            logger.warning("Failed to delete user: %s", e)
            return False
        finally:
            conn.close()
    return True


def list_users() -> dict:
    """Return users dict (without password hashes)."""
    conn = sqlite3.connect(str(DB_FILE))
    try:
        rows = conn.execute("SELECT username, profile, role, created_at FROM users").fetchall()
    except Exception:
        rows = []
    finally:
        conn.close()
    return {
        row[0]: {"profile": row[1], "role": row[2], "created_at": row[3]}
        for row in rows
    }


def authenticate(username: str, password: str) -> Optional[dict]:
    """Verify credentials. Returns user info dict on success, None on failure."""
    conn = sqlite3.connect(str(DB_FILE))
    try:
        row = conn.execute(
            "SELECT username, password_hash, profile, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    except Exception:
        return None
    finally:
        conn.close()
    if not row:
        return None
    if not verify_password(password, row[1]):
        return None
    return {"username": row[0], "profile": row[2], "role": row[3]}


def get_user(username: str) -> Optional[dict]:
    """Get user info (without password hash)."""
    conn = sqlite3.connect(str(DB_FILE))
    try:
        row = conn.execute(
            "SELECT username, profile, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    except Exception:
        return None
    finally:
        conn.close()
    if not row:
        return None
    return {"username": row[0], "profile": row[1], "role": row[2]}


# ── Session management (SQLite) ─────────────────────────────────────────────

def create_session(username: str) -> str:
    """Create a session token for the given user."""
    token = secrets.token_hex(32)
    with _lock:
        conn = sqlite3.connect(str(DB_FILE))
        try:
            conn.execute(
                "INSERT INTO sessions (token, expiry, username) VALUES (?, ?, ?)",
                (token, time.time() + SESSION_TTL, username),
            )
            conn.commit()
        finally:
            conn.close()
    return token


def verify_session(token: str) -> Optional[str]:
    """Verify a session token. Returns username if valid, None otherwise."""
    with _lock:
        conn = sqlite3.connect(str(DB_FILE))
        try:
            row = conn.execute(
                "SELECT expiry, username FROM sessions WHERE token = ?",
                (token,),
            ).fetchone()
            if not row:
                return None
            if time.time() > row[0]:
                conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
                conn.commit()
                return None
            return row[1]
        finally:
            conn.close()


def invalidate_session(token: str) -> None:
    with _lock:
        conn = sqlite3.connect(str(DB_FILE))
        try:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()
        finally:
            conn.close()


# ── Rate limiting ───────────────────────────────────────────────────────────

_login_attempts = {}  # ip -> [timestamp, ...]


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


# ── Login audit log (SQLite) ────────────────────────────────────────────────

def record_login(username: str, ip: str, user_agent: str = "") -> None:
    """Record a successful login event to the audit log."""
    with _db_lock:
        conn = sqlite3.connect(str(DB_FILE))
        try:
            conn.execute(
                "INSERT INTO login_log (time, username, ip, user_agent) VALUES (?, ?, ?, ?)",
                (time.strftime("%Y-%m-%d %H:%M:%S"), username, ip, user_agent),
            )
            # Retain login log entries from the last 30 days
            cutoff = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
            conn.execute(
                "DELETE FROM login_log WHERE time < ?",
                (cutoff,),
            )
            conn.commit()
        except Exception as e:
            logger.warning("Failed to write login log: %s", e)
        finally:
            conn.close()


def get_login_log(limit: int = 50, offset: int = 0) -> dict:
    """Return login log entries with pagination info."""
    try:
        conn = sqlite3.connect(str(DB_FILE))
        conn.row_factory = sqlite3.Row
        total = conn.execute("SELECT COUNT(*) FROM login_log").fetchone()[0]
        rows = conn.execute(
            "SELECT time, username, ip, user_agent FROM login_log ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        conn.close()
        # Reverse so oldest is first (matches old JSON behaviour)
        entries = [{"time": r[0], "username": r[1], "ip": r[2], "user_agent": r[3]}
                   for r in reversed(rows)]
        return {"total": total, "log": entries}
    except Exception:
        return {"total": 0, "log": []}


# ── Request log (SQLite) ───────────────────────────────────────────────────

_REQ_DB_COLS = [
    "time", "date", "username", "message", "session_id", "model",
    "input_tokens", "output_tokens", "cache_read_tokens",
    "cache_write_tokens", "reasoning_tokens",
]


def _row_to_dict(row) -> dict:
    """Convert a DB row (tuple or Row) to the dict format expected by the admin panel."""
    if isinstance(row, sqlite3.Row):
        return {col: row[col] for col in _REQ_DB_COLS}
    return dict(zip(_REQ_DB_COLS, row))


def record_request(username: str, message: str, session_id: str = "",
                   input_tokens: int = 0, output_tokens: int = 0,
                   cache_read_tokens: int = 0, cache_write_tokens: int = 0,
                   reasoning_tokens: int = 0, model: str = "") -> None:
    """Record a chat request to the SQLite request log."""
    msg = (message[:200] + "...") if len(message) > 200 else message
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    today = time.strftime("%Y-%m-%d")
    with _req_db_lock:
        conn = sqlite3.connect(str(DB_FILE))
        try:
            conn.execute(
                """INSERT INTO request_log
                   (time, date, username, message, session_id, model,
                    input_tokens, output_tokens, cache_read_tokens,
                    cache_write_tokens, reasoning_tokens)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (now, today, username, msg, session_id, model,
                 input_tokens, output_tokens, cache_read_tokens,
                 cache_write_tokens, reasoning_tokens),
            )
            # Retain request log entries from the last 14 days
            cutoff = (datetime.now() - timedelta(days=14)).strftime("%Y-%m-%d %H:%M:%S")
            conn.execute(
                "DELETE FROM request_log WHERE time < ?",
                (cutoff,),
            )
            conn.commit()
        except Exception as e:
            logger.warning("Failed to write request log: %s", e)
        finally:
            conn.close()


def update_request_tokens(session_id: str, input_tokens: int, output_tokens: int,
                           cache_read_tokens: int = 0, cache_write_tokens: int = 0,
                           reasoning_tokens: int = 0, model: str = "") -> None:
    """Update token usage for the most recent request with the given session_id."""
    with _req_db_lock:
        conn = sqlite3.connect(str(DB_FILE))
        try:
            row = conn.execute(
                """SELECT id FROM request_log
                   WHERE session_id = ? AND input_tokens = 0
                   ORDER BY id DESC LIMIT 1""",
                (session_id,),
            ).fetchone()
            if row:
                conn.execute(
                    """UPDATE request_log SET
                       input_tokens = ?, output_tokens = ?,
                       cache_read_tokens = ?, cache_write_tokens = ?,
                       reasoning_tokens = ?, model = ?
                       WHERE id = ?""",
                    (input_tokens, output_tokens,
                     cache_read_tokens, cache_write_tokens,
                     reasoning_tokens, model if model else "",
                     row[0]),
                )
                conn.commit()
        except Exception as e:
            logger.warning("Failed to update request tokens: %s", e)
        finally:
            conn.close()


def get_request_log(limit: int = 50, offset: int = 0) -> dict:
    """Return request log entries with pagination info."""
    try:
        conn = sqlite3.connect(str(DB_FILE))
        conn.row_factory = sqlite3.Row
        total = conn.execute("SELECT COUNT(*) FROM request_log").fetchone()[0]
        rows = conn.execute(
            "SELECT * FROM request_log ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        conn.close()
        # Reverse so oldest is first, matching the old JSON behaviour
        entries = [_row_to_dict(r) for r in reversed(rows)]
        return {"total": total, "log": entries}
    except Exception:
        return {"total": 0, "log": []}


def get_request_stats(month: str = "") -> dict:
    """Return per-user daily token statistics including cache info."""
    if not month:
        month = time.strftime("%Y-%m")

    empty = {"month": month, "days": [], "users": {}, "ranking": []}
    try:
        conn = sqlite3.connect(str(DB_FILE))
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM request_log WHERE date LIKE ?",
            (f"{month}%",),
        ).fetchall()
        conn.close()
    except Exception:
        return empty

    users_data = {}
    days_set = set()

    for row in rows:
        date = row["date"]
        day = date[8:10]
        username = row["username"]
        inp = int(row["input_tokens"])
        out = int(row["output_tokens"])
        cache_read = int(row["cache_read_tokens"])
        cache_write = int(row["cache_write_tokens"])
        reasoning = int(row["reasoning_tokens"])
        model = row["model"] or ""

        days_set.add(day)

        if username not in users_data:
            users_data[username] = {
                "daily": {}, "total_input": 0, "total_output": 0,
                "total_cache_read": 0, "total_cache_write": 0,
                "total_reasoning": 0, "total_requests": 0,
            }

        ud = users_data[username]
        if day not in ud["daily"]:
            ud["daily"][day] = {
                "input": 0, "output": 0, "cache_read": 0, "cache_write": 0,
                "reasoning": 0, "requests": 0, "models": {},
            }

        dd = ud["daily"][day]
        dd["input"] += inp
        dd["output"] += out
        dd["cache_read"] += cache_read
        dd["cache_write"] += cache_write
        dd["reasoning"] += reasoning
        dd["requests"] += 1
        if model:
            dd["models"][model] = dd["models"].get(model, 0) + 1

        ud["total_input"] += inp
        ud["total_output"] += out
        ud["total_cache_read"] += cache_read
        ud["total_cache_write"] += cache_write
        ud["total_reasoning"] += reasoning
        ud["total_requests"] += 1

    # Build ranking sorted by real tokens (input + output, excluding cache) desc
    ranking = []
    for username, ud in users_data.items():
        ranking.append({
            "username": username,
            "total_input": ud["total_input"],
            "total_output": ud["total_output"],
            "total_cache_read": ud["total_cache_read"],
            "total_cache_write": ud["total_cache_write"],
            "total_reasoning": ud["total_reasoning"],
            "total_real_tokens": ud["total_input"] + ud["total_output"],
            "total_requests": ud["total_requests"],
        })
    ranking.sort(key=lambda x: x["total_real_tokens"], reverse=True)

    return {
        "month": month,
        "days": sorted(days_set),
        "users": users_data,
        "ranking": ranking,
    }


def get_available_months() -> list:
    """Return list of months that have request log data."""
    try:
        conn = sqlite3.connect(str(DB_FILE))
        rows = conn.execute(
            "SELECT DISTINCT substr(date, 1, 7) AS m "
            "FROM request_log WHERE length(date) >= 7 "
            "ORDER BY m DESC"
        ).fetchall()
        conn.close()
        return [r[0] for r in rows]
    except Exception:
        return []
