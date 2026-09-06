"""
storage.py - Persistent storage abstraction with JSON and SQLite backends
P2: Adds optional SQLite persistence for better durability and concurrency

By default uses JSON files (simple, human-readable). Set STORAGE_BACKEND="sqlite"
in config.py or via env var LAB_STORAGE_BACKEND to use SQLite.

Both backends provide same interface, so existing code can switch without changes.
"""
import json
import os
import sqlite3
import threading
from contextlib import contextmanager

import config

# Thread-local lock for JSON file safety
_json_lock = threading.Lock()

# SQLite connection lock
_sqlite_lock = threading.Lock()

def _get_backend():
    """Get storage backend from config or env var"""
    # Allow env var override: LAB_STORAGE_BACKEND=sqlite
    backend = os.getenv("LAB_STORAGE_BACKEND", getattr(config, "STORAGE_BACKEND", "json"))
    return backend.lower()


def _ensure_data_dir():
    os.makedirs("data", exist_ok=True)


# ============ JSON Backend (original, simple) ============

def _load_json_file(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return default

def _save_json_file(path, data):
    _ensure_data_dir()
    with _json_lock:
        # Write to temp file then rename for atomicity
        tmp_path = path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, path)


# ============ SQLite Backend (P2: persistent, ACID) ============

def _get_sqlite_db():
    db_path = getattr(config, "STORAGE_DB", "data/lab.db")
    _ensure_data_dir()
    return db_path

@contextmanager
def _sqlite_conn():
    db_path = _get_sqlite_db()
    with _sqlite_lock:
        conn = sqlite3.connect(db_path, timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            # Enable WAL mode for better concurrency
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            yield conn
            conn.commit()
        finally:
            conn.close()

def _init_sqlite():
    db_path = _get_sqlite_db()
    if os.path.exists(db_path):
        return
    with _sqlite_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS kv_store (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Create index for faster lookups
        conn.execute("CREATE INDEX IF NOT EXISTS idx_kv_key ON kv_store(key)")

def _sqlite_get(key, default):
    _init_sqlite()
    try:
        with _sqlite_conn() as conn:
            row = conn.execute("SELECT value FROM kv_store WHERE key = ?", (key,)).fetchone()
            if row is None:
                return default
            return json.loads(row["value"])
    except (sqlite3.Error, json.JSONDecodeError):
        return default

def _sqlite_set(key, value):
    _init_sqlite()
    try:
        with _sqlite_conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO kv_store (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
                (key, json.dumps(value))
            )
    except sqlite3.Error as e:
        # Fallback to JSON on SQLite error
        print(f"SQLite error, falling back to JSON: {e}")
        _save_json_file(f"data/{key}.json", value)


# ============ Unified Interface ============

def load_users():
    backend = _get_backend()
    if backend == "sqlite":
        return _sqlite_get("users", {})
    return _load_json_file("data/users.json", {})

def save_users(users):
    backend = _get_backend()
    if backend == "sqlite":
        _sqlite_set("users", users)
    else:
        _save_json_file("data/users.json", users)

def load_sessions():
    backend = _get_backend()
    if backend == "sqlite":
        return _sqlite_get("sessions", {})
    return _load_json_file("data/sessions.json", {})

def save_sessions(sessions):
    backend = _get_backend()
    if backend == "sqlite":
        _sqlite_set("sessions", sessions)
    else:
        _save_json_file("data/sessions.json", sessions)

def load_requests():
    backend = _get_backend()
    if backend == "sqlite":
        return _sqlite_get("requests", {})
    return _load_json_file("data/requests.json", {})

def save_requests(requests):
    backend = _get_backend()
    if backend == "sqlite":
        _sqlite_set("requests", requests)
    else:
        _save_json_file("data/requests.json", requests)

def load_devices():
    backend = _get_backend()
    if backend == "sqlite":
        data = _sqlite_get("devices", None)
        if data is None:
            # Return None to signal "use FLEET default"
            return None
        return data
    # JSON backend: return None if file doesn't exist (caller uses FLEET)
    if not os.path.exists("data/devices.json"):
        return None
    return _load_json_file("data/devices.json", {})

def save_devices(devices):
    backend = _get_backend()
    if backend == "sqlite":
        _sqlite_set("devices", devices)
    else:
        _save_json_file("data/devices.json", devices)

def get_storage_info():
    """Return info about current storage backend for dashboard"""
    backend = _get_backend()
    if backend == "sqlite":
        db_path = _get_sqlite_db()
        exists = os.path.exists(db_path)
        size = os.path.getsize(db_path) if exists else 0
        return {
            "backend": "sqlite",
            "path": db_path,
            "exists": exists,
            "size_bytes": size,
            "persistent": True,
            "acid": True,
        }
    else:
        # JSON backend info
        files = ["data/users.json", "data/sessions.json", "data/requests.json", "data/devices.json"]
        total_size = sum(os.path.getsize(f) for f in files if os.path.exists(f))
        return {
            "backend": "json",
            "path": "data/*.json",
            "exists": any(os.path.exists(f) for f in files),
            "size_bytes": total_size,
            "persistent": True,
            "acid": False,
            "note": "Simple, human-readable, but no ACID. Use LAB_STORAGE_BACKEND=sqlite for SQLite",
        }

def migrate_json_to_sqlite():
    """Migrate existing JSON data to SQLite - useful for upgrading"""
    if _get_backend() != "sqlite":
        print("Set STORAGE_BACKEND=sqlite to migrate")
        return False
    
    print("Migrating JSON -> SQLite...")
    for key, json_path in [
        ("users", "data/users.json"),
        ("sessions", "data/sessions.json"),
        ("requests", "data/requests.json"),
        ("devices", "data/devices.json"),
    ]:
        if os.path.exists(json_path):
            data = _load_json_file(json_path, {})
            if data:
                _sqlite_set(key, data)
                print(f"  Migrated {key}: {len(data) if isinstance(data, dict) else 'data'} items")
    
    print(f"Migration complete. SQLite DB at {_get_sqlite_db()}")
    return True

if __name__ == "__main__":
    print("Storage backend:", _get_backend())
    print("Info:", get_storage_info())
    # Test migration if JSON exists
    if os.path.exists("data/users.json"):
        print("\nJSON files found. To migrate to SQLite:")
        print("  LAB_STORAGE_BACKEND=sqlite python storage.py --migrate")
    import sys
    if "--migrate" in sys.argv:
        os.environ["LAB_STORAGE_BACKEND"] = "sqlite"
        # Need to reimport config? Just set backend via env and call
        migrate_json_to_sqlite()
