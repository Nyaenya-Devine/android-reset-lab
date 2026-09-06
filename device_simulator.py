# device_simulator.py - the fictional Android fleet (nothing real)
# P2: Added persistent storage abstraction (JSON + SQLite)
import copy
import json
import os

DEVICES_FILE = "data/devices.json"

FLEET = {
    "AND-001": {"model": "Pixel 7", "owner": "finance", "status": "active"},
    "AND-002": {"model": "Galaxy S22", "owner": "sales", "status": "active"},
    "AND-003": {"model": "Pixel 6a", "owner": "hr", "status": "lost"},
    "AND-004": {"model": "OnePlus 9", "owner": "it", "status": "active"},
    "AND-005": {"model": "Pixel 8", "owner": "exec", "status": "active"},
    "AND-006": {"model": "Galaxy A54", "owner": "intern", "status": "stolen"},
}

# P2: Use storage abstraction if available
try:
    import storage as storage_backend
    _USE_STORAGE = True
except ImportError:
    _USE_STORAGE = False


def seed_devices():
    """Create the fleet file once. Never overwrites an existing fleet."""
    # Check via storage abstraction
    if _USE_STORAGE:
        try:
            existing = storage_backend.load_devices()
            if existing is not None:
                return False
        except Exception:
            pass
    else:
        if os.path.exists(DEVICES_FILE):
            return False
    # Deep copy to avoid mutating global FLEET
    save_devices(copy.deepcopy(FLEET))
    return True


def save_devices(devices):
    if _USE_STORAGE:
        try:
            import config
            if getattr(config, "STORAGE_BACKEND", "json") == "sqlite":
                storage_backend.save_devices(devices)
                return
        except Exception:
            pass
    os.makedirs("data", exist_ok=True)
    with open(DEVICES_FILE, "w", encoding="utf-8") as f:
        json.dump(devices, f, indent=2)


def load_devices():
    if _USE_STORAGE:
        try:
            import config
            if getattr(config, "STORAGE_BACKEND", "json") == "sqlite":
                data = storage_backend.load_devices()
                if data is not None:
                    return data
                return copy.deepcopy(FLEET)
        except Exception:
            pass
    if not os.path.exists(DEVICES_FILE):
        # Deep copy to prevent shallow-copy bug where inner dicts are shared
        return copy.deepcopy(FLEET)
    try:
        with open(DEVICES_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return copy.deepcopy(FLEET)


def get_device(device_id):
    return load_devices().get(device_id)


def fleet_summary():
    devices = load_devices()
    counts = {}
    for d in devices.values():
        counts[d["status"]] = counts.get(d["status"], 0) + 1
    return len(devices), counts


if __name__ == "__main__":
    print("seeded:", seed_devices())
    total, counts = fleet_summary()
    print("fleet size:", total, "| statuses:", counts)
    print("AND-003:", get_device("AND-003"))
    print("AND-999:", get_device("AND-999"))