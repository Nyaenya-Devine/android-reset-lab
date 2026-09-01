# device_simulator.py - the fictional Android fleet (nothing real)
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


def seed_devices():
    """Create the fleet file once. Never overwrites an existing fleet."""
    if not os.path.exists(DEVICES_FILE):
        # Deep copy to avoid mutating global FLEET
        save_devices(copy.deepcopy(FLEET))
        return True
    return False


def save_devices(devices):
    os.makedirs("data", exist_ok=True)
    with open(DEVICES_FILE, "w") as f:
        json.dump(devices, f, indent=2)


def load_devices():
    if not os.path.exists(DEVICES_FILE):
        # Deep copy to prevent shallow-copy bug where inner dicts are shared
        return copy.deepcopy(FLEET)
    with open(DEVICES_FILE, "r") as f:
        return json.load(f)


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