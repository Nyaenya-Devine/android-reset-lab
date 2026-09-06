import pytest
import config
import authentication
import reset_workflow
import device_simulator


@pytest.fixture(autouse=True)
def clean_lab_state(tmp_path, monkeypatch):
    """Give every test an isolated simulated data directory.
    P2: Also isolates SQLite storage backend for persistence tests
    """
    data_dir = tmp_path / "data"
    logs_dir = tmp_path / "logs"

    data_dir.mkdir()
    logs_dir.mkdir()

    monkeypatch.setattr(
        authentication,
        "USERS_FILE",
        str(data_dir / "users.json")
    )
    monkeypatch.setattr(
        authentication,
        "SESSIONS_FILE",
        str(data_dir / "sessions.json")
    )
    monkeypatch.setattr(
        reset_workflow,
        "REQUESTS_FILE",
        str(data_dir / "requests.json")
    )
    monkeypatch.setattr(
        device_simulator,
        "DEVICES_FILE",
        str(data_dir / "devices.json")
    )
    monkeypatch.setattr(
        config,
        "LOG_FILE",
        str(logs_dir / "security_log.jsonl")
    )
    # P2: Isolate storage backend - force JSON for most tests for simplicity and isolation
    monkeypatch.setattr(config, "STORAGE_BACKEND", "json")
    monkeypatch.setattr(config, "STORAGE_DB", str(data_dir / "lab.db"))
    # Clear rate limit stores for isolation
    authentication._auth_rate_limit_store.clear()
    try:
        import web_console
        web_console.rate_limit_store.clear()
    except ImportError:
        pass

    yield
