import pytest
import config
import authentication
import reset_workflow
import device_simulator


@pytest.fixture(autouse=True)
def clean_lab_state(tmp_path, monkeypatch):
    """Give every test an isolated simulated data directory."""
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

    yield