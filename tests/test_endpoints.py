from __future__ import annotations

from unittest.mock import Mock

from fastapi.testclient import TestClient


def make_client(tmp_path, monkeypatch):
    monkeypatch.setenv("SYSTEMGATE_ADMIN_KEY", "system-test-key-1234")
    monkeypatch.setenv("SYSTEMGATE_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SYSTEMGATE_BACKUP_ROOT", str(tmp_path / "backups"))
    from systemgate.main import app
    return TestClient(app)


def headers():
    return {"X-SystemGate-Key": "system-test-key-1234"}


def test_health_and_auth(tmp_path, monkeypatch):
    with make_client(tmp_path, monkeypatch) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/vitals").status_code == 401


def test_vitals_with_mocked_psutil(tmp_path, monkeypatch):
    import systemgate.main as main
    monkeypatch.setattr(main.psutil, "cpu_percent", lambda interval=0: 12.5)
    monkeypatch.setattr(main.psutil, "cpu_count", lambda: 8)
    monkeypatch.setattr(main.psutil, "virtual_memory", lambda: Mock(_asdict=lambda: {"total": 100, "available": 50}))
    monkeypatch.setattr(main.psutil, "disk_usage", lambda path: Mock(_asdict=lambda: {"total": 200, "free": 100}))
    monkeypatch.setattr(main.psutil, "sensors_temperatures", lambda fahrenheit=False: {}, raising=False)

    with make_client(tmp_path, monkeypatch) as client:
        data = client.get("/vitals", headers=headers()).json()
        assert data["cpu_percent"] == 12.5
        assert data["memory"]["total"] == 100


def test_containers_with_mocked_docker(tmp_path, monkeypatch):
    import systemgate.main as main
    container = Mock(short_id="abc123", status="running", attrs={"Created": "now"})
    container.name = "agentgate-api"
    container.image.tags = ["agentgate:latest"]
    container.stats.return_value = {"cpu_stats": {}}
    docker_client = Mock()
    docker_client.containers.list.return_value = [container]
    monkeypatch.setattr(main, "_docker_client", lambda: docker_client)

    with make_client(tmp_path, monkeypatch) as client:
        data = client.get("/containers", headers=headers()).json()
        assert data["results"][0]["name"] == "agentgate-api"


def test_services_inventory_is_metadata_only(tmp_path, monkeypatch):
    import systemgate.main as main

    class Addr:
        ip = "127.0.0.1"
        port = 8644

    conn = Mock(status="LISTEN", laddr=Addr(), pid=123)
    proc = Mock()
    proc.name.return_value = "pi-adapter"
    monkeypatch.setattr(main.psutil, "net_connections", lambda kind: [conn])
    monkeypatch.setattr(main.psutil, "Process", lambda pid: proc)

    with make_client(tmp_path, monkeypatch) as client:
        data = client.get("/services", headers=headers()).json()

    assert data["metadata_only"] is True
    assert data["results"][0]["id"] == "service-001"
    assert data["results"][0]["name"] == "pi-adapter"
    assert data["results"][0]["listeners"] == ["loopback:8644"]
    assert "pid" not in data["results"][0]
    assert "cmdline" not in data["results"][0]
    assert "env" not in data["results"][0]
    assert "username" not in data["results"][0]


def test_processes_logs_packages_and_backups_are_bounded(tmp_path, monkeypatch):
    backup_root = tmp_path / "backups"
    backup_root.mkdir()
    (backup_root / "20260101T000000Z").mkdir()
    import systemgate.main as main
    proc = Mock(info={"pid": 1, "name": "python", "username": "me", "cpu_percent": 1.0, "memory_percent": 2.0, "cmdline": ["python", "app.py"]})
    monkeypatch.setattr(main.psutil, "process_iter", lambda fields: [proc])
    monkeypatch.setattr(main, "_journal_errors", lambda: "bounded errors")
    monkeypatch.setattr(main, "_run_summary", lambda command: {"ok": True, "output": "[]"})

    with make_client(tmp_path, monkeypatch) as client:
        assert client.get("/processes", headers=headers()).json()["results"][0]["name"] == "python"
        assert client.get("/logs/errors", headers=headers()).json()["text"] == "bounded errors"
        assert client.get("/packages", headers=headers()).json()["pip"]["ok"] is True
        assert client.get("/backups", headers=headers()).json()["latest"]["name"] == "20260101T000000Z"
