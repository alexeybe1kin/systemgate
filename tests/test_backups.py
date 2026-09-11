import hashlib
import io
import json
import os
import tarfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from systemgate import backups
from systemgate.config import get_settings

# Independently specified producer contract, so changing the consumer's required
# inventory cannot silently change the fixtures to agree with the bug.
STORES = {"pi", "toolgate", "systemgate", "qdrant", "ollama", "memorygate-backups"}
SERVICES = {"pi", "toolgate", "memorygate", "systemgate", "embeddings", "postgres",
            "qdrant", "ollama", "searxng"}
FILES = {*(name + ".tar" for name in STORES), "memorygate.dump", "postgres-globals.sql",
         "config/env", "config/versions.env", "config/docker-compose.yml", "config/compose.json",
         "config/runtime.json", "memorygate/runtime-token"}


def snapshot(root, name="snapshot-a", created="2026-01-01T00:00:00+00:00"):
    directory = root / name
    directory.mkdir(parents=True)
    for filename in FILES:
        path = directory / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        if filename.endswith(".tar"):
            with tarfile.open(path, "w") as archive:
                required = {"pi.tar": "pi.db", "toolgate.tar": "toolgate.db"}.get(filename, "data")
                value = b"SQLite format 3\x00" if required.endswith(".db") else b"data"
                member = tarfile.TarInfo(required)
                member.size = len(value)
                archive.addfile(member, io.BytesIO(value))
        else:
            path.write_bytes(b"PGDMPfixture" if filename == "memorygate.dump" else b"secret-placeholder")
    manifest = {"format": "conker-snapshot-1", "status": "complete", "created_at": created,
                "images": {name: {"id": "sha256:" + "a" * 64} for name in SERVICES},
                "stores": {name: {} for name in STORES}, "deletion_ledger": "unavailable",
                "execution_journal": "unavailable"}
    save_manifest(directory, manifest)
    return directory


def save_manifest(directory, manifest=None):
    if manifest is None:
        manifest = json.loads((directory / "manifest.json").read_text())
    manifest["files"] = {
        path.relative_to(directory).as_posix(): {
            "size": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        } for path in directory.rglob("*") if path.is_file() and path.name != "manifest.json"
    }
    (directory / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def test_latest_is_verified_creation_time_not_directory_mtime(tmp_path):
    old = snapshot(tmp_path, "old", "2026-01-01T00:00:00+00:00")
    new = snapshot(tmp_path, "new", "2026-02-01T00:00:00+00:00")
    for index in range(25):
        (tmp_path / f"incomplete-{index}").mkdir()
    os.utime(old, (2000000000, 2000000000))
    os.utime(new, (1, 1))
    result = backups.backup_status(tmp_path)
    assert result["latest"]["name"] == "new"
    assert [row["name"] for row in result["results"]] == ["new", "old"]
    assert result["verified_count"] == 2 and result["rejected_count"] == 25
    assert result["status"] == "degraded"
    assert result["latest"]["restore_status"] == "not_tested"
    assert result["latest"]["deletion_ledger"] == "unavailable"


def test_tampering_same_size_and_mtime_cannot_remain_verified(tmp_path):
    directory = snapshot(tmp_path)
    assert backups.backup_status(tmp_path)["latest"] is not None
    path = directory / "config/env"
    before = path.stat()
    path.write_bytes(b"x" * before.st_size)
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    result = backups.backup_status(tmp_path)
    assert result["latest"] is None and result["results"] == []
    assert result["rejected"][0]["status"] == "invalid"


@pytest.mark.parametrize("change", ["missing", "extra", "partial", "format", "images",
                                    "stores", "timestamp", "malformed", "postgres", "archive"])
def test_invalid_snapshots_are_never_recovery_points(tmp_path, change):
    directory = snapshot(tmp_path)
    path = directory / "manifest.json"
    manifest = json.loads(path.read_text())
    if change == "missing":
        (directory / "toolgate.tar").unlink()
    elif change == "extra":
        (directory / "unexpected").write_text("not captured")
    elif change == "postgres":
        (directory / "memorygate.dump").write_bytes(b"not postgres")
        save_manifest(directory)
    elif change == "archive":
        (directory / "pi.tar").write_bytes(b"not a tar")
        save_manifest(directory)
    elif change == "malformed":
        path.write_text('{"secret-do-not-print":')
    else:
        field, value = {"partial": ("status", "writing"), "format": ("format", "future"),
                        "images": ("images", {}), "stores": ("stores", {}),
                        "timestamp": ("created_at", "invalid")}[change]
        manifest[field] = value
        path.write_text(json.dumps(manifest))
    result = backups.backup_status(tmp_path)
    assert result["latest"] is None and not result["results"]
    assert len(result["rejected"]) == 1
    assert "secret-do-not-print" not in json.dumps(result)


@pytest.mark.parametrize("member_name,kind", [("../escape", "file"), ("pi.db", "link"),
                                              ("pi.db", "dir"), ("missing.db", "file")])
def test_even_hash_matching_unsafe_archives_fail(tmp_path, member_name, kind):
    directory = snapshot(tmp_path)
    with tarfile.open(directory / "pi.tar", "w") as archive:
        member = tarfile.TarInfo(member_name)
        if kind == "dir":
            member.type = tarfile.DIRTYPE
        elif kind == "link":
            member.type = tarfile.SYMTYPE
            member.linkname = "/secret"
        else:
            member.size = 16
        archive.addfile(member, io.BytesIO(b"SQLite format 3\x00") if kind == "file" else None)
    save_manifest(directory)
    assert backups.backup_status(tmp_path)["latest"] is None


def test_read_errors_are_unverifiable_without_leaking_payload(tmp_path, monkeypatch):
    snapshot(tmp_path)
    monkeypatch.setattr(backups, "_hash", lambda path: (_ for _ in ()).throw(
        PermissionError("SECRET-IN-ERROR")))
    result = backups.backup_status(tmp_path)
    assert result["latest"] is None
    assert result["rejected"][0]["status"] == "unverifiable"
    assert "SECRET-IN-ERROR" not in json.dumps(result)


def test_links_are_not_followed_as_snapshots_or_payloads(tmp_path):
    directory = snapshot(tmp_path)
    try:
        (tmp_path / "alias").symlink_to(directory, target_is_directory=True)
    except OSError:
        pytest.skip("Creating symlinks requires additional Windows privileges")
    result = backups.backup_status(tmp_path)
    assert result["verified_count"] == 1
    assert result["rejected"][0]["name"] == "alias"
    (directory / "config/link").symlink_to(directory / "config/env")
    assert backups.backup_status(tmp_path)["latest"] is None


def test_change_during_verification_is_not_reported_as_success(tmp_path, monkeypatch):
    directory = snapshot(tmp_path)
    original = backups._archive

    def change_after_hashing(path, required):
        original(path, required)
        (directory / "config/env").write_bytes(b"changed after hashing")

    monkeypatch.setattr(backups, "_archive", change_after_hashing)
    assert backups.backup_status(tmp_path)["latest"] is None


def test_missing_and_empty_backup_roots_are_distinct(tmp_path):
    assert backups.backup_status(tmp_path / "missing")["status"] == "unavailable"
    assert backups.backup_status(tmp_path)["status"] == "empty"


def test_endpoint_reads_the_configured_mount_and_requires_auth(tmp_path, monkeypatch):
    monkeypatch.setenv("SYSTEMGATE_ADMIN_KEY", "backup-test-key-1234")
    monkeypatch.setenv("SYSTEMGATE_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SYSTEMGATE_BACKUP_ROOT", str(tmp_path / "backups"))
    snapshot(tmp_path / "backups")
    from systemgate.main import app
    with TestClient(app) as client:
        assert client.get("/backups").status_code == 401
        body = client.get("/backups", headers={"X-SystemGate-Key": "backup-test-key-1234"}).json()
    assert body["latest"]["name"] == "snapshot-a"
    assert body["latest"]["status"] == "verified"


def test_container_default_matches_backup_mount(monkeypatch):
    monkeypatch.delenv("SYSTEMGATE_BACKUP_ROOT", raising=False)
    assert get_settings().backup_root == Path("/backups").resolve()
    assert "SYSTEMGATE_BACKUP_ROOT: /backups" in Path("docker-compose.yml").read_text()
