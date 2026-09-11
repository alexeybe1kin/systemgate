"""Read-only verification of the conker-snapshot-1 recovery contract.

Keep this format in step with companion/scripts/recovery.py: a directory name
or manifest claiming success is not evidence that the snapshot is intact.
Verification does not establish deletion replay, vault recovery or restorability.
"""
from __future__ import annotations

import hashlib
import json
import re
import stat
import tarfile
import time
from datetime import datetime
from pathlib import Path, PurePosixPath

FORMAT = "conker-snapshot-1"
SERVICES = {"pi", "toolgate", "memorygate", "systemgate", "embeddings", "postgres",
            "qdrant", "ollama", "searxng"}
STORES = {"pi", "toolgate", "systemgate", "qdrant", "ollama", "memorygate-backups"}
REQUIRED = {*(name + ".tar" for name in STORES), "memorygate.dump", "postgres-globals.sql",
            "config/env", "config/versions.env", "config/docker-compose.yml", "config/compose.json",
            "config/runtime.json", "memorygate/runtime-token"}


class InvalidSnapshot(ValueError):
    def __init__(self, status: str, reason: str) -> None:
        self.status = status
        self.reason = reason
        super().__init__(reason)


def _invalid(reason: str, status: str = "invalid") -> None:
    raise InvalidSnapshot(status, reason)


def _safe_name(name: str) -> bool:
    path = PurePosixPath(name)
    return (bool(name) and not path.is_absolute() and ".." not in path.parts
            and "\\" not in name and ":" not in name and path.as_posix() == name)


def _files(directory: Path) -> dict[str, Path]:
    files = {}
    for path in directory.rglob("*"):
        mode = path.lstat().st_mode
        if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)) or path.is_symlink():
            _invalid("Snapshot contains a link or special file; use the original snapshot.")
        if stat.S_ISREG(mode) and path != directory / "manifest.json":
            files[path.relative_to(directory).as_posix()] = path
    return files


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _signature(path: Path) -> tuple:
    value = path.stat()
    # Verification itself may change access time on a writable test/local mount.
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def _archive(path: Path, required: str | None) -> None:
    seen = set()
    with tarfile.open(path, "r:") as archive:
        for member in archive:
            if (not _safe_name(member.name) or member.name in seen
                    or not (member.isfile() or member.isdir())):
                _invalid("Archive has unsafe or duplicate members; obtain an intact snapshot.")
            seen.add(member.name)
            if member.name == required and not member.isfile():
                _invalid("Required SQLite store is not a file; obtain an intact snapshot.")
            if member.isfile():
                with archive.extractfile(member) as stream:
                    if member.name == required and stream.read(16) != b"SQLite format 3\x00":
                        _invalid("Required SQLite store is invalid; obtain an intact snapshot.")
                    while stream.read(1024 * 1024):
                        pass
    if required and required not in seen:
        _invalid("Required SQLite store is missing; obtain an intact snapshot.")


def verify_snapshot(directory: Path) -> dict:
    if directory.is_symlink() or not directory.is_dir():
        _invalid("Snapshot is not an original directory; check the backup mount.")
    manifest_path = directory / "manifest.json"
    if manifest_path.is_symlink():
        _invalid("Manifest must not be a link; obtain an intact snapshot.")
    if not manifest_path.is_file():
        _invalid("Manifest missing: incomplete or legacy backup. Create a new backup.", "incomplete")
    manifest_before = _signature(manifest_path)
    if manifest_path.stat().st_size > 4 * 1024 * 1024:
        _invalid("Manifest exceeds the supported size; verify it with the recovery command.")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        _invalid("Manifest must be an object; obtain an intact snapshot.")
    if manifest.get("format") != FORMAT:
        _invalid("Unsupported snapshot format; use a compatible recovery verifier.", "unsupported")
    if manifest.get("status") != "complete":
        _invalid("Snapshot is incomplete; create a new backup.", "incomplete")
    try:
        created = datetime.fromisoformat(manifest["created_at"].replace("Z", "+00:00"))
        if created.tzinfo is None:
            raise ValueError("timezone missing")
        created_at = created.timestamp()
        if created_at > time.time() + 300:
            raise ValueError("future timestamp")
    except (KeyError, TypeError, AttributeError, ValueError, OverflowError):
        _invalid("Snapshot creation time is invalid; verify the manifest and system clock.")
    files = manifest.get("files")
    if not isinstance(files, dict) or not REQUIRED <= files.keys():
        _invalid("Required files are missing from the manifest; create a complete backup.")
    actual = _files(directory)
    if files.keys() != actual.keys():
        _invalid("Files are missing or unexpected; obtain an intact snapshot.")
    images = manifest.get("images")
    if (not isinstance(images, dict) or images.keys() != SERVICES
            or any(not isinstance(image, dict)
                   or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(image.get("id", "")))
                   for image in images.values())):
        _invalid("Image identities are invalid; obtain an intact version manifest.")
    stores = manifest.get("stores")
    if (not isinstance(stores, dict) or not STORES <= stores.keys()
            or any(name not in STORES and not re.fullmatch(r"extra-[a-z]+-[0-9]+", name)
                   for name in stores)
            or {name + ".tar" for name in stores} != {n for n in files if n.endswith(".tar")}):
        _invalid("Storage inventory and archives disagree; obtain an intact snapshot.")
    before = {name: _signature(path) for name, path in actual.items()}
    for name, path in actual.items():
        record = files[name]
        if (not _safe_name(name) or not isinstance(record, dict)
                or record.keys() != {"size", "sha256"}
                or type(record.get("size")) is not int or record["size"] < 0
                or not re.fullmatch(r"[0-9a-f]{64}", str(record.get("sha256", "")))
                or before[name][2] != record["size"] or _hash(path) != record["sha256"]):
            _invalid("File size or integrity hash differs; obtain an intact snapshot.")
    with (directory / "memorygate.dump").open("rb") as stream:
        if stream.read(5) != b"PGDMP":
            _invalid("PostgreSQL dump is invalid; create a new backup.")
    for name, path in actual.items():
        if name.endswith(".tar"):
            _archive(path, {"pi.tar": "pi.db", "toolgate.tar": "toolgate.db"}.get(name))
    if (actual.keys() != _files(directory).keys() or _signature(manifest_path) != manifest_before
            or any(_signature(path) != before[name] for name, path in actual.items())):
        _invalid("Snapshot changed during verification; wait for backup to finish and retry.")
    return {"created_at": created_at, "status": "verified", "verified_at": time.time(),
            "verification": "manifest-files-and-archives", "restore_status": "not_tested",
            "deletion_ledger": manifest.get("deletion_ledger", "unknown"),
            "execution_journal": manifest.get("execution_journal", "unknown")}


def backup_status(root: Path) -> dict:
    result = {"root": str(root), "status": "unknown", "latest": None, "results": [],
              "rejected": [], "checked_at": time.time(), "verified_count": 0,
              "rejected_count": 0}
    try:
        entries = sorted(root.iterdir(), key=lambda item: item.name)
    except OSError:
        return {**result, "status": "unavailable",
                "reason": "Backup root cannot be read. Mount backups at /backups and set "
                          "SYSTEMGATE_BACKUP_ROOT=/backups inside the container."}
    verified, rejected = [], []
    for directory in entries:
        if not directory.is_dir() and not directory.is_symlink():
            continue
        row = {"name": directory.name, "path": str(directory)}
        try:
            verified.append({**row, **verify_snapshot(directory)})
        except InvalidSnapshot as exc:
            rejected.append({**row, "status": exc.status, "reason": exc.reason})
        except (OSError, ValueError, tarfile.TarError):
            # Parser and OS errors can contain credentials or recovered text.
            rejected.append({**row, "status": "unverifiable",
                             "reason": "Snapshot could not be verified. Check permissions "
                                       "and run the recovery verifier on the original."})
    verified.sort(key=lambda row: (row["created_at"], row["name"]), reverse=True)
    return {**result, "status": "degraded" if rejected else ("ok" if verified else "empty"),
            "latest": verified[0] if verified else None, "results": verified[:20],
            "rejected": rejected[:20], "verified_count": len(verified),
            "rejected_count": len(rejected), "checked_at": time.time()}
