from __future__ import annotations

import json
import os
import platform
import subprocess
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import docker
import psutil
from fastapi import Depends, FastAPI, Header, HTTPException, Request

from .auth import hash_key, verify_key
from .backups import backup_status
from .config import Settings, get_settings

PACKAGE_CACHE_SECONDS = 3600

# Point psutil at the host's procfs when it is mounted.
#
# This must be done in code. psutil reads no environment variable for it -
# neither PROCFS_PATH nor PSUTIL_PROCFS_PATH - so setting one in compose and
# mounting /proc looks correct and does nothing: every figure still describes
# this container. The module attribute is the only mechanism, and it has to be
# assigned before the first reading is taken.
#
# Verified on Linux: with psutil.PROCFS_PATH redirected, virtual_memory() reads
# the redirected meminfo; with only the environment variable set, it does not.
_HOST_PROCFS = os.environ.get("SYSTEMGATE_PROCFS_PATH", "").strip()
if _HOST_PROCFS and Path(_HOST_PROCFS, "meminfo").exists():
    psutil.PROCFS_PATH = _HOST_PROCFS


def procfs_path() -> str:
    """Where readings are actually coming from, whatever was configured."""
    return str(getattr(psutil, "PROCFS_PATH", "/proc"))


def _bounded(value: str, limit: int = 4000) -> str:
    return value[-limit:]


def _json_safe(value: Any) -> Any:
    try:
        json.dumps(value)
        return value
    except TypeError:
        return {}


def _secret_path(settings: Settings) -> Path:
    return settings.data_dir / "admin-key.pbkdf2"


def _ensure_key_hash(settings: Settings) -> None:
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    path = _secret_path(settings)
    if path.exists():
        return
    if not settings.admin_key:
        raise RuntimeError("SYSTEMGATE_ADMIN_KEY is required")
    path.write_text(hash_key(settings.admin_key), encoding="utf-8")
    path.chmod(0o600)


def require_admin(request: Request, x_systemgate_key: str | None = Header(None, alias="X-SystemGate-Key")) -> str:
    path = _secret_path(request.app.state.settings)
    encoded = path.read_text(encoding="utf-8").strip() if path.exists() else ""
    if not verify_key(x_systemgate_key, encoded):
        raise HTTPException(401, "missing or invalid X-SystemGate-Key")
    return "admin"


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    _ensure_key_hash(settings)
    app.state.settings = settings
    app.state.package_cache = {"at": 0.0, "value": None}
    yield


# One place, so /health and the OpenAPI document cannot disagree about
# which version is running. They had: /health said 0.1.0 at tag v0.2.1.
SERVICE_VERSION = "0.2.3"

app = FastAPI(title="SystemGate", version=SERVICE_VERSION, lifespan=lifespan)


HEALTHY = {"ok", "not_configured"}


def _probe(fn: Any) -> dict[str, str]:
    """Run one dependency probe.

    Detail is deliberately coarse. /health is unauthenticated, so it must not
    leak host paths, socket locations or exception text to an anonymous caller.
    """
    try:
        fn()
    except Exception:
        return {"status": "unavailable", "reason": "unreachable"}
    return {"status": "ok"}


@app.get("/health")
def health(request: Request):
    """Shape is fixed by the Conker module contract - see docs/module-contract.md.

    `checks` is keyed by name so a caller can ask for one dependency without
    scanning, and so one dashboard renders every module with no special cases.
    """
    settings = request.app.state.settings
    checked_at = datetime.now(timezone.utc)
    checks = {
        "procfs": _probe(psutil.virtual_memory),
        "docker": _probe(lambda: _docker_client().ping()),
        "admin_key": _probe(lambda: _secret_path(settings).read_text(encoding="utf-8")),
    }
    degraded = sorted(name for name, c in checks.items() if c["status"] not in HEALTHY)
    return {
        "service": "systemgate",
        "version": app.version,
        "status": "degraded" if degraded else "ok",
        "degraded": degraded,
        "checks": checks,
        "checked_at": checked_at.isoformat(),
        # Probes run per request here; the field exists because the contract
        # allows caching and a cached answer must always carry its age.
        "age_seconds": 0.0,
    }


@app.get("/vitals", dependencies=[Depends(require_admin)])
def vitals():
    temps = {}
    try:
        sensors = getattr(psutil, "sensors_temperatures")
        temps = {name: [entry._asdict() for entry in values] for name, values in sensors(fahrenheit=False).items()}
    except (AttributeError, OSError):
        temps = {}
    # Which filesystem is measured is a deployment detail, so report it rather
    # than let the caller assume. Without the host root mounted, this is the
    # container's own filesystem and saying so is the difference between
    # telemetry and a misleading number.
    disk_path = os.environ.get("SYSTEMGATE_DISK_PATH", "/")
    disk = psutil.disk_usage(disk_path)

    # Read from psutil itself rather than from the environment, so this reports
    # where the numbers came from instead of where they were asked to come from.
    procfs = procfs_path()

    # platform.node() reads the UTS namespace, which is per-container and is
    # *not* affected by bind-mounting the host's /proc: /proc/sys/kernel/hostname
    # reflects the reading process's namespace, not the mount source. The only
    # way to report the real host name is to share the namespace, which the
    # bundled compose file does with `uts: host`. Without it this is the
    # container id, and source.scope says so.
    return {
        "host": platform.node(),
        "platform": platform.platform(),
        "cpu_percent": psutil.cpu_percent(interval=0.05),
        "cpu_count": psutil.cpu_count(),
        "memory": psutil.virtual_memory()._asdict(),
        "disk": disk._asdict(),
        "load": os.getloadavg() if hasattr(os, "getloadavg") else [0.0, 0.0, 0.0],
        "temps": temps,
        "source": {
            "procfs": procfs,
            "disk_path": disk_path,
            "scope": "host" if procfs != "/proc" else "container",
        },
    }


def _docker_client():
    return docker.from_env()


def _safe_process_name(pid: int | None) -> str:
    if not pid:
        return "unknown"
    try:
        proc = psutil.Process(pid)
        return str(proc.name() or "unknown")[:80]
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
        return "unknown"


def _safe_addr(addr: Any) -> str:
    ip = str(getattr(addr, "ip", "") or "")
    port = int(getattr(addr, "port", 0) or 0)
    if not ip or not port:
        return ""
    if ip in {"0.0.0.0", "::"}:
        scope = "container-internal" if Path("/.dockerenv").exists() else "all-interfaces"
    elif ip.startswith("127.") or ip == "::1":
        scope = "loopback"
    elif ip.startswith("100."):
        scope = "tailscale"
    elif ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")):
        scope = "private-lan"
    else:
        scope = "public-or-host"
    return f"{scope}:{port}"


@app.get("/services", dependencies=[Depends(require_admin)])
def services(limit: int = 80):
    """Safe service inventory: listener/process metadata only, no env/cmdline."""
    limit = max(1, min(limit, 200))
    rows_by_key: dict[str, dict[str, Any]] = {}
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError):
        connections = []
    for conn in connections:
        if str(getattr(conn, "status", "") or "") != "LISTEN":
            continue
        local = getattr(conn, "laddr", None)
        endpoint = _safe_addr(local)
        if not endpoint:
            continue
        pid = getattr(conn, "pid", None)
        process_name = _safe_process_name(pid)
        key = process_name
        row = rows_by_key.setdefault(
            key,
            {
                "id": "",
                "name": process_name,
                "status": "listening",
                "kind": "process-listener",
                "listeners": [],
            },
        )
        if endpoint not in row["listeners"]:
            row["listeners"].append(endpoint)
    rows = sorted(rows_by_key.values(), key=lambda item: str(item["name"]))[:limit]
    for index, row in enumerate(rows, start=1):
        row["id"] = f"service-{index:03d}"
    return {"results": rows, "source": "psutil.net_connections", "metadata_only": True}


@app.get("/containers", dependencies=[Depends(require_admin)])
def containers():
    try:
        client = _docker_client()
        rows = []
        for container in client.containers.list(all=True):
            stats = {}
            image_tags = getattr(container.image, "tags", []) or []
            image = ", ".join(str(tag) for tag in image_tags)
            if not image:
                image = str(getattr(container.image, "short_id", "unknown"))
            attrs = getattr(container, "attrs", {})
            if not isinstance(attrs, dict):
                attrs = {}
            if container.status == "running":
                try:
                    stats = _json_safe(container.stats(stream=False))
                except Exception:
                    stats = {}
            rows.append({
                "id": str(getattr(container, "short_id", "")),
                "name": str(getattr(container, "name", "")),
                "image": image,
                "status": str(getattr(container, "status", "unknown")),
                "created": attrs.get("Created"),
                "stats": stats,
            })
        return {"results": rows}
    except Exception as exc:
        return {"results": [], "error": str(exc)}


@app.get("/processes", dependencies=[Depends(require_admin)])
def processes(limit: int = 20):
    limit = max(1, min(limit, 100))
    rows = []
    for proc in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent", "cmdline"]):
        try:
            item = proc.info
            item["cmdline"] = " ".join(item.get("cmdline") or [])[:300]
            rows.append(item)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    rows.sort(key=lambda item: (float(item.get("cpu_percent") or 0), float(item.get("memory_percent") or 0)), reverse=True)
    return {"results": rows[:limit]}


def _journal_errors() -> str:
    commands = [
        ["journalctl", "-p", "3", "-n", "80", "--no-pager"],
        ["sh", "-lc", "docker ps --format '{{.Names}}' | xargs -r -n1 docker logs --tail 40 2>&1"],
    ]
    chunks = []
    for command in commands:
        try:
            result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=8)
            chunks.append(result.stdout or result.stderr)
        except Exception as exc:
            chunks.append(f"{command[0]} unavailable: {exc}")
    return _bounded("\n".join(chunks), 12000)


@app.get("/logs/errors", dependencies=[Depends(require_admin)])
def logs_errors():
    return {"text": _journal_errors()}


def _run_summary(command: list[str]) -> dict[str, Any]:
    try:
        result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=12)
        return {"ok": result.returncode == 0, "output": _bounded(result.stdout or result.stderr, 2000)}
    except Exception as exc:
        return {"ok": False, "output": str(exc)}


@app.get("/packages", dependencies=[Depends(require_admin)])
def packages(request: Request):
    cache = request.app.state.package_cache
    now = time.time()
    if cache["value"] is not None and now - cache["at"] < PACKAGE_CACHE_SECONDS:
        return cache["value"]
    value = {
        "generated_at": now,
        "pip": _run_summary(["python", "-m", "pip", "list", "--outdated", "--format=json"]),
        "npm": _run_summary(["npm", "outdated", "--json"]),
        "apt": _run_summary(["sh", "-lc", "apt list --upgradable 2>/dev/null | head -n 80"]),
    }
    cache["at"] = now
    cache["value"] = value
    return value


@app.get("/backups", dependencies=[Depends(require_admin)])
def backups(request: Request):
    return backup_status(Path(request.app.state.settings.backup_root))
