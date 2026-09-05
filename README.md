# SystemGate

Read-only local system telemetry API.

SystemGate exposes host, container, package, log, and backup status without adding any write, exec, or mutation endpoint. It is a standalone gate: run it by itself, or let a dashboard such as Conker consume it through a server-side proxy.

## Run

```bash
cp .env.example .env
docker compose up -d --build
```

API: `http://127.0.0.1:8040`

Authenticated endpoints require `X-SystemGate-Key: <SYSTEMGATE_ADMIN_KEY>`.

By default the standalone compose file creates `systemgate_net` and mounts `~/systemgate-backups` read-only. Larger stacks can mount a different backup directory with `SYSTEMGATE_BACKUP_ROOT`.

## Endpoints

- `GET /health`
- `GET /vitals`
- `GET /containers`
- `GET /processes`
- `GET /logs/errors`
- `GET /packages`
- `GET /backups`
- `GET /services` — listening processes, metadata only (no pid, cmdline, env or user)

All non-health endpoints are read-only, bounded, and require the admin key.

`GET /health` takes no key and runs real dependency probes — procfs, the Docker socket and the
admin key store. It reports `degraded` with the failing dependency named, never a hardcoded `ok`.
Probe detail is deliberately coarse because the endpoint is unauthenticated.

## Security Layers

SystemGate is intentionally narrow. It exists so a local dashboard or agent harness can show operational state without receiving host write access.

- **Read-only API**: there are no write, exec, restart, package-install, file-edit, or Docker mutation endpoints. Package and log collection shell out to a fixed, non-injectable command set; no caller input reaches a shell.
- **Admin-key auth**: every endpoint except `/health` requires `X-SystemGate-Key`.
- **PBKDF2 key storage**: the first configured `SYSTEMGATE_ADMIN_KEY` is stored as a PBKDF2 hash under `data/admin-key.pbkdf2`; the raw key is not stored by SystemGate.
- **Server-side proxy friendly**: a dashboard can call SystemGate from its backend so the browser never receives the SystemGate key.
- **Loopback binding**: compose publishes the API on `127.0.0.1:8040` only.
- **Private Docker network**: the standalone compose file uses `systemgate_net` for local service-to-service traffic.
- **Read-only host mounts**: the Docker socket, `/proc`, the host root and the backup directory are all mounted `:ro`.
- **The host root mount is a deliberate trade-off, stated plainly**: reporting the host's disk usage requires the host filesystem to be visible, so `/` is mounted at `/host/root` read-only. This is what host telemetry exporters do, and it means anything able to read files from inside this container can read any file on the host. SystemGate exposes no file-read endpoint, and adding one would turn this mount into a serious hole. Drop the mount if you would rather have container-scoped disk figures; `/vitals` will say `scope: container` and remain truthful.
- **Says which machine it measured**: `/vitals` reports `source.scope` as `host` or `container`, with the procfs and disk paths actually in use - read back from psutil, not from the configuration, so it reports where the numbers came from rather than where they were asked to come from. Host figures require `SYSTEMGATE_PROCFS_PATH=/host/proc`, the host root mount and `uts: host`, all set by the bundled compose file. psutil honours no environment variable for procfs redirection, so SystemGate assigns `psutil.PROCFS_PATH` itself at import; setting an environment variable alone silently does nothing.
- **Bounded outputs**: process, log, package, backup, and container responses are capped so host telemetry cannot become an unbounded data leak.
- **No secret logging**: endpoints return system telemetry only; admin keys and upstream service secrets are not returned in responses.
- **Telemetry only**: SystemGate can observe Docker/container state, process lists, packages, logs, vitals, and backup timestamps, but it cannot change them.

In short: SystemGate is a read-only window, not a remote control.
