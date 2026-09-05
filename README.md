# SystemGate

Read-only local system telemetry API.

SystemGate exposes host, container, package, log, and backup status without adding any write, exec, or mutation endpoint. It is a standalone gate: run it by itself, or let a dashboard such as AgentGate consume it through a server-side proxy.

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

All non-health endpoints are read-only and bounded.

## Security Layers

SystemGate is intentionally narrow. It exists so a local dashboard or agent harness can show operational state without receiving host write access.

- **Read-only API**: there are no write, exec, shell, restart, package-install, file-edit, or Docker mutation endpoints.
- **Admin-key auth**: every endpoint except `/health` requires `X-SystemGate-Key`.
- **PBKDF2 key storage**: the first configured `SYSTEMGATE_ADMIN_KEY` is stored as a PBKDF2 hash under `data/admin-key.pbkdf2`; the raw key is not stored by SystemGate.
- **Server-side proxy friendly**: a dashboard can call SystemGate from its backend so the browser never receives the SystemGate key.
- **Loopback binding**: compose publishes the API on `127.0.0.1:8040` only.
- **Private Docker network**: the standalone compose file uses `systemgate_net` for local service-to-service traffic.
- **Read-only host mounts**: Docker socket is mounted `:ro`, `/proc` is mounted `:ro`, and the backup directory is mounted `:ro`.
- **Bounded outputs**: process, log, package, backup, and container responses are capped so host telemetry cannot become an unbounded data leak.
- **No secret logging**: endpoints return system telemetry only; admin keys and upstream service secrets are not returned in responses.
- **Telemetry only**: SystemGate can observe Docker/container state, process lists, packages, logs, vitals, and backup timestamps, but it cannot change them.

In short: SystemGate is a read-only window, not a remote control.
