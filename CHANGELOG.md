# Changelog

Versions are the module's own, not an API revision. A change to the shape of
`/health` or any endpoint is a contract change and gets its own entry —
replacing a module has to be a decision with visible consequences.

## Unreleased

## 0.2.3

- **Backup telemetry reads the mounted location and verifies what it reports.**
  It looked under a path that did not exist in the container, and treated any
  directory as a backup, choosing the latest by modification time — so an
  incomplete snapshot could be shown as the newest recovery point. It now reads
  the real backup root, verifies manifests and hashes, and reports incomplete or
  unreadable snapshots separately.


- Align the container backup root with its `/backups` mount. Verify complete
  `conker-snapshot-1` manifests, inventories, hashes and archives before listing
  recovery candidates. Select latest by manifest creation time; report rejected
  candidates and unavailable roots explicitly. Integrity verification is separate
  from restore readiness, deletion replay and action reconciliation.

## 0.2.2

- **`/health` reported `0.1.0` while the module shipped as v0.2.1.** The
  version was hardcoded in the FastAPI constructor, where nothing pointed at
  it during a release. It is a named constant now, so `/health` and the
  OpenAPI document cannot drift apart again. A health contract is only worth
  having if it can be believed.
- **`.dockerignore`, and a CI job that builds the image and searches it for
  secrets.** This build context was already clean; ToolGate's was not, and
  shipped a real `.env` to the registry. The check belongs in every module,
  because the next leak will be in whichever repository nobody thought to
  look at.

## 0.2.1

Publish workflow only: attestation is skipped while the repository is private,
so a successful image push is no longer reported as a failure.

## 0.2.0

**`/vitals` was describing the container, not the host.** `docker-compose.yml`
mounted `/proc` at `/host/proc`, but nothing referenced it: psutil resolves
procfs from a module attribute and honours **no** environment variable for it,
so the mount sat inert while every figure came from this container. Setting
`PROCFS_PATH` in compose looked correct and did nothing. SystemGate now assigns
`psutil.PROCFS_PATH` in code from `SYSTEMGATE_PROCFS_PATH`, mounts the host root
read-only for disk figures, and shares the host UTS namespace so the hostname is
the host's — `/proc/sys/kernel/hostname` resolves from the reading process's
namespace, not from the mount, so bind-mounting alone could never fix it.

**`/vitals` now reports `source`** — the procfs and disk paths in use, read back
from psutil rather than from configuration, and whether the scope is `host` or
`container`. Either is legitimate; leaving the caller to guess which produced a
number is not.

**`/health` probed nothing.** It returned a hardcoded `ok`, so a broken Docker
socket left `/containers` failing while health claimed all was well. It now
probes procfs, the Docker socket and the admin key store, and reports `degraded`
naming what failed. Detail stays coarse because the route is unauthenticated.

**`/health` now answers in the shared module contract shape** — `service`,
`version`, `status`, `degraded`, `checks` keyed by name, `checked_at`,
`age_seconds` — so one dashboard renders any module without special cases.

**README corrected.** `/services` was undocumented, making eight endpoints not
seven. The "no shell" claim overstated the code: package and log collection do
shell out, to a fixed non-injectable command set, which is a stronger statement
than a slogan that does not survive reading the source. The host root mount is
documented as the trade-off it is.

## 0.1.0

First release. Read-only host telemetry: health, vitals, containers, processes,
error logs, packages, backups, services. Admin-key auth on every route except
`/health`, PBKDF2 key storage, loopback binding, bounded outputs.
