# BasitClaw

BasitClaw is a dependency-light Node.js workspace for enterprise workforce internal-audit assurance.

Passes 1–5 established the audit universe, governed engagements and findings, tenant access controls, tamper-evident history, encrypted persistence, governed recovery, encrypted replicas, resilience drills, and CI. Pass 6 adds opt-in multi-process coordination using atomic tenant leases, monotonic fencing tokens, fresh state per operation, and versioned encrypted snapshots that reject superseded writers.

## Requirements

- Node.js 20 or newer

## Local setup

```bash
cp .env.example .env
npm install
npm test
npm run lint
npm run build
npm start
```

Open `http://localhost:3000/dashboard/workforce-audit` and enter the local development key from `.env`.

## Access configuration

Configure `WORKFORCE_AUDIT_API_KEYS` as a JSON array:

```json
[{"apiKey":"replace-with-a-long-random-key","subject":"audit-manager","tenantId":"tenant-acme","role":"audit_manager"}]
```

The authenticated principal determines the tenant; callers cannot override it. Audit managers can inspect write coordination and operate backups, replicas, and non-destructive drills. Compliance administrators additionally control restore execution and manual resilience cycles.

## Encrypted persistence and recovery

Production requires a JSON keyring containing base64-encoded 32-byte keys and a primary key ID:

```bash
WORKFORCE_AUDIT_ENCRYPTION_KEYS='{"2026-q3":"<base64-32-byte-key>","2026-q2":"<previous-base64-key>"}'
WORKFORCE_AUDIT_PRIMARY_KEY_ID=2026-q3
WORKFORCE_AUDIT_DATA_DIR=/var/lib/basitclaw/workforce-audit
WORKFORCE_AUDIT_BACKUP_DIR=/var/lib/basitclaw/workforce-audit-backups
WORKFORCE_AUDIT_BACKUP_RETENTION=30
```

Primary snapshots and recovery points remain AES-256-GCM encrypted. Restore remains two-stage: dry-run with the current governance head, then an administrator request using the fresh head and exact `RESTORE <backupId>` confirmation. A verified safety backup is created before replacement, and failed recovery rolls the primary envelope, business state, and governance chain back together.

## Multi-process coordination

Coordination is disabled by default. Enable it only when every application process shares a filesystem that provides atomic directory creation and rename semantics:

```bash
WORKFORCE_AUDIT_COORDINATION_MODE=file-lease
WORKFORCE_AUDIT_COORDINATION_DIR=/var/lib/basitclaw/workforce-audit-coordination
WORKFORCE_AUDIT_FENCED_DATA_DIR=/var/lib/basitclaw/workforce-audit-fenced
WORKFORCE_AUDIT_INSTANCE_ID=basitclaw-node-1
WORKFORCE_AUDIT_LEASE_MS=30000
WORKFORCE_AUDIT_ACQUIRE_TIMEOUT_MS=1000
WORKFORCE_AUDIT_FENCED_VERSIONS=5
```

Every mutation acquires an exclusive tenant lease, reloads the latest encrypted snapshot and governance chain, and writes under a monotonically increasing fencing token. Readers select the highest token, so a paused process that resumes after lease takeover cannot replace newer state. Busy writes return `423 WRITE_COORDINATION_BUSY` with `Retry-After`; lost or unavailable leases fail closed.

## Resilience configuration

To add a separately controlled encrypted replica target and scheduled exercises:

```bash
WORKFORCE_AUDIT_REPLICA_DIR=/mnt/off-host/workforce-audit-replicas
WORKFORCE_AUDIT_REPLICA_RETENTION=90
WORKFORCE_AUDIT_REPLICATION_REQUIRED=true
WORKFORCE_AUDIT_REPLICA_MAX_LAG_MINUTES=2880
WORKFORCE_AUDIT_SCHEDULED_BACKUP_MINUTES=1440
WORKFORCE_AUDIT_DRILL_MAX_AGE_DAYS=30
```

The scheduler is disabled when `WORKFORCE_AUDIT_SCHEDULED_BACKUP_MINUTES=0`. A filesystem path only counts as independent disaster-recovery protection when the deployment mounts it from separately controlled durable storage.

## Recovery, resilience, and coordination APIs

- `GET|POST /api/workforce-audit/backups`
- `POST /api/workforce-audit/backups/:backupId/verify`
- `POST /api/workforce-audit/backups/:backupId/restore`
- `GET /api/workforce-audit/replicas`
- `POST /api/workforce-audit/backups/:backupId/replicate`
- `POST /api/workforce-audit/replicas/:backupId/verify`
- `GET /api/workforce-audit/resilience-status`
- `POST /api/workforce-audit/recovery-drills`
- `POST /api/workforce-audit/resilience-cycle`
- `GET /api/workforce-audit/coordination-status`

## Verification

- `npm test` covers audit rules, access control, encrypted persistence, backups, restore safeguards, replica integrity, scheduler behaviour, leases, stale takeover, fencing rejection, and cross-process state refresh.
- `npm run lint` performs syntax validation.
- `npm run build` verifies the runtime, recovery, resilience, and coordination boundaries.
- `.github/workflows/ci.yml` runs all three checks on pull requests and pushes to `main`.

## Deployment boundary

File-lease coordination supports multiple processes only when they share a correctly configured durable filesystem with atomic `mkdir` and `rename`. It is not a substitute for a transactional database across unreliable or eventually consistent storage. Production also needs managed key custody, monitored mounts, alert routing, retention approval, and regular isolated recovery exercises.
