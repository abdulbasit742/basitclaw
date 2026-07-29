# BasitClaw

BasitClaw is a dependency-light Node.js workspace for enterprise workforce internal-audit assurance.

Passes 1–6 established the audit universe, governed engagements and findings, tenant access controls, tamper-evident history, encrypted persistence, governed recovery, encrypted replicas, resilience drills, CI, and fenced multi-process coordination. Pass 7 adds lifecycle-managed scrypt API credentials, adaptive abuse controls, privacy-minimised security telemetry, credential-generation tooling, and security readiness APIs.

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

## API credential configuration

Legacy plaintext `apiKey` records remain available only outside production for migration compatibility. Production uses `keyId.secret` credentials backed by scrypt hashes:

```bash
npm run credential:generate -- admin-2026-q3 audit-admin tenant-acme compliance_admin 2026-10-31T00:00:00Z
```

The generator prints the presented key once and a configuration record containing `keyId`, `salt`, `secretHash`, subject, tenant, role, status, and optional expiry. Store the presented key in a secret manager and place only the record in `WORKFORCE_AUDIT_API_KEYS`.

The authenticated principal determines the tenant; callers cannot override it. `active` and `retiring` credentials are accepted within their activation and expiry windows. Retiring or soon-expiring credentials receive `x-api-key-rotation-required: true`. Revoked, expired, and premature credentials fail closed.

## API abuse protection

The built-in limiter separates client bursts, failed authentication, authenticated reads, authenticated writes, and sensitive recovery operations. Exceeded limits return `429 RATE_LIMITED` with `Retry-After` and standard rate-limit headers.

The built-in limiter is process-local and reports `distributed: false`. Multi-process deployments must also enforce a shared limit at the ingress gateway or service mesh. Keep `WORKFORCE_AUDIT_TRUST_PROXY_HOPS=0` unless the exact trusted proxy chain is known.

Compliance administrators can inspect:

- `GET /api/workforce-audit/security-status`
- `GET /api/workforce-audit/security-events`

Security events retain keyed client fingerprints, not raw addresses. API keys, secrets, passwords, and tokens are removed from details. See `docs/api-security.md` for rotation and deployment procedures.

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

## Recovery, resilience, coordination, and security APIs

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
- `GET /api/workforce-audit/security-status`
- `GET /api/workforce-audit/security-events`

## Verification

- `npm test` covers audit rules, access control, encrypted persistence, backups, restore safeguards, replicas, scheduler behaviour, leases, fencing, credential lifecycle, limiter policies, telemetry redaction, and server security responses.
- `npm run lint` performs syntax validation.
- `npm run build` verifies the runtime, recovery, resilience, coordination, and API-security boundaries.
- `.github/workflows/ci.yml` runs all three checks on pull requests and pushes to `main`.

## Deployment boundary

File-lease coordination requires a correctly configured shared filesystem with atomic `mkdir` and `rename`. The built-in rate limiter and security event buffer are process-local; production still needs global ingress limits, central alert delivery and SIEM retention, managed key custody, monitored mounts, approved retention, and regular isolated recovery exercises.
