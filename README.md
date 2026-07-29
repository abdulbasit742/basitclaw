# BasitClaw

BasitClaw is a dependency-light Node.js workspace for enterprise workforce internal-audit assurance.

Passes 1–7 established the audit universe, governed engagements and findings, tenant isolation, tamper-evident history, encrypted persistence, recovery points, replicas, resilience drills, fenced multi-process writes, lifecycle-managed credentials, throttling, and privacy-minimised telemetry. Pass 8 adds fleet-wide file-backed rate limits and an encrypted, durable, hash-chained security-event archive.

## Requirements

- Node.js 20 or newer
- A shared durable filesystem with reliable atomic `mkdir` and `rename` when shared-file coordination or security controls are enabled

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

## Credentials

Production uses `keyId.secret` credentials backed by scrypt hashes. Generate one with:

```bash
npm run credential:generate -- admin-2026-q3 audit-admin tenant-acme compliance_admin 2026-10-31T00:00:00Z
```

Store the presented key in a secret manager and place only the generated record in `WORKFORCE_AUDIT_API_KEYS`. Retiring or soon-expiring credentials receive a rotation header; revoked, expired, and premature credentials fail closed.

## Shared API security controls

The limiter separates bursts, failed authentication, reads, writes, and sensitive recovery operations. Single-process deployments may use `memory`; coordinated production deployments require `shared-file` by default:

```bash
WORKFORCE_AUDIT_RATE_LIMIT_MODE=shared-file
WORKFORCE_AUDIT_RATE_LIMIT_DIR=/var/lib/basitclaw/workforce-audit-rate-limits
WORKFORCE_AUDIT_DISTRIBUTED_RATE_LIMIT_REQUIRED=true
```

The encrypted security archive mirrors redacted events into AES-256-GCM envelopes with a global HMAC chain, crash recovery, signed retention anchors, and cursor-based export:

```bash
WORKFORCE_AUDIT_SECURITY_ARCHIVE_MODE=shared-file
WORKFORCE_AUDIT_SECURITY_ARCHIVE_REQUIRED=true
WORKFORCE_AUDIT_SECURITY_ARCHIVE_DIR=/var/lib/basitclaw/workforce-audit-security-archive
WORKFORCE_AUDIT_SECURITY_ARCHIVE_KEY=<base64-32-byte-key>
```

Compliance administrators can inspect:

- `GET /api/workforce-audit/security-status`
- `GET /api/workforce-audit/security-events`
- `GET /api/workforce-audit/security-archive-events?afterSequence=0`
- `GET /api/workforce-audit/security-archive-integrity`

Client identities are represented by keyed fingerprints, and raw keys, secrets, passwords, tokens, and addresses are not archived. See `docs/api-security.md` for rollout, recovery, and SIEM polling guidance.

## Encrypted persistence and recovery

```bash
WORKFORCE_AUDIT_ENCRYPTION_KEYS='{"2026-q3":"<base64-32-byte-key>","2026-q2":"<previous-base64-key>"}'
WORKFORCE_AUDIT_PRIMARY_KEY_ID=2026-q3
WORKFORCE_AUDIT_DATA_DIR=/var/lib/basitclaw/workforce-audit
WORKFORCE_AUDIT_BACKUP_DIR=/var/lib/basitclaw/workforce-audit-backups
```

Primary snapshots and recovery points remain AES-256-GCM encrypted. Restore is two-stage, checks the current governance head, requires exact confirmation, creates a safety backup, and rolls state and history back together on failure.

## Multi-process coordination

```bash
WORKFORCE_AUDIT_COORDINATION_MODE=file-lease
WORKFORCE_AUDIT_COORDINATION_DIR=/var/lib/basitclaw/workforce-audit-coordination
WORKFORCE_AUDIT_FENCED_DATA_DIR=/var/lib/basitclaw/workforce-audit-fenced
WORKFORCE_AUDIT_INSTANCE_ID=basitclaw-node-1
```

Every mutation acquires an exclusive tenant lease and writes under a monotonically increasing fencing token. A delayed superseded writer cannot replace newer state.

## Resilience

A separately mounted replica target, scheduled backups, and non-destructive drills provide recovery evidence. A path counts as independent disaster recovery only when mounted from separately controlled durable storage.

## Verification

- `npm test` covers audit controls, access, persistence, recovery, replicas, coordination, credential lifecycle, shared quotas, encrypted archive integrity, crash recovery, retention anchors, and API readiness.
- `npm run lint` validates runtime syntax.
- `npm run build` verifies all required production boundaries and dashboard markers.
- GitHub Actions runs all three checks on pull requests and pushes to `main`.

## Deployment boundary

Shared-file controls are unsuitable for eventually consistent object-store mounts. The archive export supports SIEM polling but does not yet push alerts outbound. Production still needs managed key custody, monitored mounts, approved retention, external alert routing, and regular isolated recovery exercises.
