# BasitClaw

BasitClaw is a dependency-light Node.js workspace for enterprise workforce internal-audit assurance.

Passes 1–9 established the audit universe, governed engagements and findings, tenant isolation, tamper-evident history, encrypted persistence and recovery, replicas and drills, fenced multi-process writes, lifecycle-managed API credentials, fleet-wide throttling, encrypted security evidence, and governed signed alert delivery. Pass 10 adds rotation-safe archive and webhook keyrings, historical verification, retirement safeguards, and key-lifecycle operator tooling.

## Requirements

- Node.js 20 or newer
- A shared durable filesystem with reliable atomic `mkdir` and `rename` when shared-file coordination, security controls, or alert delivery are enabled

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

Coordinated production deployments use fleet-wide rate limits and encrypted event evidence:

```bash
WORKFORCE_AUDIT_RATE_LIMIT_MODE=shared-file
WORKFORCE_AUDIT_RATE_LIMIT_DIR=/var/lib/basitclaw/workforce-audit-rate-limits
WORKFORCE_AUDIT_DISTRIBUTED_RATE_LIMIT_REQUIRED=true

WORKFORCE_AUDIT_SECURITY_ARCHIVE_MODE=shared-file
WORKFORCE_AUDIT_SECURITY_ARCHIVE_REQUIRED=true
WORKFORCE_AUDIT_SECURITY_ARCHIVE_DIR=/var/lib/basitclaw/workforce-audit-security-archive
WORKFORCE_AUDIT_SECURITY_ARCHIVE_KEYS='{"2026-q3":"<base64-32-byte-key>","2026-q2":"<previous-base64-32-byte-key>"}'
WORKFORCE_AUDIT_SECURITY_ARCHIVE_PRIMARY_KEY_ID=2026-q3
```

The archive stores already-redacted events in AES-256-GCM envelopes with a global HMAC chain, crash recovery, signed retention anchors, integrity verification, cursor export, and historical-key verification.

## Signed outbound security alerts

Enable policy-driven webhook delivery with a shared durable outbox and an overlap signing keyring:

```bash
WORKFORCE_AUDIT_SECURITY_ALERT_MODE=webhook
WORKFORCE_AUDIT_SECURITY_ALERT_REQUIRED=true
WORKFORCE_AUDIT_SECURITY_ALERT_WEBHOOK_URL=https://siem.example.com/hooks/workforce-audit
WORKFORCE_AUDIT_SECURITY_ALERT_SIGNING_SECRETS='{"2026-q3":"<new-long-random-secret>","2026-q2":"<previous-long-random-secret>"}'
WORKFORCE_AUDIT_SECURITY_ALERT_PRIMARY_SIGNING_KEY_ID=2026-q3
WORKFORCE_AUDIT_SECURITY_ALERT_OUTBOX_DIR=/var/lib/basitclaw/workforce-audit-security-alerts
WORKFORCE_AUDIT_SECURITY_ALERT_MIN_SEVERITY=high
```

Requests carry a stable delivery ID, timestamp, signing key ID, and HMAC-SHA256 signature. Delivery is at least once; receivers must select the matching key, verify the signature and timestamp, and deduplicate by delivery ID. Retryable failures use bounded backoff and `Retry-After`; permanent or exhausted failures move to a durable dead-letter queue.

Operator commands:

```bash
npm run security-alerts -- status
npm run security-alerts -- dispatch 25
npm run security-alerts -- dead-letters 100
npm run security-alerts -- requeue ALERT-0123456789abcdef0123456789abcdef

npm run security-keys -- status
npm run security-keys -- archive-can-retire 2026-q2
npm run security-keys -- alert-can-retire 2026-q2 --receiver-confirmed
```

See `docs/api-security.md`, `docs/security-alert-delivery.md`, and `docs/security-key-rotation.md` for rollout, verification, retirement, incident response, and recovery procedures.

## Encrypted persistence and recovery

```bash
WORKFORCE_AUDIT_ENCRYPTION_KEYS='{"2026-q3":"<base64-32-byte-key>","2026-q2":"<previous-base64-key>"}'
WORKFORCE_AUDIT_PRIMARY_KEY_ID=2026-q3
WORKFORCE_AUDIT_DATA_DIR=/var/lib/basitclaw/workforce-audit
WORKFORCE_AUDIT_BACKUP_DIR=/var/lib/basitclaw/workforce-audit-backups
```

Primary snapshots and recovery points remain AES-256-GCM encrypted. Restore is two-stage, checks the current governance head, requires exact confirmation, creates a safety backup, and rolls state and history back together on failure.

## Multi-process coordination and resilience

```bash
WORKFORCE_AUDIT_COORDINATION_MODE=file-lease
WORKFORCE_AUDIT_COORDINATION_DIR=/var/lib/basitclaw/workforce-audit-coordination
WORKFORCE_AUDIT_FENCED_DATA_DIR=/var/lib/basitclaw/workforce-audit-fenced
WORKFORCE_AUDIT_INSTANCE_ID=basitclaw-node-1
```

Every mutation acquires a tenant lease and writes under a monotonically increasing fencing token. A separately mounted replica target, scheduled backups, and non-destructive drills provide recovery evidence.

## Security inspection APIs

Compliance administrators can inspect:

- `GET /api/workforce-audit/security-status`
- `GET /api/workforce-audit/security-events`
- `GET /api/workforce-audit/security-archive-events?afterSequence=0`
- `GET /api/workforce-audit/security-archive-integrity`

The security status response includes alert delivery, dead-letter, and redacted key-rotation readiness. Exact key IDs, references, and retirement decisions remain local operator information.

## Verification

- `npm test` covers audit controls, access, persistence, recovery, replicas, coordination, credential lifecycle, shared quotas, archive integrity, mixed-key evidence, signed alert delivery, cross-process claims, retry/dead-letter recovery, retirement safeguards, and readiness.
- `npm run lint` validates runtime syntax.
- `npm run build` verifies required production boundaries and dashboard markers.
- GitHub Actions runs all three checks on pull requests and pushes to `main`.

## Deployment boundary

Shared-file controls are unsuitable for eventually consistent object-store mounts. Production still requires managed secret custody, monitored mounts, approved retention, controlled egress, receivers that verify signatures and deduplicate deliveries, and regular recovery exercises. Key generation and secret-manager distribution remain external change-management responsibilities.
