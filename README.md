# BasitClaw

BasitClaw is a dependency-light Node.js workspace for enterprise workforce internal-audit assurance.

Passes 1–12 established the audit universe, governed engagements and findings, tenant isolation, tamper-evident history, encrypted persistence and recovery, replicas and drills, fenced multi-process writes, lifecycle-managed credentials, fleet-wide security controls, signed alert delivery, key rotation, OIDC federation, and governed SCIM identity lifecycle. Pass 13 adds time-boxed privileged access and controlled break glass. Pass 14 adds encrypted audit evidence, immutable versions, registered finding references, chain-of-custody integrity, legal holds, and governed disposition.

## Requirements

- Node.js 20 or newer
- A shared durable filesystem with reliable atomic `mkdir` and `rename` when shared-file controls are enabled
- An approved OIDC identity provider when bearer authentication is enabled
- An approved SCIM provisioning client when governed identity lifecycle is enabled

## Local setup

```bash
cp .env.example .env
npm install
npm test
npm run lint
npm run build
npm start
```

Open `http://localhost:3000/dashboard/workforce-audit`. Development defaults to the local API key. The dashboard accepts a short-lived OIDC bearer token only after OIDC federation has been configured and `WORKFORCE_AUDIT_AUTH_MODE` is `oidc` or `hybrid`.

## Enterprise identity and provisioning

Authentication modes are `api-key`, `oidc`, and `hybrid`. Hybrid mode supports controlled migration but rejects requests that send both credentials.

```bash
WORKFORCE_AUDIT_AUTH_MODE=oidc
WORKFORCE_AUDIT_OIDC_ISSUER=https://identity.example.com/tenant
WORKFORCE_AUDIT_OIDC_AUDIENCE=workforce-audit-api
WORKFORCE_AUDIT_OIDC_JWKS_URI=https://identity.example.com/tenant/.well-known/jwks.json
WORKFORCE_AUDIT_OIDC_GROUP_ROLE_MAP='{"audit-viewers":"audit_viewer","auditors":"auditor","audit-managers":"audit_manager","compliance-admins":"compliance_admin"}'
WORKFORCE_AUDIT_OIDC_ALLOWED_TENANTS=tenant-acme

WORKFORCE_AUDIT_IDENTITY_ENTITLEMENT_MODE=enforce
WORKFORCE_AUDIT_IDENTITY_STORE_DIR=/var/lib/basitclaw/workforce-audit-identities
WORKFORCE_AUDIT_IDENTITY_STORE_KEYS='{"2026-q3":"<base64-32-byte-key>"}'
WORKFORCE_AUDIT_IDENTITY_STORE_PRIMARY_KEY_ID=2026-q3
WORKFORCE_AUDIT_SCIM_ENABLED=true
```

Generate a separate SCIM credential:

```bash
npm run scim:credential:generate -- scim-2026-q3 enterprise-idp --expires-at 2026-10-31T00:00:00Z --scopes scim:read,scim:write
```

Store the one-time presented SCIM token only in the identity provider or approved secret manager. Put only the generated scrypt record in `WORKFORCE_AUDIT_SCIM_CREDENTIALS`.

Run identity checks:

```bash
npm run identity:check
npm run identity:entitlements -- status
npm run identity:entitlements -- review-status
npm run identity:entitlements -- events 200
```

The resource server validates issuer, audience, signature, token lifetime, tenant, mapped group, and optional ACR/AMR assurance. Raw identity-provider subjects are never persisted. See `docs/identity-federation.md` and `docs/identity-provisioning.md`.

## Just-in-time privileged access

Sensitive permissions can be removed from continuous use and unlocked only through tenant-bound, time-boxed grants with two distinct approvers. Emergency access is separately controlled, short-lived, immediately alerted, and requires post-use review. See `docs/privileged-access.md`.

## Encrypted evidence custody

Enable registered audit evidence in production:

```bash
WORKFORCE_AUDIT_EVIDENCE_MODE=shared-file
WORKFORCE_AUDIT_EVIDENCE_REQUIRED=true
WORKFORCE_AUDIT_EVIDENCE_DIR=/var/lib/basitclaw/workforce-audit-evidence
WORKFORCE_AUDIT_EVIDENCE_KEYS='{"2026-q3":"<base64-32-byte-key>","2026-q2":"<previous-base64-32-byte-key>"}'
WORKFORCE_AUDIT_EVIDENCE_PRIMARY_KEY_ID=2026-q3
```

Evidence content and metadata are AES-256-GCM encrypted. Every item has an immutable `EVD-...` identifier, immutable versions, SHA-256 verification, retention metadata, and a hash-linked custody history. When enabled, findings can reference only active registered evidence or governed fieldwork placeholders; arbitrary links and paths are rejected.

Legal hold, release and disposition require the protected `backup:restore` permission, so the default JIT policy applies. Disposition is refused before retention expiry, during a legal hold, or while any finding references the item. The service commits a durable tombstone before purging bytes and reports `purgePending` if deletion must be repaired.

```bash
npm run evidence:check -- status tenant-acme
npm run evidence:check -- verify tenant-acme
npm run evidence:check -- list tenant-acme 100
```

See `docs/evidence-chain-of-custody.md`.

## API credentials

Production API-key authentication uses `keyId.secret` credentials backed by scrypt hashes:

```bash
npm run credential:generate -- admin-2026-q3 audit-admin tenant-acme compliance_admin 2026-10-31T00:00:00Z
```

Store the presented key in a secret manager and place only the generated record in `WORKFORCE_AUDIT_API_KEYS`.

## Shared API security controls

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

The archive stores redacted events in AES-256-GCM envelopes with a global HMAC chain, crash recovery, signed retention anchors, integrity verification, cursor export, and historical-key verification.

## Signed outbound security alerts

```bash
WORKFORCE_AUDIT_SECURITY_ALERT_MODE=webhook
WORKFORCE_AUDIT_SECURITY_ALERT_REQUIRED=true
WORKFORCE_AUDIT_SECURITY_ALERT_WEBHOOK_URL=https://siem.example.com/hooks/workforce-audit
WORKFORCE_AUDIT_SECURITY_ALERT_SIGNING_SECRETS='{"2026-q3":"<new-long-random-secret>","2026-q2":"<previous-long-random-secret>"}'
WORKFORCE_AUDIT_SECURITY_ALERT_PRIMARY_SIGNING_KEY_ID=2026-q3
WORKFORCE_AUDIT_SECURITY_ALERT_OUTBOX_DIR=/var/lib/basitclaw/workforce-audit-security-alerts
```

Delivery is at least once; receivers verify the key ID, HMAC signature and timestamp, then deduplicate by delivery ID.

```bash
npm run security-alerts -- status
npm run security-alerts -- dispatch 25
npm run security-alerts -- dead-letters 100
npm run security-keys -- status
npm run security-keys -- archive-can-retire 2026-q2
npm run security-keys -- alert-can-retire 2026-q2 --receiver-confirmed
```

## Encrypted persistence and recovery

```bash
WORKFORCE_AUDIT_ENCRYPTION_KEYS='{"2026-q3":"<base64-32-byte-key>","2026-q2":"<previous-base64-key>"}'
WORKFORCE_AUDIT_PRIMARY_KEY_ID=2026-q3
WORKFORCE_AUDIT_DATA_DIR=/var/lib/basitclaw/workforce-audit
WORKFORCE_AUDIT_BACKUP_DIR=/var/lib/basitclaw/workforce-audit-backups
```

Restore is two-stage, checks the current governance head, requires exact confirmation, creates a safety backup, and rolls state and history back together on failure.

## Multi-process coordination and resilience

```bash
WORKFORCE_AUDIT_COORDINATION_MODE=file-lease
WORKFORCE_AUDIT_COORDINATION_DIR=/var/lib/basitclaw/workforce-audit-coordination
WORKFORCE_AUDIT_FENCED_DATA_DIR=/var/lib/basitclaw/workforce-audit-fenced
WORKFORCE_AUDIT_INSTANCE_ID=basitclaw-node-1
```

Every mutation acquires a tenant lease and writes under a monotonically increasing fencing token. A separately mounted replica target, scheduled backups, and non-destructive drills provide recovery evidence.

## Verification

- `npm test` covers audit controls, credentials, OIDC/JWKS, SCIM lifecycle, JIT access, encrypted evidence custody, persistence, recovery, replicas, coordination, quotas, alerts, rotation and readiness.
- `npm run lint` validates runtime syntax.
- `npm run build` verifies required production boundaries and dashboard markers.
- GitHub Actions runs all checks on pull requests and pushes to `main`.

## Deployment boundary

Shared-file controls are unsuitable for eventually consistent object-store mounts. Production still requires managed secret custody, monitored mounts, approved retention, controlled egress, authoritative HR and access-approval systems, an identity provider that issues and revokes tokens, receivers that verify alert signatures, malware and DLP scanning for uploaded evidence, external WORM/object-lock storage where required, and regular recovery, custody and access-review exercises.
