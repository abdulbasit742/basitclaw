# Workforce audit governance boundary

This module separates audit planning readiness from audit conclusions and enforces identity, credential and evidence-key lifecycle, tenant isolation, fleet-wide abuse protection, encrypted security evidence, governed outbound alerts, durability, traceability, backup, recovery, replication, drills, and multi-process coordination.

## Permissions

| Role | Backups | Replicas | Drills | Restore | Manual resilience cycle | Coordination | Security controls/events |
|---|---:|---:|---:|---:|---:|---:|---:|
| audit_viewer | No | No | No | No | No | No | No |
| auditor | No | No | No | No | No | No | No |
| audit_manager | Create/read/verify | Create/read/verify | Yes | No | No | Read | No |
| compliance_admin | Create/read/verify | Create/read/verify | Yes | Yes | Yes | Read | Read/export/verify |

Alert dispatch, dead-letter recovery, and exact key-retirement checks are deployment-operator actions. Public HTTP responses expose readiness and counts but not filesystem paths, key IDs, or secret material.

## Credential protocol

Production credentials are presented as `keyId.secret`; configuration stores only scrypt hashes, subject, tenant, role, lifecycle state, and optional activation/expiry windows. Retiring credentials receive rotation headers; revoked, expired, and premature credentials fail closed.

## API security and evidence protocol

Every request passes through client burst limits, credential lifecycle validation, failed-authentication pressure limits, read/write/sensitive-operation quotas, role authorisation, and tenant isolation.

Shared-file quotas store only SHA-256 identity hashes and use atomic locks, fsynced replacements, stale-lock recovery, capacity controls, and fail-closed corruption handling.

Telemetry records security-control events after replacing raw addresses with keyed fingerprints and removing secrets. The durable archive encrypts redacted events with AES-256-GCM and authenticates a global sequence and hash chain. Cross-process appends are serialised; interrupted head updates recover from segment tails; retention uses signed anchors and a signed prune journal.

## Security evidence key lifecycle

Archive encryption uses a keyring with one primary key for new envelopes and retained historical keys for old envelopes, anchors, and prune journals. Each envelope carries an authenticated key ID, while the hash chain remains continuous across key changes.

The lifecycle inspector acquires the same archive mutex as writers and verifies every retained reference before reporting a key retirement-safe. It refuses retirement when inspection is unavailable, the key is primary, a retained reference exists, or required historical material cannot be verified.

Webhook signing uses an overlap keyring. Outbound requests include the primary signing key ID. A non-primary signing key is not retirement-safe until an operator explicitly confirms receiver overlap completion.

Operator controls:

- `npm run security-keys -- status`
- `npm run security-keys -- archive-can-retire <keyId>`
- `npm run security-keys -- alert-can-retire <keyId> --receiver-confirmed`

## Outbound security alert protocol

Eligible redacted events enter a shared durable outbox before network delivery. The policy selects minimum severity and optional exact event types. Each request contains delivery ID, timestamp, signing key ID, attempt number, event, and HMAC-SHA256 signature.

The receiver verifies the selected key, timestamp, and signature and deduplicates by delivery ID. Delivery is at least once. Transient failures retry with bounded backoff and `Retry-After`; permanent or exhausted failures dead-letter; expired claims recover; committed destination state wins over orphaned in-flight claims.

Required delivery participates in readiness. Business mutations remain governed by their own persistence and coordination controls.

## Durable audit mutation protocol

In coordinated mode every mutation acquires a tenant lease, receives the next fencing token, reloads current state and history, applies validation, writes a token-versioned encrypted package, verifies ownership, and releases only its own lease. Readers select the highest token, preventing superseded writers from replacing newer state.

## Backup, restore, replica, and drill controls

- Backups copy validated encrypted primary envelopes, write checksum manifests atomically, enforce retention, and append governance evidence.
- Restore requires a reason, current governance head, dry-run, administrator permission, exact confirmation, and safety backup.
- Replicas retain unchanged encrypted packages on a separately controlled target.
- Drills compare local recovery points with replicas without replacing primary state.
- Scheduled cycles isolate tenant failures and acquire tenant leases in coordinated mode.

## APIs and operator controls

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
- `GET /api/workforce-audit/security-archive-events`
- `GET /api/workforce-audit/security-archive-integrity`
- `npm run security-alerts -- status|dispatch|dead-letters|requeue`
- `npm run security-keys -- status|archive-can-retire|alert-can-retire`

## Error model

- `401 CREDENTIAL_REVOKED`, `CREDENTIAL_EXPIRED`, or `CREDENTIAL_NOT_ACTIVE`: credential lifecycle rejection.
- `409 BACKUP_INTEGRITY_FAILED`, `REPLICA_INTEGRITY_FAILED`, or `SECURITY_ARCHIVE_INTEGRITY_FAILED`: durable evidence is inconsistent.
- `409 RECOVERY_CONFLICT`: supplied governance head is stale or missing.
- `423 WRITE_COORDINATION_BUSY`: another process owns the tenant write lease.
- `429 RATE_LIMITED`: an API policy was exceeded.
- `503 RATE_LIMIT_STORE_UNAVAILABLE`: distributed quota storage failed safely.
- `503 SECURITY_ARCHIVE_UNAVAILABLE`: encrypted evidence could not be committed or read safely.
- `SECURITY_ALERT_DELIVERY_UNAVAILABLE`: alert delivery failed safely and is reported through telemetry and operator commands.
- Missing or still-referenced security keys fail retirement checks closed.

## Deployment limitation

File coordination, shared quotas, archives, and alert outboxes require durable storage with reliable atomic directory creation and rename. Webhook delivery also requires controlled HTTPS egress, receiver-side key-ID selection, HMAC verification, replay protection, and deduplication. Managed secret generation, distribution, and change approvals remain external responsibilities.
