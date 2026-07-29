# Workforce audit governance boundary

This module separates audit planning readiness from audit conclusions and enforces identity, credential lifecycle, tenant isolation, fleet-wide API abuse protection, encrypted security evidence, governed outbound alerts, durability, traceability, backup, recovery, replication, drills, and multi-process coordination.

## Permissions

| Role | Backups | Replicas | Drills | Restore | Manual resilience cycle | Coordination | Security controls/events |
|---|---:|---:|---:|---:|---:|---:|---:|
| audit_viewer | No | No | No | No | No | No | No |
| auditor | No | No | No | No | No | No | No |
| audit_manager | Create/read/verify | Create/read/verify | Yes | No | No | Read | No |
| compliance_admin | Create/read/verify | Create/read/verify | Yes | Yes | Yes | Read | Read/export/verify |

Outbound alert dispatch and dead-letter recovery are deployment-operator actions performed with `npm run security-alerts`. They do not grant broader tenant or audit-data access.

## Credential protocol

Production credentials are presented as `keyId.secret`; configuration stores only the key ID, random salt, base64 scrypt hash, subject, tenant, role, lifecycle status, and optional activation/expiry windows. Plaintext records are rejected in production. Retiring or soon-expiring credentials receive rotation headers, while revoked, expired, and premature credentials fail closed.

## API security and evidence protocol

Every workforce-audit API request passes through:

1. a client burst quota;
2. credential and lifecycle validation;
3. a dedicated failed-authentication quota;
4. a credential-and-client read, write, or sensitive-operation quota;
5. role authorisation and tenant isolation.

Shared-file limiter mode stores only SHA-256 identity hashes, uses atomic per-bucket locks and fsynced replacements, recovers stale locks, and fails closed on corrupted buckets. Coordinated production deployments require distributed limiting by default.

Security telemetry records authentication failures, tenant override attempts, permission denials, throttling, and shared-control failures. Raw addresses become keyed fingerprints, and key/secret/token/password/address fields are removed.

When enabled, the durable archive encrypts each redacted event with AES-256-GCM and authenticates a global sequence and hash chain with a separately derived HMAC key. Cross-process appends are serialised. Interrupted head updates recover from segment tails. Retention uses signed anchors and a signed prune journal.

## Outbound security alert protocol

Eligible redacted events are written to a shared durable outbox before network delivery. The policy selects a minimum severity and optional exact event types.

Every request contains a stable delivery ID, timestamp, attempt number, event, and HMAC-SHA256 signature. The receiver must verify the signature and deduplicate by delivery ID. Delivery is at least once.

The outbox protocol:

1. hashes the event identity into a stable delivery ID;
2. deduplicates across pending, in-flight, delivered, and dead-letter states;
3. atomically claims due work under the shared security mutex;
4. signs and sends the redacted event;
5. records a durable receipt for `2xx` responses;
6. retries transient failures with bounded exponential backoff and `Retry-After` support;
7. dead-letters permanent failures or exhausted retries;
8. recovers expired claims after process failure;
9. treats a committed receipt, pending retry, or dead letter as authoritative over an orphaned in-flight claim.

Required delivery participates in readiness. An unavailable outbox or retained dead letter makes the security evidence pipeline unavailable until reviewed. Business mutations remain governed by their own persistence and coordination controls.

## Durable audit mutation protocol

In coordinated mode every mutation atomically acquires the tenant lease, receives the next fencing token, reloads current state and governance history, applies validation, writes a token-versioned encrypted package, verifies ownership, and releases only its own lease. Readers select the highest token, preventing delayed superseded writers from replacing newer state.

## Backup, restore, replica, and drill controls

- Backups copy a validated encrypted primary envelope, write checksum manifests atomically, enforce retention, and append governance evidence.
- Restore requires a reason, current governance head, dry-run, administrator permission, exact confirmation, and a verified safety backup.
- Replicas retain unchanged encrypted packages on a separately controlled target and verify tenant binding, checksum, encryption, and source comparison.
- Drills compare local recovery points with replicas without replacing primary state.
- Scheduled cycles isolate per-tenant failures and acquire tenant leases in coordinated mode.

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

## Error model

- `401 CREDENTIAL_REVOKED`, `CREDENTIAL_EXPIRED`, or `CREDENTIAL_NOT_ACTIVE`: credential lifecycle rejection.
- `409 BACKUP_INTEGRITY_FAILED`, `REPLICA_INTEGRITY_FAILED`, or `SECURITY_ARCHIVE_INTEGRITY_FAILED`: durable evidence is inconsistent.
- `409 RECOVERY_CONFLICT`: the supplied governance head is stale or missing.
- `423 WRITE_COORDINATION_BUSY`: another process owns the tenant write lease.
- `429 RATE_LIMITED`: a configured API policy was exceeded.
- `503 RATE_LIMIT_STORE_UNAVAILABLE`: the distributed quota store could not commit safely.
- `503 SECURITY_ARCHIVE_UNAVAILABLE`: encrypted security evidence could not be committed or read safely.
- `SECURITY_ALERT_DELIVERY_UNAVAILABLE`: the alert outbox or dispatch cycle failed safely and is reported through telemetry and operator commands.
- `503 WRITE_COORDINATION_LOST`, `WRITE_COORDINATION_UNAVAILABLE`, `PERSISTENCE_FENCE_REJECTED`, `BACKUP_UNAVAILABLE`, `REPLICA_UNAVAILABLE`, or `PERSISTENCE_UNAVAILABLE`: another durable boundary failed closed.

## Deployment limitation

File-based coordination, shared quotas, encrypted archives, and alert outboxes require a shared durable filesystem with reliable atomic directory creation and rename. Do not use eventually consistent object-store mounts. Webhook delivery also requires controlled HTTPS egress, receiver-side HMAC verification, replay protection, and delivery-ID deduplication. Automatic archive-key and alert-signing-secret rotation remain future boundaries.
