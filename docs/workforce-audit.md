# Workforce audit governance boundary

This module separates audit planning readiness from audit conclusions and enforces identity, tenant, durability, traceability, backup, recovery, replication, drill, and multi-process coordination boundaries.

## Recovery permissions

| Role | Backups | Replicas | Drills | Restore | Manual resilience cycle | Coordination status |
|---|---:|---:|---:|---:|---:|---:|
| audit_viewer | No | No | No | No | No | No |
| auditor | No | No | No | No | No | No |
| audit_manager | Create/read/verify | Create/read/verify | Yes | No | No | Yes |
| compliance_admin | Create/read/verify | Create/read/verify | Yes | Yes | Yes | Yes |

## Durable mutation protocol

In single-process mode, business mutations and governance events are committed together to the encrypted tenant snapshot. In coordinated mode, every mutation additionally:

1. atomically acquires the tenant lease;
2. receives the next durable fencing token;
3. reloads the latest encrypted state and governance chain;
4. applies and validates the requested mutation;
5. writes a token-versioned encrypted package;
6. verifies lease ownership before returning success;
7. releases only the lease owned by the same instance and token.

Readers always select the highest fencing token. A delayed writer using an older token cannot become the current tenant state even if it resumes after stale-lease takeover.

## Backup protocol

1. Ensure the latest tenant state and governance chain are durably committed.
2. Copy the validated encrypted primary envelope into the tenant-hashed backup directory.
3. Write a checksum manifest with key ID, encrypted size, kind, timestamp, and ordering metadata.
4. Fsync and atomically rename both files.
5. Enforce the configured per-tenant retention count.
6. Append `backup.created` to the tenant governance chain and durably commit it.

## Restore protocol

A restore requires a 10–500 character reason, the current governance head, a dry-run, administrator permission, and the exact `RESTORE <backupId>` phrase for execution. The service rejects stale heads, verifies checksum, encryption, tenant binding, and governance integrity, and creates a safety backup before replacement. In coordinated mode the entire execution runs under one tenant lease and is re-encrypted under its current fencing token. A failed recovery restores the prior business state and governance chain together.

## Replica protocol

1. Load and verify the source encrypted recovery point.
2. Write the unchanged encrypted snapshot envelope to a tenant-hashed replica directory.
3. Write a manifest containing source time, replica time, key ID, checksum, encrypted size, kind, and ordering metadata.
4. Fsync and atomically rename both files.
5. Enforce per-tenant replica retention.
6. Append `backup.replicated` to the tenant governance chain and durably commit it.
7. Treat a repeated replication request as idempotent after checksum verification.

Replica data is never decrypted for storage. Verification decrypts only through the existing tenant-bound AES-256-GCM inspection path.

## Drill and scheduler protocol

A drill compares the local recovery-point checksum and decrypted summary with the corresponding replica. A successful drill appends `recovery.drill.completed`; no primary state is replaced.

The scheduler is disabled when `WORKFORCE_AUDIT_SCHEDULED_BACKUP_MINUTES=0`. When enabled it covers unique tenants represented by configured principals. In coordinated mode each tenant cycle acquires its own lease, so one busy or failed tenant does not stop the remaining cycle.

## APIs

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

## Error model

- `404 BACKUP_NOT_FOUND` or `REPLICA_NOT_FOUND`: the requested package is absent.
- `409 BACKUP_INTEGRITY_FAILED` or `REPLICA_INTEGRITY_FAILED`: checksum, size, tenant binding, encryption, or source comparison failed.
- `409 RECOVERY_CONFLICT`: the supplied governance head is stale or missing.
- `423 WRITE_COORDINATION_BUSY`: another process owns the tenant lease; clients should respect `Retry-After`.
- `503 WRITE_COORDINATION_LOST` or `WRITE_COORDINATION_UNAVAILABLE`: lease ownership or shared coordination storage failed.
- `503 PERSISTENCE_FENCE_REJECTED`: a superseded fencing token attempted a durable write.
- `503 BACKUP_UNAVAILABLE`, `REPLICA_UNAVAILABLE`, or `PERSISTENCE_UNAVAILABLE`: another durable operation could not complete safely.

## Deployment limitation

File-lease coordination supports multiple processes only on shared durable filesystems with reliable atomic directory creation and rename. Do not use it on eventually consistent object-store mounts. A replica directory provides independent recovery only when mounted from separately controlled durable storage. Production also needs mount monitoring, alert delivery, managed key custody, retention approval, and isolated recovery exercises.
