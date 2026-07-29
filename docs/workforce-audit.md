# Workforce audit governance boundary

This module separates audit planning readiness from audit conclusions and enforces identity, tenant, durability, traceability, backup, recovery, replication, and drill boundaries.

## Recovery permissions

| Role | Backups | Replicas | Drills | Restore | Manual resilience cycle |
|---|---:|---:|---:|---:|---:|
| audit_viewer | No | No | No | No | No |
| auditor | No | No | No | No | No |
| audit_manager | Create/read/verify | Create/read/verify | Yes | No | No |
| compliance_admin | Create/read/verify | Create/read/verify | Yes | Yes | Yes |

## Backup protocol

1. Ensure the latest tenant state and governance chain are durably committed.
2. Copy the validated encrypted primary envelope into the tenant-hashed backup directory.
3. Write a checksum manifest with key ID, encrypted size, kind, timestamp, and ordering metadata.
4. Fsync and atomically rename both files.
5. Enforce the configured per-tenant retention count.
6. Append `backup.created` to the tenant governance chain and durably commit it.

## Restore protocol

A restore requires a 10–500 character reason, the current governance head, a dry-run, administrator permission, and the exact `RESTORE <backupId>` phrase for execution. The service rejects stale heads, verifies checksum, encryption, tenant binding, and governance integrity, and creates a safety backup before replacement. A failed recovery restores the prior encrypted primary file, business state, and governance chain together.

## Replica protocol

1. Load and verify the source encrypted recovery point.
2. Write the unchanged encrypted snapshot envelope to a tenant-hashed replica directory.
3. Write a manifest containing source time, replica time, key ID, checksum, encrypted size, kind, and ordering metadata.
4. Fsync and atomically rename both files.
5. Enforce per-tenant replica retention.
6. Append `backup.replicated` to the tenant governance chain and durably commit it.
7. Treat a repeated replication request as idempotent after checksum verification.

Replica data is never decrypted for storage. Verification decrypts only through the existing tenant-bound AES-256-GCM inspection path.

## Drill protocol

A drill compares the local recovery-point checksum and decrypted summary with the corresponding replica. A successful drill appends `recovery.drill.completed` with the package ID, checksum, counts, replica time, and governance head. No primary state is replaced.

## Scheduler

The scheduler is disabled when `WORKFORCE_AUDIT_SCHEDULED_BACKUP_MINUTES=0`. When enabled it covers unique tenants represented by configured principals, creates overdue scheduled recovery points, repairs missing latest replicas, and runs overdue drills. Per-tenant failures are isolated and reported as a partial cycle rather than stopping every tenant.

## Recovery and resilience APIs

- `GET|POST /api/workforce-audit/backups`
- `POST /api/workforce-audit/backups/:backupId/verify`
- `POST /api/workforce-audit/backups/:backupId/restore`
- `GET /api/workforce-audit/replicas`
- `POST /api/workforce-audit/backups/:backupId/replicate`
- `POST /api/workforce-audit/replicas/:backupId/verify`
- `GET /api/workforce-audit/resilience-status`
- `POST /api/workforce-audit/recovery-drills`
- `POST /api/workforce-audit/resilience-cycle`

## Error model

- `404 BACKUP_NOT_FOUND` or `REPLICA_NOT_FOUND`: the requested package is absent.
- `409 BACKUP_INTEGRITY_FAILED` or `REPLICA_INTEGRITY_FAILED`: checksum, size, tenant binding, encryption, or source comparison failed.
- `409 RECOVERY_CONFLICT`: the supplied governance head is stale or missing.
- `503 BACKUP_UNAVAILABLE`, `REPLICA_UNAVAILABLE`, or `PERSISTENCE_UNAVAILABLE`: a durable operation could not complete safely.

## Existing durable mutation protocol

Business mutations and their governance events are committed together. Success is returned only after the encrypted primary snapshot is fsynced and atomically renamed. Failed writes roll business state and governance history back together.

## Deployment limitation

The file stores assume one writer process. A replica directory provides independent recovery only when mounted from separately controlled durable storage. Multi-process deployment requires transactional shared persistence or proven distributed locking. Production also needs mount monitoring, alert delivery, managed key custody, retention approval, and isolated recovery exercises.
