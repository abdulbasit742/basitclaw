# Workforce audit governance boundary

This module separates audit planning readiness from audit conclusions and enforces identity, tenant, durability, traceability, backup, recovery, replication, and drill boundaries.

## Recovery permissions

| Role | Backups | Replicas | Drills | Restore | Manual resilience cycle |
|---|---:|---:|---:|---:|---:|
| audit_viewer | No | No | No | No | No |
| auditor | No | No | No | No | No |
| audit_manager | Create/read/verify | Create/read/verify | Yes | No | No |
| compliance_admin | Create/read/verify | Create/read/verify | Yes | Yes | Yes |

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

## Resilience APIs

- `GET /api/workforce-audit/resilience-status`
- `GET /api/workforce-audit/replicas`
- `POST /api/workforce-audit/backups/:backupId/replicate`
- `POST /api/workforce-audit/replicas/:backupId/verify`
- `POST /api/workforce-audit/recovery-drills`
- `POST /api/workforce-audit/resilience-cycle`

## Error model

- `404 REPLICA_NOT_FOUND`: the requested replica is absent.
- `409 REPLICA_INTEGRITY_FAILED`: checksum, size, tenant binding, encryption, or source comparison failed.
- `503 REPLICA_UNAVAILABLE`: the replica target cannot safely complete the operation.
- Existing backup, recovery-conflict, and persistence errors remain unchanged.

## Deployment limitation

The file stores assume one writer process. A replica directory provides independent recovery only when mounted from separately controlled durable storage. Multi-process deployment requires transactional shared persistence or proven distributed locking. Production also needs mount monitoring, alert delivery, managed key custody, and isolated recovery exercises.
