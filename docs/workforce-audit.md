# Workforce audit governance boundary

This module separates audit planning readiness from audit conclusions and enforces identity, tenant, durability, traceability, backup, and recovery boundaries.

## Recovery permissions

| Role | List/verify backups | Create backups | Restore backups |
|---|---:|---:|---:|
| audit_viewer | No | No | No |
| auditor | No | No | No |
| audit_manager | Yes | Yes | No |
| compliance_admin | Yes | Yes | Yes |

## Backup protocol

1. Ensure the latest tenant state and governance chain are durably committed.
2. Read and decrypt-validate the primary snapshot.
3. Copy the encrypted envelope to the tenant-hashed backup directory.
4. Write a manifest containing the backup ID, tenant hash, key ID, checksum, encrypted size, creation order, and backup kind.
5. Fsync each file, atomically rename it, and attempt to fsync the directory.
6. Enforce the configured per-tenant retention count.
7. Append a `backup.created` governance event with actor, reason, checksum, key ID, and any pruned backup IDs.

Backup manifests contain operational metadata only. Audit business data remains encrypted inside the copied AES-256-GCM envelope.

## Restore protocol

A restore request must include:

- a reason containing 10 to 500 characters;
- the current governance head hash;
- a dry-run first;
- for execution, `dryRun: false`;
- the exact phrase `RESTORE <backupId>`;
- a principal with `backup:restore`.

The service rejects stale governance heads with `409 RECOVERY_CONFLICT`. Before an actual restore it creates a `safety` backup. The selected backup is checksum-verified, decrypted, tenant-bound, and governance-chain validated. After replacement, a `backup.restored` event records the source and safety backup. If any stage fails, the original encrypted primary file, business state, and governance events are restored.

## Recovery APIs

- `GET /api/workforce-audit/backups`
- `POST /api/workforce-audit/backups`
- `POST /api/workforce-audit/backups/:backupId/verify`
- `POST /api/workforce-audit/backups/:backupId/restore`

## Error model

- `404 BACKUP_NOT_FOUND`: the requested recovery point is absent.
- `409 BACKUP_INTEGRITY_FAILED`: checksum, encryption, tenant binding, or snapshot validation failed.
- `409 RECOVERY_CONFLICT`: the supplied governance head is stale or missing.
- `503 BACKUP_UNAVAILABLE`: the backup subsystem cannot safely complete the operation.
- `503 PERSISTENCE_UNAVAILABLE`: the primary encrypted snapshot cannot be committed.

## Existing durable mutation protocol

Business mutations and their governance events are committed together. The service returns success only after the encrypted primary snapshot is fsynced and atomically renamed. A failed write rolls back both business state and governance history.

## Deployment limitation

The file store assumes one writer process. Horizontal scaling requires a transactional shared persistence layer or proven distributed locking. Backups should also be replicated off-host, monitored, retention-approved, and exercised through scheduled disaster-recovery tests.
