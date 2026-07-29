# BasitClaw

BasitClaw is a dependency-light Node.js workspace for enterprise workforce internal-audit assurance.

Pass 1 established the HR audit universe, engagement planning, fieldwork placeholders, findings, provider readiness, APIs, and dashboard. Pass 2 added API-key authentication, role permissions, tenant isolation, and a tamper-evident governance ledger. Pass 3 added encrypted durable snapshots, atomic commits, restart recovery, key rotation support, and persistence rollback. Pass 4 adds encrypted recovery points, integrity manifests, retention, restore dry-runs, safety backups, and governed disaster-recovery operations.

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

## Access configuration

Configure `WORKFORCE_AUDIT_API_KEYS` as a JSON array:

```json
[{"apiKey":"replace-with-a-long-random-key","subject":"audit-manager","tenantId":"tenant-acme","role":"audit_manager"}]
```

Supported roles are `audit_viewer`, `auditor`, `audit_manager`, and `compliance_admin`. Audit managers may create and verify recovery points. Only compliance administrators may execute a restore.

## Encrypted persistence and recovery

Production requires a JSON keyring containing base64-encoded 32-byte keys and a primary key ID:

```bash
WORKFORCE_AUDIT_ENCRYPTION_KEYS='{"2026-q3":"<base64-32-byte-key>","2026-q2":"<previous-base64-key>"}'
WORKFORCE_AUDIT_PRIMARY_KEY_ID=2026-q3
WORKFORCE_AUDIT_DATA_DIR=/var/lib/basitclaw/workforce-audit
WORKFORCE_AUDIT_BACKUP_DIR=/var/lib/basitclaw/workforce-audit-backups
WORKFORCE_AUDIT_BACKUP_RETENTION=30
```

Primary snapshots and recovery points remain AES-256-GCM encrypted. Backup filenames use tenant hashes rather than tenant IDs. Every backup has a manifest containing its checksum, key ID, encrypted size, creation order, and retention class.

Restore is deliberately two-stage:

1. Run a dry-run using the current governance head hash.
2. Review the backup summary and integrity result.
3. Submit the same governance head hash, `dryRun: false`, and the exact confirmation phrase `RESTORE <backupId>`.
4. The service creates a safety backup before replacing the primary snapshot.
5. The restored governance chain receives a `backup.restored` event referencing the safety backup.
6. Any failure restores the original encrypted primary snapshot and in-memory governance state.

## Recovery APIs

- `GET /api/workforce-audit/backups`
- `POST /api/workforce-audit/backups`
- `POST /api/workforce-audit/backups/:backupId/verify`
- `POST /api/workforce-audit/backups/:backupId/restore`

## Verification

- `npm test` covers access control, audit rules, encrypted storage, key rotation, restart recovery, backups, retention, checksum tampering, dry-run recovery, safety copies, role restrictions, and governance-chain restoration.
- `npm run lint` performs syntax validation.
- `npm run build` verifies the complete runtime and recovery boundary.

## Current production boundary

The encrypted file and backup stores assume one writer process on a durable filesystem. Multi-process deployment still requires shared transactional persistence or distributed locking. Managed key custody, off-host backup replication, scheduled backup orchestration, rate limiting, retention policy approval, and regular disaster-recovery exercises remain deployment responsibilities.
