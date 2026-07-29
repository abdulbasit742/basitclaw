# BasitClaw

BasitClaw is a dependency-light Node.js workspace for enterprise workforce internal-audit assurance.

Pass 1 established the HR audit universe, engagement planning, fieldwork placeholders, findings, provider readiness, APIs, and dashboard. Pass 2 added API-key authentication, role permissions, tenant isolation, and a tamper-evident governance ledger. Pass 3 adds encrypted durable snapshots, atomic commits, restart recovery, key identifiers for rotation, storage health reporting, and mutation rollback when persistence fails.

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

Supported roles are `audit_viewer`, `auditor`, `audit_manager`, and `compliance_admin`. The authenticated principal determines the tenant; callers cannot override it.

## Encrypted persistence

Production requires a JSON keyring containing base64-encoded 32-byte keys and a primary key ID:

```bash
WORKFORCE_AUDIT_ENCRYPTION_KEYS='{"2026-q3":"<base64-32-byte-key>","2026-q2":"<previous-base64-key>"}'
WORKFORCE_AUDIT_PRIMARY_KEY_ID=2026-q3
WORKFORCE_AUDIT_DATA_DIR=/var/lib/basitclaw/workforce-audit
```

The primary key encrypts every new snapshot. Previous keys may remain in the keyring so older snapshots can be read and rewritten with the new primary key. Do not remove an old key until all tenant snapshots have been rewritten and verified.

Snapshots are tenant-separated, AES-256-GCM encrypted, bound to authenticated envelope metadata, written to a temporary file, fsynced, and atomically renamed. A failed durable write rolls back both the business mutation and its governance event.

## Verification

- `npm test` covers access control, audit rules, encrypted storage, key rotation, restart recovery, rollback, tenant isolation, governance integrity, and HTTP behaviour.
- `npm run lint` performs syntax validation.
- `npm run build` verifies the complete runtime boundary.

## Current production boundary

The encrypted file store is suitable for a single application process with a durable filesystem. Multi-process deployment still requires a shared transactional database or distributed lock, central identity federation, managed key custody, automated backups, retention controls, rate limiting, and disaster-recovery exercises.
