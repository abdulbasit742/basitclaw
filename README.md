# BasitClaw

BasitClaw is a dependency-light Node.js workspace for enterprise workforce internal-audit assurance.

Passes 1–4 established the audit universe, governed engagements and findings, tenant-scoped access, tamper-evident history, encrypted durable state, and governed backup/restore controls. Pass 5 adds encrypted replica targets, replication lag monitoring, scheduled recovery-point orchestration, non-destructive recovery drills, resilience APIs, and a GitHub Actions quality gate.

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

## Resilience configuration

Primary snapshots and recovery points remain AES-256-GCM encrypted. To add a separately controlled replica target:

```bash
WORKFORCE_AUDIT_REPLICA_DIR=/mnt/off-host/workforce-audit-replicas
WORKFORCE_AUDIT_REPLICA_RETENTION=90
WORKFORCE_AUDIT_REPLICATION_REQUIRED=true
WORKFORCE_AUDIT_REPLICA_MAX_LAG_MINUTES=2880
WORKFORCE_AUDIT_SCHEDULED_BACKUP_MINUTES=1440
WORKFORCE_AUDIT_DRILL_MAX_AGE_DAYS=30
```

The scheduler is disabled when `WORKFORCE_AUDIT_SCHEDULED_BACKUP_MINUTES=0`. A filesystem path only counts as off-host protection when the deployment mounts it from independently controlled durable storage.

## Access model

- `audit_manager`: read resilience state, create and verify backups, create and verify replicas, and run non-destructive drills.
- `compliance_admin`: all manager permissions plus restore execution and manual resilience-cycle execution.

## Verification

- `npm test` covers audit rules, access control, encrypted persistence, backups, restore safeguards, replica integrity, scheduler behaviour, lag monitoring, and drills.
- `npm run lint` performs syntax validation.
- `npm run build` verifies the runtime, recovery, and resilience boundaries.
- `.github/workflows/ci.yml` runs all three checks on pull requests and pushes to `main`.

## Deployment boundary

The primary, backup, and replica file stores still assume one writer process. A replica directory on the same host is not independent disaster recovery. Multi-process deployment requires shared transactional persistence or proven distributed locking; production also needs managed key custody, monitored storage mounts, alert routing, and regular isolated recovery exercises.
