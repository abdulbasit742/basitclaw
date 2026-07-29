# Resilience operations

## Replica target

`WORKFORCE_AUDIT_REPLICA_DIR` enables encrypted replica packages. In production this path should be a separately controlled mounted volume or storage gateway; setting another directory on the same disk does not provide off-host protection.

A replica contains the already encrypted snapshot envelope plus a tenant-hashed manifest. Replication never writes decrypted audit content. Every package is checksum-verified and decrypted through the existing tenant-bound AES-256-GCM validation path during a drill.

## Scheduler

Set `WORKFORCE_AUDIT_SCHEDULED_BACKUP_MINUTES` above zero to enable the internal scheduler. The scheduler covers unique tenants represented by configured API-key principals. It creates a scheduled recovery point when the latest scheduled backup exceeds the interval, repairs a missing latest replica, and performs a non-destructive drill when the latest successful drill exceeds `WORKFORCE_AUDIT_DRILL_MAX_AGE_DAYS`.

The scheduler is disabled by default. It starts when the HTTP server begins listening and stops when the server closes. Its timer is unreferenced so it cannot prevent clean process shutdown.

## Health expectations

- `replicas.status=ready`: the target directory is accessible.
- `replicaHealth.status=ready`: the tenant has a replica within the configured lag objective.
- `replicaHealth.status=missing`: replication is required but no package exists.
- `replicaHealth.status=stale`: the latest package exceeds the lag objective.
- `drill.status=missing|stale`: a verified drill is required.

When `WORKFORCE_AUDIT_REPLICATION_REQUIRED=true`, the public health endpoint becomes degraded if the replica subsystem is unavailable. Per-tenant lag and drill freshness are exposed through the authenticated resilience-status endpoint.

## APIs

- `GET /api/workforce-audit/resilience-status`
- `GET /api/workforce-audit/replicas`
- `POST /api/workforce-audit/backups/:backupId/replicate`
- `POST /api/workforce-audit/replicas/:backupId/verify`
- `POST /api/workforce-audit/recovery-drills`
- `POST /api/workforce-audit/resilience-cycle`

Audit managers may inspect and replicate packages and run drills. Only compliance administrators may manually run the complete resilience cycle.
