# Multi-process coordination runbook

## Safety model

The coordination layer combines three controls:

1. Atomic per-tenant lease directories prevent two current owners from mutating the same tenant simultaneously.
2. Every successful lease acquisition increments a durable tenant fencing counter.
3. Encrypted snapshots are stored as token-versioned packages, and readers always select the highest token.

The third control is essential. If a paused process resumes after its lease expires, any late write using its lower token cannot supersede state written by the replacement owner.

## Deployment prerequisites

- All BasitClaw processes must share the same coordination and fenced-data directories.
- The shared filesystem must provide atomic `mkdir` and `rename` semantics.
- Each process or container should use a unique `WORKFORCE_AUDIT_INSTANCE_ID`.
- The lease duration must comfortably exceed the longest synchronous tenant operation.
- Coordination, fenced state, backups, and replicas must use restrictive filesystem permissions.
- Do not enable file-lease coordination on eventually consistent object-store mounts.

## Enable coordination

```bash
WORKFORCE_AUDIT_COORDINATION_MODE=file-lease
WORKFORCE_AUDIT_COORDINATION_DIR=/var/lib/basitclaw/workforce-audit-coordination
WORKFORCE_AUDIT_FENCED_DATA_DIR=/var/lib/basitclaw/workforce-audit-fenced
WORKFORCE_AUDIT_INSTANCE_ID=basitclaw-node-1
WORKFORCE_AUDIT_LEASE_MS=30000
WORKFORCE_AUDIT_ACQUIRE_TIMEOUT_MS=1000
WORKFORCE_AUDIT_LEASE_RETRY_MS=20
WORKFORCE_AUDIT_FENCED_VERSIONS=5
```

Restart one process first, verify `/health` and `/api/workforce-audit/coordination-status`, then roll the remaining processes.

## Operational responses

- `423 WRITE_COORDINATION_BUSY`: another current process owns the tenant lease. Respect `Retry-After`; do not bypass the lock.
- `503 WRITE_COORDINATION_LOST`: the process lost ownership during an operation. Treat the mutation as failed and reload state.
- `503 WRITE_COORDINATION_UNAVAILABLE`: the coordination directory or fencing counter could not be used safely.
- `503 PERSISTENCE_FENCE_REJECTED`: a superseded fencing token attempted to write. Investigate process pauses, mount latency, and lease sizing.

## Monitoring

Monitor:

- coordination health status;
- active and stale lease counts;
- repeated `423` responses;
- fencing-token growth per tenant;
- fenced version retention;
- storage latency against the configured lease duration.

A stale lease is quarantined automatically during takeover. There is intentionally no remote force-unlock endpoint.

## Rollback

To return to one process:

1. Stop all but one application process.
2. Confirm no tenant mutation is running.
3. Keep fenced state and coordination files intact.
4. Set `WORKFORCE_AUDIT_COORDINATION_MODE=disabled` only after the surviving process has been validated.
5. Do not delete fenced versions until an approved backup and recovery test confirms the retained state.

Disabling coordination while multiple writers remain active reintroduces stale overwrite risk.
