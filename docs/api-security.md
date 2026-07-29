# Workforce-audit API security runbook

## Credential format and lifecycle

Development may use a legacy plaintext `apiKey` record. Production rejects plaintext records and requires `keyId.secret` credentials backed by a random salt and base64 scrypt hash. Generate one with:

```bash
npm run credential:generate -- admin-2026-q3 audit-admin tenant-acme compliance_admin 2026-10-31T00:00:00Z
```

Store the presented key in a secret manager and place only the generated record in `WORKFORCE_AUDIT_API_KEYS`. `active` credentials are accepted inside their time window, `retiring` credentials receive `x-api-key-rotation-required: true`, and revoked, expired, or premature credentials fail closed with explicit 401 codes.

Rotate by adding a replacement as `active`, marking the old credential `retiring`, updating clients, and then marking the old credential `revoked`.

## Rate-limit modes

The limiter separates client bursts, failed authentication, authenticated reads, authenticated writes, and sensitive recovery operations. Exceeded limits return `429 RATE_LIMITED`, `Retry-After`, and standard rate-limit headers.

Available modes:

- `memory`: process-local fixed windows for single-process development or defence in depth.
- `shared-file`: fleet-wide fixed windows stored on a shared durable filesystem.
- `disabled`: accepted only when distributed enforcement is not required.

A coordinated production deployment requires `shared-file` by default. The shared store uses atomic per-bucket locks, hashed identities, fsynced replacement files, stale-lock recovery, bounded bucket capacity, and fail-closed corruption handling. Raw client addresses and credential values are never written to bucket files.

```bash
WORKFORCE_AUDIT_RATE_LIMIT_MODE=shared-file
WORKFORCE_AUDIT_RATE_LIMIT_DIR=/var/lib/basitclaw/workforce-audit-rate-limits
WORKFORCE_AUDIT_DISTRIBUTED_RATE_LIMIT_REQUIRED=true
```

Use shared-file mode only on storage with reliable atomic `mkdir` and `rename`. Do not use eventually consistent object-store mounts.

## Trusted proxy handling

`WORKFORCE_AUDIT_TRUST_PROXY_HOPS=0` is the safe default and uses the direct socket address. Increase it only when the application is behind exactly that many controlled reverse proxies. An incorrect value can allow spoofed forwarding data or group unrelated clients together.

## Security telemetry and encrypted archive

The in-memory event buffer records failed credential use, permission denial, tenant override attempts, throttling, and shared-control failures. It stores keyed client fingerprints, strips key/secret/token/password/address fields, and maintains a bounded local hash chain.

For durable fleet-wide evidence, enable the encrypted archive:

```bash
WORKFORCE_AUDIT_SECURITY_ARCHIVE_MODE=shared-file
WORKFORCE_AUDIT_SECURITY_ARCHIVE_REQUIRED=true
WORKFORCE_AUDIT_SECURITY_ARCHIVE_DIR=/var/lib/basitclaw/workforce-audit-security-archive
WORKFORCE_AUDIT_SECURITY_ARCHIVE_KEY_ID=security-archive-v1
WORKFORCE_AUDIT_SECURITY_ARCHIVE_KEY=<base64-32-byte-key>
WORKFORCE_AUDIT_SECURITY_ARCHIVE_RETENTION_DAYS=90
```

The archive provides:

- AES-256-GCM encrypted event envelopes;
- an HMAC-authenticated global sequence and hash chain;
- atomic cross-process appends;
- recovery when a segment write committed but the head update was interrupted;
- signed retention anchors after old segments are pruned;
- a signed prune journal for roll-forward or rollback after interruption;
- integrity verification and cursor-based export for SIEM polling.

The archive key is independent from the workforce-audit data key. Keep it in managed secret custody. Changing or losing the key makes retained archive segments unverifiable; automatic archive-key rotation is not yet implemented.

## APIs and permissions

Only `compliance_admin` has `security:read`:

- `GET /api/workforce-audit/security-status`
- `GET /api/workforce-audit/security-events?limit=100&type=<type>&severity=<severity>`
- `GET /api/workforce-audit/security-archive-events?afterSequence=0&limit=100`
- `GET /api/workforce-audit/security-archive-integrity`

The archive export response includes `nextSequence` for cursor polling. Public `/health` reports readiness but removes storage paths, lock directories, and archive key identifiers.

## Failure responses

- `429 RATE_LIMITED`: a policy was exceeded.
- `503 RATE_LIMIT_STORE_UNAVAILABLE`: a shared quota could not be updated safely.
- `409 SECURITY_ARCHIVE_INTEGRITY_FAILED`: encrypted evidence, its sequence, signature, or retention anchor is inconsistent.
- `503 SECURITY_ARCHIVE_UNAVAILABLE`: the archive filesystem or lock could not complete safely.

A required archive or required shared limiter degrades `/health` to 503. Do not bypass a damaged control to restore readiness; preserve the files, investigate integrity, and recover from approved evidence.

## Deployment checklist

1. Generate high-entropy credentials and store presented keys in a secret manager.
2. Remove plaintext `apiKey` records before production.
3. Configure expiry windows and a rotation owner.
4. Validate trusted proxy depth.
5. Mount rate-limit and archive directories on a qualifying shared durable filesystem.
6. Configure a stable telemetry pepper and managed archive key.
7. Enable required flags only after verifying shared mounts from every process.
8. Test cross-process quotas, archive export, integrity, `429`, and degraded `/health` behaviour.
9. Poll archive events into the organisation's SIEM and retain the returned cursor externally.
10. Never force-delete locks, bucket files, archive segments, anchors, or prune journals during an incident.
