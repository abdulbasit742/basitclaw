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

The archive provides AES-256-GCM event envelopes, an HMAC-authenticated global chain, atomic cross-process appends, interrupted-head recovery, signed retention anchors, a signed prune journal, integrity verification, and cursor export.

The archive key is independent from the workforce-audit data key. Keep it in managed secret custody. Changing or losing the key makes retained segments unverifiable; automatic archive-key rotation is not implemented yet.

## Signed webhook alert delivery

The alert subsystem consumes the already-redacted telemetry event. Eligible events are persisted before delivery and sent through a shared durable outbox:

```bash
WORKFORCE_AUDIT_SECURITY_ALERT_MODE=webhook
WORKFORCE_AUDIT_SECURITY_ALERT_REQUIRED=true
WORKFORCE_AUDIT_SECURITY_ALERT_WEBHOOK_URL=https://siem.example.com/hooks/workforce-audit
WORKFORCE_AUDIT_SECURITY_ALERT_SIGNING_SECRET=<at-least-32-random-bytes>
WORKFORCE_AUDIT_SECURITY_ALERT_OUTBOX_DIR=/var/lib/basitclaw/workforce-audit-security-alerts
WORKFORCE_AUDIT_SECURITY_ALERT_MIN_SEVERITY=high
```

An empty `WORKFORCE_AUDIT_SECURITY_ALERT_TYPES` value sends every event meeting the severity threshold. A comma-separated value restricts delivery to exact event types.

Requests include a stable delivery ID, Unix timestamp, and `x-basitclaw-signature: sha256=<HMAC>`. The receiver verifies the HMAC over `timestamp + "." + raw_body`, checks timestamp freshness, and deduplicates by delivery ID.

Delivery is at least once:

- `2xx` creates a durable receipt;
- `408`, `425`, `429`, `5xx`, timeouts, and network failures retry;
- `Retry-After` is honoured within the configured maximum;
- other `4xx` responses dead-letter immediately;
- exhausted retries dead-letter;
- stale claims recover after process failure;
- a committed receipt or dead letter wins over a leftover in-flight claim.

Production endpoints must use HTTPS. Redirects and URL user information are rejected. Literal local/private targets are blocked unless explicitly approved. DNS rebinding remains an infrastructure concern, so enforce outbound egress and DNS policy.

See `docs/security-alert-delivery.md` for receiver verification and incident response.

## Security APIs and operator commands

Only `compliance_admin` has `security:read`:

- `GET /api/workforce-audit/security-status`
- `GET /api/workforce-audit/security-events?limit=100&type=<type>&severity=<severity>`
- `GET /api/workforce-audit/security-archive-events?afterSequence=0&limit=100`
- `GET /api/workforce-audit/security-archive-integrity`

Alert operations use the local authenticated deployment environment:

```bash
npm run security-alerts -- status
npm run security-alerts -- dispatch 25
npm run security-alerts -- dead-letters 100
npm run security-alerts -- requeue ALERT-0123456789abcdef0123456789abcdef
```

The archive export includes `nextSequence` for cursor polling. HTTP health and security-status responses remove storage and lock paths; the local CLI retains full diagnostics.

## Failure and readiness behaviour

- `429 RATE_LIMITED`: a policy was exceeded.
- `503 RATE_LIMIT_STORE_UNAVAILABLE`: a shared quota could not be updated safely.
- `409 SECURITY_ARCHIVE_INTEGRITY_FAILED`: encrypted evidence or its retention chain is inconsistent.
- `503 SECURITY_ARCHIVE_UNAVAILABLE`: the archive filesystem or lock failed safely.
- `SECURITY_ALERT_DELIVERY_UNAVAILABLE`: the alert outbox or dispatch cycle could not complete safely; it is reported by the CLI and telemetry status.

A required shared limiter, archive, or alert-delivery control degrades `/health` to `503`. A retained dead letter degrades required alert delivery until it is reviewed and resolved. Do not bypass a damaged control to restore readiness; preserve files and investigate.

## Deployment checklist

1. Generate high-entropy API credentials and store presented keys in a secret manager.
2. Remove plaintext `apiKey` records before production.
3. Configure credential expiry and rotation ownership.
4. Validate trusted proxy depth.
5. Mount rate-limit, archive, and alert-outbox directories on a qualifying shared filesystem.
6. Configure a stable telemetry pepper, managed archive key, and separate webhook signing secret.
7. Verify the receiver's signature, timestamp, and delivery-ID deduplication.
8. Enable required flags only after every process can use the shared mounts and receiver.
9. Test cross-process quotas, archive integrity, signed delivery, retry, dead-letter, and degraded readiness.
10. Poll archive events into the SIEM and retain the cursor externally even when push delivery is enabled.
11. Never force-delete locks, buckets, archive segments, pending alerts, receipts, or dead letters during an incident.
