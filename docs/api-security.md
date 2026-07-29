# Workforce-audit API security runbook

## Credential format and lifecycle

Development may use a legacy plaintext `apiKey` record. Production rejects plaintext records and requires `keyId.secret` credentials backed by a random salt and base64 scrypt hash. Generate one with:

```bash
npm run credential:generate -- admin-2026-q3 audit-admin tenant-acme compliance_admin 2026-10-31T00:00:00Z
```

Store the presented key in a secret manager and place only the generated record in `WORKFORCE_AUDIT_API_KEYS`. `active` credentials are accepted inside their time window, `retiring` credentials receive `x-api-key-rotation-required: true`, and revoked, expired, or premature credentials fail closed.

## Rate-limit modes

The limiter separates client bursts, failed authentication, authenticated reads, authenticated writes, and sensitive recovery operations. Exceeded limits return `429 RATE_LIMITED`, `Retry-After`, and standard rate-limit headers.

- `memory`: process-local defence in depth.
- `shared-file`: fleet-wide fixed windows on a qualifying shared filesystem.
- `disabled`: accepted only when distributed enforcement is not required.

```bash
WORKFORCE_AUDIT_RATE_LIMIT_MODE=shared-file
WORKFORCE_AUDIT_RATE_LIMIT_DIR=/var/lib/basitclaw/workforce-audit-rate-limits
WORKFORCE_AUDIT_DISTRIBUTED_RATE_LIMIT_REQUIRED=true
```

Shared mode uses hashed identities, atomic per-bucket locks, fsynced replacements, stale-lock recovery, bounded capacity, and fail-closed corruption handling. Do not use eventually consistent object-store mounts.

## Trusted proxy handling

`WORKFORCE_AUDIT_TRUST_PROXY_HOPS=0` uses the direct socket address. Increase it only when the application is behind exactly that many controlled reverse proxies.

## Security telemetry and encrypted archive

Telemetry stores keyed client fingerprints, removes key/secret/token/password/address fields, and maintains a bounded local hash chain. Durable evidence uses an overlap archive keyring:

```bash
WORKFORCE_AUDIT_SECURITY_ARCHIVE_MODE=shared-file
WORKFORCE_AUDIT_SECURITY_ARCHIVE_REQUIRED=true
WORKFORCE_AUDIT_SECURITY_ARCHIVE_DIR=/var/lib/basitclaw/workforce-audit-security-archive
WORKFORCE_AUDIT_SECURITY_ARCHIVE_KEYS='{"2026-q3":"<base64-32-byte-key>","2026-q2":"<previous-base64-32-byte-key>"}'
WORKFORCE_AUDIT_SECURITY_ARCHIVE_PRIMARY_KEY_ID=2026-q3
WORKFORCE_AUDIT_SECURITY_ARCHIVE_RETENTION_DAYS=90
```

New AES-256-GCM envelopes use the primary key. Historical envelopes carry authenticated key IDs and remain readable while their keys stay configured. The global hash chain remains continuous across rotation. Retention anchors and interrupted prune journals are verified against the key that signed them.

Use `npm run security-keys -- status` to inspect exact key references. Never remove an archive key until `npm run security-keys -- archive-can-retire <keyId>` returns `safe: true`.

Legacy `WORKFORCE_AUDIT_SECURITY_ARCHIVE_KEY` remains supported and reports `legacy-single-key` readiness.

## Signed webhook alert delivery

Eligible already-redacted events are persisted before network delivery:

```bash
WORKFORCE_AUDIT_SECURITY_ALERT_MODE=webhook
WORKFORCE_AUDIT_SECURITY_ALERT_REQUIRED=true
WORKFORCE_AUDIT_SECURITY_ALERT_WEBHOOK_URL=https://siem.example.com/hooks/workforce-audit
WORKFORCE_AUDIT_SECURITY_ALERT_SIGNING_SECRETS='{"2026-q3":"<new-long-random-secret>","2026-q2":"<previous-long-random-secret>"}'
WORKFORCE_AUDIT_SECURITY_ALERT_PRIMARY_SIGNING_KEY_ID=2026-q3
WORKFORCE_AUDIT_SECURITY_ALERT_OUTBOX_DIR=/var/lib/basitclaw/workforce-audit-security-alerts
WORKFORCE_AUDIT_SECURITY_ALERT_MIN_SEVERITY=high
```

Requests include delivery ID, Unix timestamp, `x-basitclaw-key-id`, and `x-basitclaw-signature`. Receivers select the matching secret, verify HMAC over `timestamp + "." + raw_body`, enforce timestamp freshness, and deduplicate by delivery ID.

Delivery is at least once. `2xx` creates a receipt; transient failures retry with bounded backoff and `Retry-After`; permanent or exhausted failures dead-letter; expired claims recover after process failure.

Signing-key retirement requires receiver overlap confirmation:

```bash
npm run security-keys -- alert-can-retire 2026-q2
npm run security-keys -- alert-can-retire 2026-q2 --receiver-confirmed
```

The first command remains unsafe until external receiver checks are complete. See `docs/security-alert-delivery.md` and `docs/security-key-rotation.md`.

## APIs and operator commands

Only `compliance_admin` has `security:read`:

- `GET /api/workforce-audit/security-status`
- `GET /api/workforce-audit/security-events?limit=100&type=<type>&severity=<severity>`
- `GET /api/workforce-audit/security-archive-events?afterSequence=0&limit=100`
- `GET /api/workforce-audit/security-archive-integrity`

Local operator commands:

```bash
npm run security-alerts -- status
npm run security-alerts -- dispatch 25
npm run security-alerts -- dead-letters 100
npm run security-alerts -- requeue ALERT-0123456789abcdef0123456789abcdef
npm run security-keys -- status
```

HTTP responses expose key counts and rotation readiness, not key IDs, filesystem paths, or secret material.

## Failure and readiness behaviour

- `429 RATE_LIMITED`: a policy was exceeded.
- `503 RATE_LIMIT_STORE_UNAVAILABLE`: a shared quota could not be updated safely.
- `409 SECURITY_ARCHIVE_INTEGRITY_FAILED`: encrypted evidence or its retention chain is inconsistent.
- `503 SECURITY_ARCHIVE_UNAVAILABLE`: the archive filesystem or lock failed safely.
- `SECURITY_ALERT_DELIVERY_UNAVAILABLE`: alert outbox or dispatch failed safely.
- Missing historical archive keys make lifecycle inspection unavailable and must be restored from approved custody.

A required limiter, archive, or alert-delivery control degrades `/health` to `503`. Do not delete durable control files or bypass integrity checks to restore readiness.

## Deployment checklist

1. Generate and protect API credentials.
2. Validate trusted proxy depth.
3. Mount rate-limit, archive, and alert-outbox directories on qualifying shared storage.
4. Configure a stable telemetry pepper and independent managed keyrings.
5. Add new keys everywhere before switching primary IDs.
6. Verify receiver key-ID selection, signatures, timestamps, and delivery-ID deduplication.
7. Exercise mixed-key archive reads and signed webhook overlap.
8. Use lifecycle retirement checks before deleting any historical key.
9. Retain SIEM archive cursors externally.
10. Never force-delete locks, buckets, archive segments, pending alerts, receipts, or dead letters during an incident.
