# Signed security alert delivery runbook

## Purpose and delivery model

The security alert subsystem forwards privacy-minimised security events to an approved webhook without making business requests depend on receiver availability. Eligible events are written to a shared durable outbox before delivery. Delivery is **at least once**: receivers must deduplicate using `x-basitclaw-delivery-id`.

Only the event produced after telemetry sanitisation is queued. Raw client addresses, API keys, secrets, passwords, and tokens are not included.

## Production configuration

```bash
WORKFORCE_AUDIT_SECURITY_ALERT_MODE=webhook
WORKFORCE_AUDIT_SECURITY_ALERT_REQUIRED=true
WORKFORCE_AUDIT_SECURITY_ALERT_WEBHOOK_URL=https://siem.example.com/hooks/workforce-audit
WORKFORCE_AUDIT_SECURITY_ALERT_SIGNING_SECRETS='{"2026-q3":"<new-long-random-secret>","2026-q2":"<previous-long-random-secret>"}'
WORKFORCE_AUDIT_SECURITY_ALERT_PRIMARY_SIGNING_KEY_ID=2026-q3
WORKFORCE_AUDIT_SECURITY_ALERT_OUTBOX_DIR=/var/lib/basitclaw/workforce-audit-security-alerts
WORKFORCE_AUDIT_SECURITY_ALERT_MIN_SEVERITY=high
WORKFORCE_AUDIT_SECURITY_ALERT_TYPES=
WORKFORCE_AUDIT_SECURITY_ALERT_MAX_ATTEMPTS=8
WORKFORCE_AUDIT_SECURITY_ALERT_POLL_INTERVAL_MS=5000
```

The outbox must be shared by every application process and provide reliable atomic `mkdir` and `rename`. Do not use eventually consistent object-store mounts.

An empty event-type setting sends every event at or above the configured severity. A comma-separated value restricts delivery to exact types.

Legacy `WORKFORCE_AUDIT_SECURITY_ALERT_SIGNING_SECRET` remains available for migration but reports single-key rotation readiness.

## Webhook request

Each request body contains version, delivery ID, emitted time, attempt number, and the redacted event. Headers include:

- `x-basitclaw-delivery-id`: stable deduplication identifier;
- `x-basitclaw-timestamp`: Unix timestamp in seconds;
- `x-basitclaw-key-id`: signing-key identifier;
- `x-basitclaw-signature`: `sha256=<hex HMAC>`;
- `content-type`: `application/json; charset=utf-8`.

The receiver selects the secret associated with `x-basitclaw-key-id` and verifies the exact raw body:

```text
HMAC-SHA256(selected_signing_secret, timestamp + "." + raw_body)
```

Compare signatures in constant time. Reject unknown key IDs and timestamps outside the approved replay window. Retain delivery IDs for at least the maximum retry and requeue period.

## Signing-key rotation

1. Add the new key ID and secret to sender and receiver keyrings.
2. Confirm the receiver accepts the new key while the old key remains primary.
3. Switch `WORKFORCE_AUDIT_SECURITY_ALERT_PRIMARY_SIGNING_KEY_ID`.
4. Verify successful requests carrying the new `x-basitclaw-key-id`.
5. Keep both keys through the approved overlap and replay window.
6. Run `npm run security-keys -- alert-can-retire <oldKeyId>`.
7. After receiver ownership confirms overlap completion, run the same command with `--receiver-confirmed`.
8. Remove the old secret only when the confirmed check returns `safe: true`.

See `docs/security-key-rotation.md` for the full change-control procedure.

## Receiver responses

- Any `2xx` response completes delivery and creates a durable receipt.
- `408`, `425`, `429`, and `5xx` responses retry.
- Other `4xx` responses dead-letter immediately.
- Network and timeout failures retry.
- A valid `Retry-After` header overrides the calculated delay within the configured maximum.

Retries use bounded exponential backoff with deterministic jitter. Exhausted items are dead-lettered.

## Crash and concurrency guarantees

- Only one process can claim a delivery at a time.
- Claims expire and recover after process failure.
- Receipts and dead letters commit before the in-flight claim is removed.
- A committed destination wins over an orphaned claim.
- The same event hash maps to the same delivery ID across processes.

## Operator commands

```bash
npm run security-alerts -- status
npm run security-alerts -- dispatch 25
npm run security-alerts -- dead-letters 100
npm run security-alerts -- requeue ALERT-0123456789abcdef0123456789abcdef
npm run security-keys -- status
```

Requeue only after the receiver problem or policy mismatch is corrected. Dead letters are never silently discarded.

## Readiness and incident response

When delivery is required, an unavailable outbox or retained dead letter makes the security evidence pipeline unavailable and `/health` returns `503`.

During an incident:

1. Preserve the outbox and locks.
2. Inspect delivery and key-lifecycle status.
3. Confirm receiver availability and matching key IDs.
4. Run a bounded dispatch.
5. Review dead letters and response codes.
6. Correct receiver, keyring, or policy configuration.
7. Requeue only reviewed delivery IDs.
8. Confirm readiness and latest successful delivery.

Do not delete queue or lock files to clear readiness.

## Network boundary

Production endpoints must use HTTPS. URL user information, localhost, `.local`, loopback, link-local, and literal private IPv4 targets are rejected unless explicitly approved. DNS and egress controls remain deployment responsibilities. Redirects are rejected, and signing secrets must not be reused by other systems.
