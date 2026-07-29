# Signed security alert delivery runbook

## Purpose and delivery model

The security alert subsystem forwards privacy-minimised security events to an approved webhook without making business requests depend on receiver availability. Eligible events are written to a shared durable outbox before delivery. Delivery is **at least once**: receivers must deduplicate using `x-basitclaw-delivery-id`.

Only the event produced after telemetry sanitisation is queued. Raw client addresses, API keys, secrets, passwords, and tokens are not included.

## Production configuration

```bash
WORKFORCE_AUDIT_SECURITY_ALERT_MODE=webhook
WORKFORCE_AUDIT_SECURITY_ALERT_REQUIRED=true
WORKFORCE_AUDIT_SECURITY_ALERT_WEBHOOK_URL=https://siem.example.com/hooks/workforce-audit
WORKFORCE_AUDIT_SECURITY_ALERT_SIGNING_SECRET=<at-least-32-random-bytes>
WORKFORCE_AUDIT_SECURITY_ALERT_OUTBOX_DIR=/var/lib/basitclaw/workforce-audit-security-alerts
WORKFORCE_AUDIT_SECURITY_ALERT_MIN_SEVERITY=high
WORKFORCE_AUDIT_SECURITY_ALERT_TYPES=
WORKFORCE_AUDIT_SECURITY_ALERT_MAX_ATTEMPTS=8
WORKFORCE_AUDIT_SECURITY_ALERT_POLL_INTERVAL_MS=5000
```

The outbox path must be on storage shared by every application process and must provide reliable atomic `mkdir` and `rename`. Do not use eventually consistent object-store mounts.

`WORKFORCE_AUDIT_SECURITY_ALERT_TYPES` is optional. An empty value sends every event at or above the configured severity. A comma-separated value restricts delivery to exact event types.

## Webhook request

Each request is JSON and includes:

```json
{
  "version": 1,
  "deliveryId": "ALERT-...",
  "emittedAt": "2026-07-29T15:00:00.000Z",
  "attempt": 1,
  "event": {}
}
```

Headers:

- `x-basitclaw-delivery-id`: stable identifier used for deduplication;
- `x-basitclaw-timestamp`: Unix timestamp in seconds;
- `x-basitclaw-signature`: `sha256=<hex HMAC>`;
- `content-type`: `application/json; charset=utf-8`.

Verify the signature over the exact raw request body:

```text
HMAC-SHA256(signing_secret, timestamp + "." + raw_body)
```

Compare signatures in constant time. Reject timestamps outside the receiver's approved replay window and retain delivery IDs for at least the maximum sender retry period.

## Receiver responses

- Any `2xx` response completes delivery and creates a durable receipt.
- `408`, `425`, `429`, and `5xx` responses are retried.
- Other `4xx` responses move directly to the dead-letter queue.
- Network and timeout failures are retried.
- A valid `Retry-After` header overrides the calculated delay, subject to the configured maximum.

Retries use bounded exponential backoff with deterministic jitter. When the maximum attempt count is reached, the item is dead-lettered.

## Crash and concurrency guarantees

- Only one process can claim a delivery at a time.
- Claims have an expiry and are recovered after a process stops unexpectedly.
- Delivered receipts and dead letters are committed before the in-flight claim is removed.
- If a process stops between those operations, the committed destination wins and recovery removes the orphaned claim without resending it.
- The same event hash maps to the same delivery ID, preventing duplicate enqueue across processes.

## Operator commands

```bash
npm run security-alerts -- status
npm run security-alerts -- dispatch 25
npm run security-alerts -- dead-letters 100
npm run security-alerts -- requeue ALERT-0123456789abcdef0123456789abcdef
```

`status` reports full local filesystem diagnostics and queue counts. HTTP health and security-status responses omit outbox and mutex paths.

Requeue only after the receiver problem or policy mismatch has been corrected. Requeue is explicit; dead letters are never silently discarded or retried forever.

## Readiness and incident response

When delivery is marked required, an unavailable outbox or any retained dead letter makes the security evidence pipeline unavailable and `/health` returns `503`. Normal business requests still fail or succeed according to their own controls; telemetry enqueue failures are counted and surfaced.

During an incident:

1. Preserve the outbox directory and its locks.
2. Inspect `npm run security-alerts -- status`.
3. Confirm receiver availability and signature configuration.
4. Run a bounded manual dispatch.
5. Inspect dead letters and receiver response codes.
6. Correct the receiver or policy.
7. Requeue only the reviewed delivery IDs.
8. Confirm readiness and the latest successful delivery timestamp.

Do not force-delete in-flight, pending, receipt, dead-letter, or lock files to clear readiness.

## Network boundary

Production endpoints must use HTTPS. URL user information, localhost, `.local`, loopback, link-local, and literal private IPv4 targets are rejected unless private targets are explicitly approved. DNS resolution can still change after validation, so production deployments must enforce outbound egress policy and DNS controls.

Redirects are rejected. Keep the receiver endpoint narrowly scoped and do not reuse the signing secret for other systems.

## Remaining boundary

The archive and alert signing secrets still rely on external managed secret custody. Automatic archive-key rotation and automated signing-secret rollover are not included in this pass.
