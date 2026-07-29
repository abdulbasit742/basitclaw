# Workforce-audit API security runbook

## Credential format

Development may continue using a legacy plaintext `apiKey` record. Production rejects plaintext credential records and requires a scrypt-backed record:

```json
{
  "keyId": "admin-2026-q3",
  "salt": "<random-salt>",
  "secretHash": "<base64-scrypt-hash>",
  "subject": "audit-admin",
  "tenantId": "tenant-acme",
  "role": "compliance_admin",
  "status": "active",
  "notBefore": "2026-07-29T00:00:00.000Z",
  "expiresAt": "2026-10-31T00:00:00.000Z"
}
```

The client presents `keyId.secret` in `x-api-key`. Only the scrypt hash and salt belong in `WORKFORCE_AUDIT_API_KEYS`.

Generate a credential with:

```bash
npm run credential:generate -- admin-2026-q3 audit-admin tenant-acme compliance_admin 2026-10-31T00:00:00Z
```

The command prints the presented key once and a configuration record. Store the presented key in a secret manager immediately; do not commit it, write it to application logs, or place it in support tickets.

## Lifecycle states

- `active`: accepted while inside its optional activation and expiry window.
- `retiring`: accepted, but responses include `x-api-key-rotation-required: true`.
- `revoked`: rejected with `401 CREDENTIAL_REVOKED`.
- A future `notBefore` is rejected with `401 CREDENTIAL_NOT_ACTIVE`.
- An elapsed `expiresAt` is rejected with `401 CREDENTIAL_EXPIRED`.

Credentials expiring within `WORKFORCE_AUDIT_CREDENTIAL_WARNING_DAYS` also receive the rotation-required header. Rotate by adding the replacement as `active`, marking the old record `retiring`, deploying both, updating clients, then marking the old record `revoked`.

## Rate-limit policies

The built-in limiter applies separate fixed windows for:

- per-client bursts;
- failed authentication attempts;
- authenticated reads;
- authenticated writes;
- sensitive restore, replication, drill, and manual resilience operations.

Exceeded limits return `429 RATE_LIMITED`, `Retry-After`, `RateLimit-Limit`, `RateLimit-Remaining`, and `RateLimit-Reset`.

The built-in limiter is intentionally process-local and reports `distributed: false`. In a multi-process deployment its limits are defence in depth, not a global quota. Enforce an additional shared limit at the ingress gateway or service mesh.

## Trusted proxy handling

`WORKFORCE_AUDIT_TRUST_PROXY_HOPS=0` is the safe default and uses the direct socket address. Increase it only when the application is behind exactly that many controlled reverse proxies. A wrong value can allow spoofed `x-forwarded-for` values or group unrelated clients under one address.

## Security telemetry

The bounded event buffer records only security-relevant events:

- failed, expired, revoked, or premature credential use;
- permission denial;
- tenant override attempts;
- request throttling.

Client addresses are stored only as keyed SHA-256 fingerprints. Keys, secrets, passwords, tokens, and raw addresses are removed from event details. Configure `WORKFORCE_AUDIT_SECURITY_EVENT_PEPPER` with a stable secret if fingerprints must remain comparable across restarts.

The event buffer is hash-chained but process-local and non-durable. Export alerts to a central security platform in a later integration; do not treat this bounded memory buffer as the organisation's authoritative SIEM archive.

## APIs and permissions

Only `compliance_admin` has `security:read`:

- `GET /api/workforce-audit/security-status`
- `GET /api/workforce-audit/security-events?limit=100&type=<type>&severity=<severity>`

Public `/health` exposes readiness counts and subsystem status, but never credential hashes, salts, presented keys, or raw security events.

## Deployment checklist

1. Generate high-entropy credentials and store presented keys in a secret manager.
2. Remove every plaintext `apiKey` record before setting `NODE_ENV=production`.
3. Configure expiry windows and a documented rotation owner.
4. Set the trusted proxy hop count only after validating the ingress chain.
5. Apply global distributed rate limits at ingress for multi-process deployments.
6. Configure a stable telemetry pepper.
7. Verify `security-status`, rotation headers, `429` behaviour, and `/health` before completing rollout.
8. Never disable throttling to resolve an incident; adjust approved policy values and retain evidence of the change.
