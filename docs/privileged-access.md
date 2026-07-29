# Just-in-time privileged access

BasitClaw can remove selected sensitive permissions from continuous use while keeping them assigned to the approved standing role. A user may exercise a protected permission only when an active, tenant-bound, time-boxed grant exists.

## Recommended production configuration

```bash
WORKFORCE_AUDIT_AUTH_MODE=oidc
WORKFORCE_AUDIT_PRIVILEGED_ACCESS_MODE=enforce
WORKFORCE_AUDIT_PRIVILEGED_ACCESS_DIR=/var/lib/basitclaw/workforce-audit-privileged-access
WORKFORCE_AUDIT_PRIVILEGED_ACCESS_KEYS='{"2026-q3":"<base64-32-byte-key>"}'
WORKFORCE_AUDIT_PRIVILEGED_ACCESS_PRIMARY_KEY_ID=2026-q3
WORKFORCE_AUDIT_PRIVILEGED_ACCESS_PROTECTED_PERMISSIONS=backup:restore,resilience:run,security:read
WORKFORCE_AUDIT_PRIVILEGED_ACCESS_APPROVALS_REQUIRED=2
WORKFORCE_AUDIT_PRIVILEGED_ACCESS_MAX_DURATION_MINUTES=120
WORKFORCE_AUDIT_PRIVILEGED_ACCESS_REQUIRED_AMR=mfa
WORKFORCE_AUDIT_PRIVILEGED_ACCESS_ALLOW_API_KEY=false
```

Use a shared durable filesystem with reliable atomic directory creation and rename semantics. Retain historical encryption keys while old envelopes may reference them.

## Request and approval flow

1. The requester authenticates with an approved standing role and step-up assurance.
2. `POST /api/workforce-audit/privileged-access/requests` creates a tenant-bound request containing permissions, duration, business reason, and ticket reference.
3. Two different compliance administrators approve through `POST /requests/{id}/approve`.
4. The requester cannot approve or deny their own request. One approver cannot count twice.
5. The grant activates only after the configured approval threshold and expires automatically.
6. Every update requires the current `ETag` through `If-Match`.

A grant never adds a permission absent from the requester's approved role. It only unlocks a permission already present in that role and configured as protected.

## Management API

- `GET /api/workforce-audit/privileged-access/status`
- `GET /api/workforce-audit/privileged-access/requests`
- `GET /api/workforce-audit/privileged-access/requests/{id}`
- `POST /api/workforce-audit/privileged-access/requests`
- `POST /api/workforce-audit/privileged-access/requests/{id}/approve`
- `POST /api/workforce-audit/privileged-access/requests/{id}/deny`
- `POST /api/workforce-audit/privileged-access/requests/{id}/cancel`
- `POST /api/workforce-audit/privileged-access/requests/{id}/revoke`
- `POST /api/workforce-audit/privileged-access/requests/{id}/review`
- `POST /api/workforce-audit/privileged-access/break-glass`

## Break glass

Break-glass access is disabled separately by default. When enabled:

- OIDC is mandatory even when ordinary API-key grants are explicitly allowed;
- the user must satisfy the configured AMR and ACR values;
- exact confirmation `BREAK GLASS` is required;
- duration is capped independently, normally at 15 minutes;
- an incident reference and detailed reason are required;
- activation produces a critical security event immediately;
- an independent compliance administrator must complete post-use review before the deadline;
- the emergency user cannot review their own access.

Overdue post-use reviews make privileged-access posture `attention`, but do not falsely report the encrypted store as unavailable.

## Failure response

- `PRIVILEGED_ACCESS_REQUIRED`: no active grant exists.
- `PRIVILEGED_ACCESS_AMR_REQUIRED` or `PRIVILEGED_ACCESS_ACR_REQUIRED`: repeat authentication with approved step-up policy.
- `PRIVILEGED_ACCESS_CONFLICT`: reload the request and retry with its current ETag.
- `PRIVILEGED_ACCESS_STORE_UNAVAILABLE`: drain sensitive operations and restore the shared encrypted store; do not bypass enforcement.
- `BREAK_GLASS_CONFIRMATION_REQUIRED`: verify the emergency procedure and exact confirmation.

## Evidence and privacy

Requests and the event chain are encrypted with AES-256-GCM. Every event is hash-linked, writes use an atomic shared mutex, and stale requests are retained according to policy. Public health and dashboard responses omit filesystem paths, key identifiers, reasons, ticket references, and approver identities.

## Rollout

1. Start in `observe` outside production and confirm which operations would require grants.
2. Configure OIDC step-up assurance and at least two eligible approvers per tenant.
3. Test request, dual approval, expiry, revocation, break-glass alerting, and post-use review.
4. Switch production to `enforce`.
5. Review pending requests, active grants, and overdue emergency reviews every day.
6. Exercise store recovery and encryption-key rotation under change control.
