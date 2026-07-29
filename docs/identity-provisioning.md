# Governed identity provisioning and deprovisioning

## Scope

BasitClaw can enforce a locally governed entitlement after an OIDC token has passed signature and claim validation. The entitlement records the approved tenant, workforce-audit role, active state, review deadline, and lifecycle version.

The service never persists the raw identity-provider subject. SCIM requests provide `externalId`; BasitClaw derives the same issuer-bound pseudonymous subject used by OIDC and stores only that value.

## Enable the lifecycle boundary

```bash
WORKFORCE_AUDIT_IDENTITY_ENTITLEMENT_MODE=enforce
WORKFORCE_AUDIT_IDENTITY_STORE_DIR=/var/lib/basitclaw/workforce-audit-identities
WORKFORCE_AUDIT_IDENTITY_STORE_KEYS='{"2026-q3":"<base64-32-byte-key>"}'
WORKFORCE_AUDIT_IDENTITY_STORE_PRIMARY_KEY_ID=2026-q3
WORKFORCE_AUDIT_IDENTITY_REVIEW_MAX_AGE_DAYS=365
WORKFORCE_AUDIT_SCIM_ENABLED=true
```

`observe` mode can be used outside production to measure unprovisioned identities without denying them. Production rejects an enabled lifecycle unless it uses `enforce`.

The store is AES-256-GCM encrypted, written atomically, protected by a cross-process file mutex, and contains a hash-chained lifecycle event history. Shared deployments require durable storage with reliable atomic `mkdir` and `rename` behaviour.

## Generate a SCIM credential

```bash
npm run scim:credential:generate -- scim-2026-q3 enterprise-idp 2026-10-31T00:00:00Z scim:read,scim:write
```

Store the one-time presented token in the identity provider. Put only the generated scrypt record in `WORKFORCE_AUDIT_SCIM_CREDENTIALS`.

SCIM credentials have their own key ID, subject, scopes, activation/expiry windows, and active, retiring, or revoked state. They are not workforce-audit API credentials and cannot call audit routes.

## SCIM endpoint and schema

Configure the identity provider with:

```text
Base URL: https://basitclaw.example.com/scim/v2
Authorization: Bearer <generated-keyId.secret>
```

Supported resources:

- `GET /scim/v2/ServiceProviderConfig`
- `GET /scim/v2/ResourceTypes`
- `GET /scim/v2/Schemas`
- `GET|POST /scim/v2/Users`
- `GET|PUT|PATCH|DELETE /scim/v2/Users/:id`

Every user must include the extension:

```text
urn:basitclaw:params:scim:schemas:extension:workforce-audit:2.0:User
```

Example create request:

```json
{
  "schemas": [
    "urn:ietf:params:scim:schemas:core:2.0:User",
    "urn:basitclaw:params:scim:schemas:extension:workforce-audit:2.0:User"
  ],
  "externalId": "identity-provider-object-id",
  "active": true,
  "displayName": "Approved auditor",
  "urn:basitclaw:params:scim:schemas:extension:workforce-audit:2.0:User": {
    "tenantId": "tenant-acme",
    "role": "auditor",
    "reviewBy": "2027-01-31T00:00:00Z",
    "reason": "Approved onboarding request IAM-1042"
  }
}
```

The response deliberately omits `externalId`. It returns a BasitClaw resource ID, weak ETag, approved tenant/role, and review status.

## Updates and optimistic concurrency

`PUT`, `PATCH`, and `DELETE` require the latest `If-Match` value, for example:

```text
If-Match: W/"3"
```

A stale or missing version fails with `409`. This prevents two identity-provider workers or administrators from silently overwriting one another.

Only bounded `replace` PATCH operations are accepted. Supported fields are:

- `active`
- extension `tenantId`
- extension `role`
- extension `reviewBy`
- extension `reason`

Every change requires a governance reason. `DELETE` performs governed deactivation rather than erasing evidence and requires `x-basitclaw-change-reason`.

## Runtime enforcement

After OIDC validation, BasitClaw checks the encrypted entitlement:

1. the pseudonymous subject must exist;
2. the entitlement must be active;
3. token tenant and role must exactly match the approved tenant and role;
4. the review deadline must remain in the future.

Failures are explicit:

- `IDENTITY_NOT_PROVISIONED`
- `IDENTITY_SUSPENDED`
- `IDENTITY_ENTITLEMENT_MISMATCH`
- `IDENTITY_REVIEW_OVERDUE`
- `IDENTITY_ENTITLEMENT_STORE_UNAVAILABLE`

A required unavailable store fails startup and request processing closed. Suspensions and mismatches are recorded in privacy-minimised security telemetry.

## Review and operations

```bash
npm run identity:check
npm run identity:entitlements -- status
npm run identity:entitlements -- review-status
npm run identity:entitlements -- list 100
npm run identity:entitlements -- events 200
```

Review overdue and due-soon counts must be monitored. The event history records provision, update, suspension, and deprovision actions with actor, reason, version, previous hash, and event hash.

## Key rotation

Add the new encryption key to `WORKFORCE_AUDIT_IDENTITY_STORE_KEYS`, change the primary key ID, and restart. New snapshots use the new primary key. Keep every historical key until the current entitlement envelope has been successfully read and rewritten under the new primary through an approved lifecycle change.

Do not remove a key merely because it is no longer primary. Missing historical keys make the store unavailable.

## Incident response

- Preserve the encrypted entitlement directory and lock directory.
- Run `npm run identity:check` and `npm run identity:entitlements -- status`.
- Verify storage mount health and configured historical keys.
- Review the latest entitlement events before changing an identity.
- Correct the identity provider or entitlement through approved SCIM change control.
- Do not delete the encrypted envelope or locks to clear readiness.

## Remaining boundary

BasitClaw enforces approved access but does not decide employment status, source authoritative HR data, approve access requests, or issue OIDC tokens. Those responsibilities remain with the enterprise identity, HR, and access-governance systems. Token revocation or introspection and browser login remain separate boundaries.
