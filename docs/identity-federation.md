# Enterprise identity federation runbook

## Scope

BasitClaw acts as an OIDC-protected resource server. It validates short-lived bearer access tokens issued by an approved enterprise identity provider. It does not implement a browser authorization-code callback, store refresh tokens, or manage identity-provider sessions.

Authentication modes:

- `api-key`: existing lifecycle-managed API credentials only;
- `oidc`: bearer access tokens only;
- `hybrid`: either method during a controlled migration.

A request must never contain both an API key and a bearer token. Ambiguous credentials fail closed.

## Production configuration

```bash
WORKFORCE_AUDIT_AUTH_MODE=oidc
WORKFORCE_AUDIT_OIDC_ISSUER=https://identity.example.com/tenant
WORKFORCE_AUDIT_OIDC_AUDIENCE=workforce-audit-api
WORKFORCE_AUDIT_OIDC_JWKS_URI=https://identity.example.com/tenant/.well-known/jwks.json
WORKFORCE_AUDIT_OIDC_GROUP_ROLE_MAP='{"audit-viewers":"audit_viewer","auditors":"auditor","audit-managers":"audit_manager","compliance-admins":"compliance_admin"}'
WORKFORCE_AUDIT_OIDC_ALLOWED_TENANTS=tenant-acme,tenant-emea
WORKFORCE_AUDIT_OIDC_TENANT_CLAIM=tenant_id
WORKFORCE_AUDIT_OIDC_GROUPS_CLAIM=groups
WORKFORCE_AUDIT_OIDC_ALLOWED_ALGORITHMS=RS256
```

Production requires an explicit tenant allowlist unless `WORKFORCE_AUDIT_OIDC_ALLOW_ANY_TENANT=true` is approved. An allow-any deployment cannot enumerate federated tenants for scheduled per-tenant work, so an allowlist is preferred.

## Token validation

The verifier enforces HTTPS endpoints, exact issuer and audience matching, RS256 or ES256, required `kid`, `sub`, `iat`, and `exp`, bounded lifetime and clock skew, minimum RSA/P-256 strength, controlled JWKS retrieval, forced unknown-key refresh, and bounded stale-key use. Unsigned, symmetric, weak-key, malformed, oversized, and header-supplied-key tokens fail closed.

The service never trusts roles or permissions supplied directly by the token. Exact identity-provider groups map to one BasitClaw role. Missing or ambiguous role mappings are denied.

## Tenant, identity, and entitlement mapping

The tenant claim is mandatory and checked against the allowlist. `x-tenant-id` cannot override it. Raw external subjects are not placed into governance records; BasitClaw derives an issuer-bound pseudonymous subject and a stable rate-limit identity.

When governed provisioning is enabled, successful JWT validation is followed by an encrypted entitlement check. The pseudonymous subject must be provisioned, active, approved for the same tenant and role, and within its review period. See `docs/identity-provisioning.md`.

Nested claim paths are supported, for example:

```bash
WORKFORCE_AUDIT_OIDC_TENANT_CLAIM=organisation.tenant
WORKFORCE_AUDIT_OIDC_GROUPS_CLAIM=realm.groups
```

Prototype-related path segments are rejected.

## Step-up authentication

Optional exact assurance requirements can be configured:

```bash
WORKFORCE_AUDIT_OIDC_REQUIRED_ACR=urn:example:mfa
WORKFORCE_AUDIT_OIDC_REQUIRED_AMR=mfa
```

Every configured AMR value must be present. Use identity-provider conditional-access policy as the primary control; these checks provide resource-server enforcement.

## JWKS and lifecycle readiness

Run the preflight before deployment:

```bash
npm run identity:check
```

OIDC-only production defaults to failing startup when JWKS warm-up fails. Hybrid mode may continue for API-key migration, but readiness becomes unavailable until OIDC recovers. Known keys may be used during a temporary outage only until the configured stale boundary.

When entitlement enforcement or SCIM is enabled, the same preflight also validates encrypted entitlement storage and SCIM credential readiness. Required lifecycle storage fails startup closed.

## Migration procedure

1. Configure OIDC issuer, audience, JWKS, tenant allowlist, and group mappings.
2. Configure entitlement lifecycle in `observe` outside production and measure unprovisioned identities.
3. Configure SCIM and provision approved users with tenant, role, and review deadline.
4. Run `npm run identity:check`.
5. Set authentication to `hybrid` and entitlement lifecycle to `enforce` in the approved rollout.
6. Migrate clients to bearer tokens and monitor OIDC and entitlement denials.
7. Revoke API credentials only after every approved client has migrated.
8. Set authentication to `oidc` and remove API-key configuration.

## Failure response

- `OIDC_SIGNATURE_INVALID`: verify issuer signing keys and audience; never bypass signature validation.
- `OIDC_SIGNING_KEY_UNKNOWN`: verify rollover and JWKS freshness.
- `OIDC_UNAVAILABLE`: no acceptable signing key was available.
- `OIDC_TENANT_NOT_ALLOWED`: correct the tenant assignment or allowlist.
- `OIDC_ROLE_NOT_MAPPED` / `OIDC_ROLE_AMBIGUOUS`: correct approved group mappings.
- `OIDC_ACR_REQUIRED` / `OIDC_AMR_REQUIRED`: satisfy the required assurance policy.
- `IDENTITY_NOT_PROVISIONED`: provision the identity through approved SCIM change control.
- `IDENTITY_SUSPENDED`: review the deprovisioning source; do not reactivate outside approval.
- `IDENTITY_ENTITLEMENT_MISMATCH`: reconcile token group/tenant claims with the approved entitlement.
- `IDENTITY_REVIEW_OVERDUE`: complete and record the access review.
- `IDENTITY_ENTITLEMENT_STORE_UNAVAILABLE`: restore encrypted store and historical key availability.
- `AMBIGUOUS_CREDENTIALS`: send exactly one authentication method.

Failed bearer authentication and lifecycle denials use rate controls and privacy-minimised security telemetry.

## Remaining boundary

BasitClaw now supports governed SCIM provisioning and local entitlement enforcement. Authoritative employment data, access approvals, browser login, token issuance, refresh-token custody, token revocation or introspection, and identity-provider conditional-access policy remain enterprise responsibilities.
