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

The verifier enforces:

- HTTPS issuer and JWKS endpoints;
- exact issuer and audience matching;
- RS256 or ES256 only;
- no unsigned, HMAC-signed, or header-supplied-key JWTs;
- required `kid`, `sub`, `iat`, and `exp` claims;
- optional `nbf` enforcement;
- maximum token lifetime and bounded clock skew;
- RSA keys of at least 2048 bits or P-256 EC keys;
- JWKS response size, cache, timeout, redirect, and private-target controls;
- forced JWKS refresh when an unknown signing key appears;
- bounded stale-key use only inside the configured grace period.

The service never trusts roles or permissions supplied directly by the token. Exact identity-provider groups are mapped to one BasitClaw role. No mapped role is denied. Multiple distinct mapped roles are treated as ambiguous and denied.

## Tenant and identity mapping

The tenant claim is mandatory and is compared with the configured allowlist. `x-tenant-id` cannot override the authenticated tenant.

Raw external subjects are not placed into governance records. BasitClaw derives a stable issuer-bound pseudonymous subject. The credential identity used for rate limits remains stable when the identity provider rotates signing keys; the signing key ID is retained separately for diagnostics.

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

## JWKS lifecycle and readiness

Run the preflight before deployment:

```bash
npm run identity:check
```

OIDC-only production defaults to failing startup when JWKS warm-up fails. Hybrid mode may continue for API-key migration, but readiness becomes unavailable until OIDC recovers. Runtime refresh is controlled by `WORKFORCE_AUDIT_OIDC_REFRESH_SECONDS`.

Known cached keys may be used during a temporary provider outage only until `WORKFORCE_AUDIT_OIDC_JWKS_STALE_SECONDS` expires. After that boundary, token verification fails unavailable rather than trusting indefinitely stale keys.

## Migration procedure

1. Configure OIDC issuer, audience, JWKS, tenant allowlist, and group mappings.
2. Run `npm run identity:check` and verify mapped groups in a non-production environment.
3. Set `WORKFORCE_AUDIT_AUTH_MODE=hybrid`.
4. Migrate clients to short-lived bearer tokens.
5. Monitor failed-authentication telemetry, unknown groups, tenant denials, JWKS cache state, and token-lifetime failures.
6. Revoke or retire API credentials only after every approved client has migrated.
7. Set `WORKFORCE_AUDIT_AUTH_MODE=oidc` and remove API-key configuration from the deployment.

## Failure response

- `OIDC_SIGNATURE_INVALID`: verify issuer signing keys and token audience; do not bypass signature validation.
- `OIDC_SIGNING_KEY_UNKNOWN`: verify key rollover and JWKS freshness.
- `OIDC_UNAVAILABLE`: identity-provider keys could not be refreshed and no acceptable cached key was available.
- `OIDC_TENANT_NOT_ALLOWED`: correct the tenant assignment or allowlist through approved change control.
- `OIDC_ROLE_NOT_MAPPED`: add an exact approved group mapping.
- `OIDC_ROLE_AMBIGUOUS`: remove conflicting group membership or mappings.
- `OIDC_ACR_REQUIRED` / `OIDC_AMR_REQUIRED`: satisfy the required identity-provider assurance policy.
- `AMBIGUOUS_CREDENTIALS`: send exactly one authentication method.

Failed bearer authentication uses the existing failed-authentication rate policy and privacy-minimised security telemetry. Provider outages are recorded as critical security-control events.

## Remaining boundary

Identity creation, group lifecycle, SCIM provisioning/deprovisioning, browser login, token issuance, refresh-token custody, token revocation/introspection, and identity-provider conditional access remain external enterprise identity responsibilities.
