# Workforce audit governance boundary

This module separates audit planning readiness from audit conclusions and enforces identity, tenant, durability, and traceability boundaries.

## Identity and tenancy

- Every `/api/workforce-audit/*` request requires `x-api-key`.
- API keys resolve to a subject, tenant, and role.
- The authenticated principal is the only source of tenant selection.
- Every tenant receives a separate service instance and encrypted snapshot.

## Durable mutation protocol

1. Validate the requested audit operation.
2. Capture a business-state and governance-ledger checkpoint.
3. Apply the business mutation and append the actor-attributed governance event.
4. Encrypt the complete tenant snapshot using AES-256-GCM.
5. Write with restrictive permissions to a unique temporary file.
6. Fsync the file, atomically rename it, and attempt to fsync the directory.
7. Return success only after the durable write completes.
8. Restore both business state and governance history if persistence fails.

## Encryption and rotation

- Each envelope identifies the encryption key used.
- The tenant ID is never used as a filename; a SHA-256 tenant hash selects the file.
- Tenant hash, format, version, algorithm, key ID, write time, and IV are authenticated as GCM additional data.
- Older keys may be retained for reads while a new primary key handles writes.
- Production startup fails when encryption keys or a primary key ID are missing.

## Persistence APIs

- `GET /health` includes storage health and returns `503` when persistence is unavailable.
- `GET /api/workforce-audit/persistence-health` exposes storage mode, active key ID, configured key IDs, and persisted tenant count to governance-authorised roles.

## Existing audit guardrails

- Engagements require a valid audit-universe item, explicit scope, valid dates, a named lead auditor, and management approval.
- Overlapping engagements for the same audit-universe item are blocked.
- Fieldwork placeholders require an owner, reason, expiry date, and replacement evidence, with a maximum 60-day lifetime.
- Findings require traceable evidence; placeholder references cannot support verified or closed status.
- External providers remain blocked until independence, security review, data-processing terms, delivery capacity, and current due diligence are satisfactory.

## Deployment limitation

The current atomic file store assumes one writer process. Horizontal scaling requires a transactional shared persistence layer or a proven distributed locking protocol.
