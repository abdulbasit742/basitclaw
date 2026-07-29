# Workforce audit governance boundary

This module separates audit planning readiness from audit conclusions and now enforces identity and tenant boundaries at the HTTP layer.

## Identity and tenancy

- Every `/api/workforce-audit/*` request requires `x-api-key`.
- API keys resolve to a subject, tenant, and role.
- The tenant comes only from the authenticated principal; `x-tenant-id` cannot override it.
- Every tenant receives a separate service instance and mutation state.
- Production startup fails when no API-key configuration is supplied.

## Role permissions

| Role | Read | Engagement planning | Fieldwork | Findings | Governance history |
|---|---:|---:|---:|---:|---:|
| audit_viewer | Yes | No | No | No | No |
| auditor | Yes | No | Yes | Yes | No |
| audit_manager | Yes | Yes | Yes | Yes | Yes |
| compliance_admin | Yes | Yes | Yes | Yes | Yes |

## Governance ledger

Every engagement, fieldwork-placeholder, and finding mutation appends a tenant-scoped governance event containing actor, action, entity, time, metadata, previous hash, and SHA-256 hash. `GET /api/workforce-audit/governance-integrity` verifies the complete tenant chain.

The in-memory chain is tamper-evident during the process lifetime, not durable. A production ledger must be persisted in append-only storage with restricted write paths and independent retention.

## Existing audit guardrails

- Engagements require a valid audit-universe item, explicit scope, valid dates, a named lead auditor, and management approval.
- Overlapping engagements for the same audit-universe item are blocked unless an earlier engagement is cancelled.
- Fieldwork placeholders require an owner, reason, expiry date, and replacement evidence. They cannot remain open longer than 60 days.
- Findings require traceable evidence. Placeholder references cannot support verified or closed status.
- External providers remain blocked until independence, security review, data-processing terms, delivery capacity, and current due diligence are satisfactory.

## API surface

- `GET /api/workforce-audit/session`
- `GET /api/workforce-audit/overview`
- `GET /api/workforce-audit/universe`
- `GET /api/workforce-audit/engagements`
- `POST /api/workforce-audit/engagements`
- `POST /api/workforce-audit/engagements/:id/placeholders`
- `GET /api/workforce-audit/findings`
- `POST /api/workforce-audit/findings`
- `GET /api/workforce-audit/providers`
- `GET /api/workforce-audit/governance-events`
- `GET /api/workforce-audit/governance-integrity`
