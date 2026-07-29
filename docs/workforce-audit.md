# Workforce audit governance boundary

This module deliberately separates planning readiness from audit conclusions.

## Guardrails

- An engagement cannot enter the plan without a valid audit-universe item, explicit scope, valid dates, a named lead auditor, and management approval.
- Overlapping engagements for the same audit-universe item are blocked unless an earlier engagement is cancelled.
- Fieldwork placeholders require an owner, reason, expiry date, and replacement evidence. They cannot remain open longer than 60 days.
- A finding requires traceable evidence. Placeholder references cannot support verified or closed status.
- External providers are blocked unless independence, security review, data-processing terms, delivery capacity, and current due diligence are all satisfactory.

## API surface

- `GET /api/workforce-audit/overview`
- `GET /api/workforce-audit/universe`
- `GET /api/workforce-audit/engagements`
- `POST /api/workforce-audit/engagements`
- `POST /api/workforce-audit/engagements/:id/placeholders`
- `GET /api/workforce-audit/findings`
- `POST /api/workforce-audit/findings`
- `GET /api/workforce-audit/providers`

Fixture mode is the only supported persistence mode in this bootstrap pass. The service boundary is intentionally isolated so a durable repository can replace fixtures without changing routes or governance rules.
