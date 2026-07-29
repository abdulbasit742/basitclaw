# BasitClaw

BasitClaw is a dependency-light Node.js workspace for enterprise workforce internal-audit assurance.

Pass 1 established the HR audit universe, engagement planning, fieldwork placeholders, findings, provider readiness, APIs, and dashboard. Pass 2 adds API-key authentication, role-based permissions, tenant-isolated service instances, request traceability, and a SHA-256 chained governance ledger for audit mutations.

## Requirements

- Node.js 20 or newer

## Local setup

```bash
cp .env.example .env
npm install
npm test
npm run lint
npm run build
npm start
```

Open `http://localhost:3000/dashboard/workforce-audit` and enter the local development key from `.env`.

## Access model

Configure `WORKFORCE_AUDIT_API_KEYS` as a JSON array of principals:

```json
[{"apiKey":"replace-with-a-long-random-key","subject":"audit-manager","tenantId":"tenant-acme","role":"audit_manager"}]
```

Supported roles:

- `audit_viewer`: read assurance data
- `auditor`: read, fieldwork placeholder, and finding operations
- `audit_manager`: auditor permissions plus engagement planning and governance-history access
- `compliance_admin`: full current module access

The authenticated principal determines the tenant. A client cannot override tenant selection with headers.

## Verification

- `npm test` runs service, access-control, tenant-isolation, governance-ledger, and HTTP tests.
- `npm run lint` performs syntax validation on executable modules.
- `npm run build` verifies required application files and dashboard security integration.

## Current persistence boundary

Business data and governance events remain in memory in this pass. The service and registry boundaries are ready for a durable repository, but production deployment still requires encrypted persistent storage, key rotation, rate limiting, central identity integration, backups, and immutable external evidence retention.
