# BasitClaw

BasitClaw is a dependency-light Node.js workspace for enterprise workforce internal-audit assurance. Prompt 171 establishes HR audit-universe readiness, engagement planning boundaries, governed fieldwork placeholders, finding readiness, and external audit-provider readiness.

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

Open `http://localhost:3000/dashboard/workforce-audit`.

## Verification

- `npm test` runs service and HTTP smoke tests with Node's built-in test runner.
- `npm run lint` performs syntax validation on executable modules.
- `npm run build` verifies that the dashboard, service, server, and type contract are present and internally consistent.

## Current persistence boundary

This bootstrap pass uses deterministic in-memory fixtures. It does not claim durable audit evidence storage. Future persistence must preserve the service validation rules and add authentication, tenant isolation, immutable evidence lineage, and database migrations before production use.
