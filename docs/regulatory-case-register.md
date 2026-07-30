# Regulatory case register

Pass 25 adds an encrypted register for regulator requests, external-audit enquiries, legal requests and certification reviews. It tracks the authority, jurisdiction, legal basis, statutory or contractual deadline, response owner, immutable evidence scope and response approval history.

## Security boundary

The case register stores structured workflow data in an AES-256-GCM encrypted tenant index with a hash-linked event history. It does not replace evidence custody.

Do not paste regulator letters, legal advice, employee records or response attachments into `summary`, `legalBasis` or `responseSummary`. Ingest those documents through the evidence-custody API, then reference their immutable evidence IDs and versions in the case.

The workflow provides:

- tenant-isolated encrypted case records;
- deterministic, idempotent case identity from tenant, authority reference and received time;
- verified immutable evidence references;
- deadline states: `on_track`, `due_soon`, `overdue` and `complete`;
- response revalidation before submission and approval;
- response submitter/approver separation;
- response approver/final closer separation;
- exact high-impact confirmation text;
- hash-linked create, evidence, response, approval and terminal events;
- authenticated, rate-limited APIs;
- JIT-protected compliance approval, cancellation, closure and integrity verification.

BasitClaw does not determine whether a request is legally valid, privileged, overbroad, subject to secrecy restrictions or approved for cross-border transfer. Legal counsel, privacy, records management and the accountable business owner must make those decisions.

## Configuration

```bash
WORKFORCE_AUDIT_REGULATORY_CASE_MODE=shared-file
WORKFORCE_AUDIT_REGULATORY_CASE_DIR=/var/lib/basitclaw/workforce-audit-regulatory-cases
WORKFORCE_AUDIT_REGULATORY_CASE_KEYS='{"2026-q3":"<dedicated-base64-32-byte-key>"}'
WORKFORCE_AUDIT_REGULATORY_CASE_PRIMARY_KEY_ID=2026-q3
WORKFORCE_AUDIT_REGULATORY_CASE_DUE_SOON_HOURS=72
WORKFORCE_AUDIT_REGULATORY_CASE_MAX_CASES=10000
WORKFORCE_AUDIT_REGULATORY_CASE_MAX_EVIDENCE=500
```

Use a dedicated keyring separate from live evidence, preservation, notary and identity stores. Keep historical keys available while encrypted case indexes still reference them.

## Create a case

```text
POST /api/workforce-audit/regulatory-cases
```

```json
{
  "type": "regulator_request",
  "priority": "high",
  "authority": "National Labour Regulator",
  "jurisdiction": "PK-Federal",
  "requestReference": "NLR-2026-0042",
  "legalBasis": "Statutory workforce record inspection",
  "summary": "Provide verified payroll-control records for the stated review period.",
  "receivedAt": "2026-07-30T00:00:00.000Z",
  "dueAt": "2026-08-01T00:00:00.000Z",
  "owner": "audit.manager",
  "evidence": [
    { "evidenceId": "EVD-0123456789abcdef0123456789abcdef", "version": 1 }
  ]
}
```

Supported types:

- `regulator_request`
- `external_audit`
- `legal_request`
- `certification_review`

Priorities are `normal`, `high` and `critical`.

## Add evidence

```text
POST /api/workforce-audit/regulatory-cases/{caseId}/evidence
```

```json
{
  "evidence": [
    { "evidenceId": "EVD-0123456789abcdef0123456789abcdef", "version": 2 }
  ]
}
```

Evidence is reopened through the custody registry and its immutable version, SHA-256 and size are verified before the reference is added.

## Submit a response

```text
POST /api/workforce-audit/regulatory-cases/{caseId}/submit-response
```

```json
{
  "responseReference": "RESP-2026-0042",
  "responseSummary": "Verified evidence assembled and response prepared for the authority.",
  "confirmation": "SUBMIT RESPONSE RGC-..."
}
```

The case must be open and have at least one evidence reference. Every reference is revalidated before the response enters `response_pending`.

## Approve a response

```text
POST /api/workforce-audit/regulatory-cases/{caseId}/approve-response
```

```json
{
  "reason": "Response independently reviewed and approved",
  "confirmation": "APPROVE RESPONSE RGC-..."
}
```

The response submitter cannot approve it. This action maps to the existing JIT-protected compliance permission so production can require MFA and a current privileged-access grant.

## Close or cancel

```text
POST /api/workforce-audit/regulatory-cases/{caseId}/close
POST /api/workforce-audit/regulatory-cases/{caseId}/cancel
```

Exact confirmations:

```text
CLOSE CASE RGC-...
CANCEL CASE RGC-...
```

Only a response-approved case can close. The response approver cannot also perform final closure. Cancellation is available for non-terminal cases and must record a reason.

## Read and verify

```text
GET  /api/workforce-audit/regulatory-cases
GET  /api/workforce-audit/regulatory-cases/status
GET  /api/workforce-audit/regulatory-cases/{caseId}
GET  /api/workforce-audit/regulatory-cases/{caseId}/events
POST /api/workforce-audit/regulatory-cases/verify
```

List filters support `state`, `priority` and a bounded `limit`.

## Monitoring

Monitor:

- critical-priority cases;
- cases due soon or overdue;
- responses awaiting independent approval;
- cases with no evidence references;
- evidence revalidation failures;
- self-approval and closure-separation denials;
- event-chain or encrypted-index integrity failures;
- case-key rotation age and storage availability.

Deadline posture is an operational signal, not legal advice. Time-zone, service-of-process, public-holiday, extension and tolling rules remain an organisational responsibility.
