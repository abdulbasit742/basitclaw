# Dual-control assurance exports

Pass 22 prevents a single authenticated user from disclosing evidence to an external assurance recipient. Export intent is recorded first as an encrypted, expiring approval request bound to the exact tenant, evidence ID, immutable version, SHA-256 digest, recipient, purpose and requester.

## Control model

The requester cannot approve the same disclosure. Production defaults require two distinct approvers in addition to the requester; organisations may configure one approver for classic four-eyes control or up to five approvers for higher-risk evidence.

An approved request can be materialised exactly once. Recipient, purpose, version and digest are taken from the encrypted approval record, not from the materialisation request. A failed bundle-queue operation leaves the approval in `approved` state for safe retry; a successful operation records the resulting bundle ID and changes the approval to `consumed`.

## Production configuration

```bash
WORKFORCE_AUDIT_ASSURANCE_EXPORT_APPROVAL_MODE=shared-file
WORKFORCE_AUDIT_ASSURANCE_EXPORT_APPROVAL_REQUIRED=true
WORKFORCE_AUDIT_ASSURANCE_EXPORT_APPROVAL_DIR=/var/lib/basitclaw/workforce-audit-assurance-export-approvals
WORKFORCE_AUDIT_ASSURANCE_EXPORT_APPROVAL_KEYS='{"2026-q3":"<dedicated-base64-32-byte-key>"}'
WORKFORCE_AUDIT_ASSURANCE_EXPORT_APPROVAL_PRIMARY_KEY_ID=2026-q3
WORKFORCE_AUDIT_ASSURANCE_EXPORT_REQUIRED_APPROVALS=2
WORKFORCE_AUDIT_ASSURANCE_EXPORT_APPROVAL_TTL_MINUTES=1440
WORKFORCE_AUDIT_ASSURANCE_EXPORT_APPROVAL_RETENTION=10000
```

Use a dedicated encryption keyring. Do not reuse evidence, preservation, scanner, notary, governance, bundle or alert keys.

## Workflow

### 1. Request

```text
POST /api/workforce-audit/evidence/{evidenceId}/assurance-export-requests
```

```json
{
  "version": 1,
  "recipientId": "external-auditor",
  "purpose": "Independent regulatory workforce audit review",
  "confirmation": "REQUEST EXPORT EVD-0123456789abcdef0123456789abcdef V1 TO external-auditor"
}
```

The service authenticates the immutable evidence metadata before storing the request. Audit managers and compliance administrators use the existing `evidence:export` authority through the `evidence:export-request` policy adapter.

### 2. Review

```text
GET  /api/workforce-audit/assurance-export-approvals/status
GET  /api/workforce-audit/evidence/{evidenceId}/assurance-export-requests
GET  /api/workforce-audit/assurance-export-requests/{requestId}
POST /api/workforce-audit/assurance-export-requests/{requestId}/approve
POST /api/workforce-audit/assurance-export-requests/{requestId}/reject
POST /api/workforce-audit/assurance-export-requests/{requestId}/cancel
```

Approval and rejection require `privileged:approve`, which is assigned to compliance administrators. The requester may cancel only while the request remains pending. Rejection requires a reason.

### 3. Materialise

```text
POST /api/workforce-audit/evidence/{evidenceId}/assurance-bundles
```

```json
{
  "approvalRequestId": "AER-0123456789abcdef0123456789abcdef",
  "confirmation": "MATERIALIZE EXPORT AER-0123456789abcdef0123456789abcdef"
}
```

The materialiser cannot supply replacement recipient, version or purpose fields. BasitClaw retrieves the approved values, creates the recipient-encrypted bundle, then consumes the request.

## States

- `pending`: waiting for the configured number of distinct approvers;
- `approved`: quorum complete and available for materialisation;
- `rejected`: permanently refused with a recorded reason;
- `cancelled`: withdrawn by the requester before approval;
- `expired`: approval window elapsed before quorum;
- `consumed`: bundle successfully created and linked.

There is no reset, deletion or approval-reuse API. A materially changed purpose, recipient or evidence version requires a new request and fresh review.

## Failure handling

The approval record is stored as AES-256-GCM encrypted JSON under a tenant-hashed directory and protected by a cross-process file mutex. Temporary writes are fsynced and atomically renamed. Materialisation executes while the approval lock is held, which prevents two workers from consuming the same request concurrently.

Dual control reduces insider and accidental-disclosure risk. It does not establish the external recipient's legal authority, determine whether disclosure is lawful or replace privacy, labour, regulatory and legal review.
