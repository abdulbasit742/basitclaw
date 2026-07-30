# Assurance export governance

Pass 21 introduced recipient-encrypted assurance bundles. Passes 22–27 add the approval and policy boundary that decides whether those bundles may be created or delivered:

22. encrypted export requests and requester/approver separation;
23. distinct-person approval quorum;
24. recipient trust policy and policy expiry;
25. purpose code and legal-basis enforcement;
26. residency-zone enforcement plus rejection/revocation delivery suppression;
27. hash-chained reporting, integrity verification and delivery acknowledgement linkage.

The Pass-21 bundle engine remains the only component that opens evidence bytes and creates recipient-encrypted packages. The governance layer stores no evidence content. It stores AES-256-GCM-encrypted request metadata and an encrypted bundle-to-request index.

## Fail-closed boundary

When `WORKFORCE_AUDIT_ASSURANCE_GOVERNANCE_MODE=shared-file`:

- direct calls to `createAssuranceBundle` fail with `EVIDENCE_ASSURANCE_GOVERNANCE_REQUIRED`;
- the existing `POST /api/workforce-audit/evidence/{evidenceId}/assurance-bundles` route creates a pending request rather than sealing immediately;
- the requester cannot approve their own request;
- one principal can count only once;
- Pass 21 is invoked only after the configured quorum;
- the selected recipient must have an enabled, unexpired policy;
- tenant, purpose code, legal basis and residency zone must all be allowed;
- policy metadata is embedded in the encrypted, digest-bound assurance manifest;
- rejected, revoked, expired or unlinked bundles are removed before the recipient response;
- a claimed or delivered bundle cannot be treated as if it never left custody;
- delivered history cannot be retroactively revoked;
- every governance transition is SHA-256 hash chained.

Revocation before a recipient claim prevents package delivery. It cannot erase a package already returned to a recipient. Suspected exposure after claim must be handled as an incident, with recipient coordination and legal review.

## Production configuration

```bash
WORKFORCE_AUDIT_ASSURANCE_GOVERNANCE_MODE=shared-file
WORKFORCE_AUDIT_ASSURANCE_GOVERNANCE_REQUIRED=true
WORKFORCE_AUDIT_ASSURANCE_GOVERNANCE_DIR=/var/lib/basitclaw/workforce-audit-assurance-governance
WORKFORCE_AUDIT_ASSURANCE_GOVERNANCE_KEYS='{"2026-q3":"<base64-32-byte-dedicated-governance-key>"}'
WORKFORCE_AUDIT_ASSURANCE_GOVERNANCE_PRIMARY_KEY_ID=2026-q3
WORKFORCE_AUDIT_ASSURANCE_APPROVAL_QUORUM=2
WORKFORCE_AUDIT_ASSURANCE_REQUEST_TTL_MINUTES=1440
WORKFORCE_AUDIT_ASSURANCE_GOVERNANCE_MAX_REQUESTS=100000
WORKFORCE_AUDIT_ASSURANCE_RECIPIENT_POLICIES='{"external-auditor":{"enabled":true,"allowedTenants":["tenant-a"],"allowedResidencyZones":["pk-primary"],"allowedPurposeCodes":["regulatory-exam"],"allowedLegalBases":["statutory-notice"],"validUntil":"2027-07-30T00:00:00.000Z"}}'
```

Use an encryption keyring separate from live evidence, preservation, notary, notary-governance and assurance-bundle record keys.

## Request workflow

The original Pass-21 route remains the entry point, but the confirmation changes to make the governance transition explicit:

```text
POST /api/workforce-audit/evidence/{evidenceId}/assurance-bundles
```

```json
{
  "version": 1,
  "recipientId": "external-auditor",
  "purpose": "Respond to an authorised regulatory examination",
  "purposeCode": "regulatory-exam",
  "legalBasis": "statutory-notice",
  "residencyZone": "pk-primary",
  "confirmation": "REQUEST EXPORT EVD-0123456789abcdef0123456789abcdef V1 TO external-auditor"
}
```

The request records immutable evidence identity and SHA-256 metadata, but it does not read or persist evidence content.

## Approval and sealing

```text
POST /api/workforce-audit/assurance-requests/{requestId}/approve
```

```json
{
  "confirmation": "APPROVE ASSURANCE AGR-0123456789abcdef0123456789abcdef"
}
```

After quorum, BasitClaw invokes Pass 21 using the original requester as the export actor and embeds:

- governance request ID;
- purpose code;
- legal basis;
- residency zone.

If bundle creation succeeds but request linkage is interrupted, an authorised operator may retry:

```text
POST /api/workforce-audit/assurance-requests/{requestId}/seal
```

with confirmation `SEAL ASSURANCE AGR-...`. Pass-21 bundle creation is deterministic and the governance link is idempotent.

## Rejection and revocation

```text
POST /api/workforce-audit/assurance-requests/{requestId}/reject
POST /api/workforce-audit/assurance-requests/{requestId}/revoke
```

Confirmations are `REJECT ASSURANCE AGR-...` and `REVOKE ASSURANCE AGR-...`. Both require a 10–500 character reason. Rejection is for unsealed requests. Revocation is for pending, approved or sealed requests before recipient claim/delivery.

## Read and reporting routes

```text
GET /api/workforce-audit/assurance-governance/status
GET /api/workforce-audit/assurance-governance/report
GET /api/workforce-audit/evidence/{evidenceId}/assurance-requests
GET /api/workforce-audit/assurance-requests/{requestId}
GET /api/workforce-audit/evidence/{evidenceId}/assurance-bundles
```

Reports aggregate by state, recipient, purpose code and residency zone. They never expose evidence bytes, bundle ciphertext, recipient private keys, recipient HMAC secrets or governance encryption keys.

## Recipient delivery control

The recipient routes remain the Pass-21 HMAC-authenticated pull and acknowledgement endpoints. The outer governance runtime intercepts them:

1. Pass 21 authenticates the recipient, applies replay protection and claims eligible encrypted bundles.
2. The governance layer checks each bundle link and current request state.
3. Only `sealed` governance requests are returned.
4. Suppressed delivery attempts are hash-chain recorded.
5. Acknowledgement is accepted only while delivery remains authorised.
6. Successful acknowledgement marks the governance request `delivered`.

Because the Pass-21 claim occurs before filtering, a suppressed bundle may temporarily remain in Pass-21 `claimed` state until its lease expires, but its encrypted package is not returned by the outer API.

## Operational checks

Monitor:

- pending requests and approval age;
- repeated self-approval or duplicate-approval denials;
- expired recipient policies;
- denied tenant, purpose, legal-basis and residency combinations;
- approved requests awaiting seal retry;
- revoked bundles and suppressed delivery attempts;
- claimed bundles approaching lease expiry;
- governance index or event-chain integrity failures;
- unusual recipient or residency distribution changes.

This control supports evidence-disclosure governance but does not itself establish legal authority, cross-border transfer compliance or recipient trustworthiness. Those decisions require approved policy owners and legal review.
