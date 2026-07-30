# Evidence-notary request orchestration

Pass 21 automates delivery of pass-19 preservation challenges to approved independent time authorities without adding arbitrary outbound network targets.

Authorities pull work from BasitClaw, sign the request action with their existing Ed25519 or RSA-PSS private key, and later submit the independent time attestation through the pass-19 callback. BasitClaw stores no authority private key and sends no request to a provider-controlled URL.

## Security boundary

The request queue contains only:

- tenant and preservation archive identifiers inside an AES-256-GCM encrypted provider index;
- preservation receipt and encrypted-object SHA-256 values;
- archive and retention timestamps;
- lifecycle, actor, purpose and delivery metadata.

It never contains evidence bytes, preserved content, scanner packages, credentials or arbitrary URLs. Provider IDs are hashed in filesystem paths, and each authority has an independently locked encrypted index.

A successful request delivery does not establish legal qualification, RFC 3161 compliance, court admissibility or provider trust. The pass-19 asymmetric attestation and pass-20 operational-governance evaluation remain the source of those application-level decisions.

## Governance routes

```text
GET  /api/workforce-audit/evidence-notary/requests/status
POST /api/workforce-audit/evidence-notary/requests/verify
GET  /api/workforce-audit/evidence-preservation/{archiveId}/notary-requests
POST /api/workforce-audit/evidence-preservation/{archiveId}/notary-requests
POST /api/workforce-audit/evidence-notary/requests/{jobId}/requeue
```

Reads and verification require `governance:read`. Queue and requeue operations require `evidence:notarize`, which is assigned only to audit managers and compliance administrators.

Queue request:

```json
{
  "providerId": "qualified-tsa-a",
  "purpose": "Independent timestamp required for disposition quorum",
  "confirmation": "REQUEST NOTARY ARC-0123456789abcdef0123456789abcdef qualified-tsa-a"
}
```

Dead-letter requeue:

```json
{
  "purpose": "Approved retry after authority service recovery",
  "confirmation": "REQUEUE NOTARY NTR-0123456789abcdef0123456789abcdef"
}
```

An archive/provider pair is not queued when an attestation from that provider already exists.

## Authority pull routes

```text
POST /api/workforce-audit/evidence-notary/requests/claim
POST /api/workforce-audit/evidence-notary/requests/{jobId}/acknowledge
POST /api/workforce-audit/evidence-notary/requests/{jobId}/fail
```

These routes do not accept API-key or OIDC identity as a substitute for authority authentication. Each JSON request contains `action`, `providerId`, `keyId`, `timestamp`, `nonce`, action-specific fields and `signature`.

The canonical signed value is:

```text
basitclaw-evidence-notary-request-auth-v1
<action>
<providerId>
<keyId>
<normalised timestamp>
<nonce>
<SHA-256 of stable JSON request without signature>
```

Ed25519 signs this UTF-8 value directly. RSA authorities use RSA-PSS with SHA-256 and an approved 2048-bit-or-stronger key. The same public-key configuration used for pass-19 attestations authenticates these request actions.

Nonces must be unique per signed request. Replay records are encrypted and retained for twice the configured clock-skew interval. Invalid signatures are rejected before a provider queue is opened.

## Lifecycle

```text
pending -> inflight -> delivered -> completed
                    \-> pending     (retry)
                    \-> dead-letter
```

- `pending`: challenge is available to its configured authority.
- `inflight`: authority owns a time-bounded claim token.
- `delivered`: authority acknowledged receipt and BasitClaw is awaiting the signed attestation.
- `completed`: a matching pass-19 attestation was accepted.
- `dead-letter`: TTL, claim, retry or authority processing failed.

Expired claims return to pending when attempts and TTL remain. Pending requests expire at their TTL. Delivered requests dead-letter as `attestation_timeout` when no matching attestation arrives before expiry.

Every transition is appended to a SHA-256 chain. When old events are pruned, the retained chain stores an anchor sequence and hash rather than pretending the remaining event is genesis.

## Attestation-linked completion

A callback completes a request only when tenant, archive, provider, receipt digest and encrypted-object digest all match. If attestation storage succeeds but request completion temporarily fails, submitting the exact attestation again is idempotent and retries deterministic completion.

The original pass-19 attestation remains authoritative. A request record cannot manufacture quorum and never automatically disposes evidence.

## Production configuration

```bash
WORKFORCE_AUDIT_EVIDENCE_NOTARY_REQUEST_MODE=pull
WORKFORCE_AUDIT_EVIDENCE_NOTARY_REQUEST_REQUIRED=true
WORKFORCE_AUDIT_EVIDENCE_NOTARY_REQUEST_DIR=/var/lib/basitclaw/workforce-audit-evidence-notary-requests
WORKFORCE_AUDIT_EVIDENCE_NOTARY_REQUEST_KEYS='{"2026-q3":"<dedicated-base64-32-byte-key>"}'
WORKFORCE_AUDIT_EVIDENCE_NOTARY_REQUEST_PRIMARY_KEY_ID=2026-q3
WORKFORCE_AUDIT_EVIDENCE_NOTARY_REQUEST_TTL_MINUTES=1440
WORKFORCE_AUDIT_EVIDENCE_NOTARY_REQUEST_CLAIM_LEASE_MS=300000
WORKFORCE_AUDIT_EVIDENCE_NOTARY_REQUEST_MAX_ATTEMPTS=5
WORKFORCE_AUDIT_EVIDENCE_NOTARY_REQUEST_COMPLETED_RETENTION=10000
WORKFORCE_AUDIT_EVIDENCE_NOTARY_REQUEST_DEAD_LETTER_RETENTION=2000
WORKFORCE_AUDIT_EVIDENCE_NOTARY_REQUEST_EVENT_RETENTION=50000
WORKFORCE_AUDIT_EVIDENCE_NOTARY_REQUEST_CLOCK_SKEW_SECONDS=300
```

Request-store keys must be separate from evidence, preservation, attestation and governance keys. Enabling request delivery without pass-18 preservation and pass-19 time attestations fails startup.

## Rotation

1. Add a new authority public key to `WORKFORCE_AUDIT_EVIDENCE_NOTARY_PROVIDERS` while retaining the old key.
2. Authorities begin signing pull actions and attestations with the new key ID.
3. Verify request and attestation stores across every tenant.
4. Retain the old public key while any retained request, replay, attestation or governance decision references it.
5. Rotate request-store encryption by adding a new key and changing the request primary key ID; retain old encryption keys until every envelope has been rewritten or retired through approved retention.

## Monitoring

Alert on:

- request-store or mutex unavailability;
- repeated invalid authority signatures or replay attempts;
- dead-letter growth;
- claim recovery or attempt exhaustion;
- delivered requests approaching TTL without attestations;
- provider queues with sustained backlog;
- transition-chain verification failure;
- required request delivery operating in degraded state;
- provider revocation or key compromise from pass-20 governance.
