# Evidence time-attestation governance

Pass 20 adds an append-only operational-governance layer for the independent authority attestations introduced in pass 19.

A governance event never deletes, edits or invalidates the original asymmetric signature. BasitClaw deliberately reports two separate conclusions:

- **Cryptographically valid** — the original authority signature, preservation challenge and pass-19 hash chain still verify.
- **Operationally acceptable** — no effective revocation, compromise or supersession event excludes that attestation from the current disposition quorum.

This distinction preserves historical proof while allowing present-day trust decisions to change safely.

## Supported events

- `attestation_revoked` — excludes one exact authority attestation.
- `attestation_superseded` — excludes one exact attestation and records its replacement.
- `provider_revoked` — excludes attestations from an authority provider.
- `key_revoked` — excludes attestations issued by one provider/key pair.

Every event binds an effective timestamp, reason code, human-readable reason, actor, sequence, previous hash, record hash, governance signing-key ID and HMAC signature. The complete tenant journal is AES-256-GCM encrypted with a dedicated keyring.

## Prospective and retroactive effects

Provider and key revocations support two operating modes:

- `retroactive: false` excludes attestations whose authority timestamp is on or after `effectiveAt`. Earlier attestations remain operationally acceptable.
- `retroactive: true` excludes all matching retained attestations, including those issued before `effectiveAt`. Use this for confirmed historical compromise only after security and legal review.

Attestation-specific revocation and supersession always target the exact immutable attestation ID once the event becomes effective.

Future-effective events are retained immediately but do not affect quorum until their `effectiveAt` timestamp.

## Governance routes

```text
GET  /api/workforce-audit/evidence-notary/governance/status
GET  /api/workforce-audit/evidence-notary/governance/events
POST /api/workforce-audit/evidence-notary/governance/events
POST /api/workforce-audit/evidence-notary/governance/verify
```

Reads and verification require `governance:read`. Writes use the manager-only preservation capability already assigned to audit managers and compliance administrators.

The events list supports `eventType`, `attestationId`, `providerId`, `keyId` and `limit` query filters.

## Exact confirmations

High-impact writes require one exact confirmation string:

```text
REVOKE ATTESTATION <attestationId>
SUPERSEDE ATTESTATION <originalAttestationId> WITH <replacementAttestationId>
REVOKE NOTARY PROVIDER <providerId>
REVOKE NOTARY KEY <providerId>/<keyId>
```

Example provider compromise:

```json
{
  "eventType": "provider_revoked",
  "providerId": "qualified-tsa-a",
  "effectiveAt": "2026-07-30T01:00:00.000Z",
  "retroactive": true,
  "reasonCode": "authority_compromise",
  "reason": "The authority trust boundary was confirmed compromised.",
  "confirmation": "REVOKE NOTARY PROVIDER qualified-tsa-a"
}
```

## Reason codes

- `authority_compromise`
- `key_compromise`
- `policy_withdrawn`
- `provider_termination`
- `administrative_error`
- `superseded`
- `legal_direction`
- `other`

Reasons must contain enough information for an independent reviewer to understand the operational decision, but must not include secrets, private keys or sensitive investigation evidence.

## Quorum and disposition

When `WORKFORCE_AUDIT_EVIDENCE_NOTARY_GOVERNANCE_REQUIRED_FOR_DISPOSITION=true`, every current immutable evidence version must have:

1. a verified pass-18 preservation receipt;
2. cryptographically valid pass-19 authority attestations;
3. the configured number of **operationally acceptable distinct providers** after applying every effective pass-20 event.

A cryptographic quorum can therefore remain valid while operational quorum fails. Disposition then fails with `409 EVIDENCE_TIME_ATTESTATION_GOVERNANCE_REQUIRED`.

The gate runs inside the registry rather than only in HTTP routing, so internal and non-HTTP disposition callers cannot bypass it.

## Supersession procedure

Supersession does not silently replace history.

1. Obtain and record the corrected authority attestation through the pass-19 signed callback.
2. Verify that both original and replacement belong to the same preservation archive.
3. Record `attestation_superseded` with the exact confirmation.
4. Re-run archive and tenant governance verification.
5. Confirm that the replacement restores the required distinct-provider quorum.

The old attestation remains cryptographically verifiable and appears as operationally superseded.

## Authority or key compromise procedure

1. Preserve incident evidence outside this journal through the normal evidence-custody workflow.
2. Determine provider, key, discovery time, effective compromise time and whether historical signatures are affected.
3. Obtain security, compliance and legal approval for prospective or retroactive treatment.
4. Record the provider or key revocation using the exact confirmation.
5. Verify the governance chain and inspect all archives that lost operational quorum.
6. Obtain replacement attestations from approved independent authorities.
7. Do not delete the original attestation, authority key configuration or governance event while retention requirements remain active.

## No undo or deletion

The journal exposes no update, delete, reinstate or rollback endpoint. A mistaken governance action remains part of the audit trail. Corrective action requires a new authority attestation and, where appropriate, a later supersession record. Historical policy interpretation remains an enterprise and legal responsibility.

## Production configuration

```bash
WORKFORCE_AUDIT_EVIDENCE_NOTARY_GOVERNANCE_MODE=shared-file
WORKFORCE_AUDIT_EVIDENCE_NOTARY_GOVERNANCE_REQUIRED_FOR_DISPOSITION=true
WORKFORCE_AUDIT_EVIDENCE_NOTARY_GOVERNANCE_DIR=/var/lib/basitclaw/workforce-audit-evidence-notary-governance
WORKFORCE_AUDIT_EVIDENCE_NOTARY_GOVERNANCE_KEYS='{"2026-q3":"<dedicated-base64-32-byte-key>"}'
WORKFORCE_AUDIT_EVIDENCE_NOTARY_GOVERNANCE_PRIMARY_KEY_ID=2026-q3
WORKFORCE_AUDIT_EVIDENCE_NOTARY_GOVERNANCE_SIGNING_SECRETS='{"2026-q3":"<dedicated-base64-32-to-128-byte-secret>"}'
WORKFORCE_AUDIT_EVIDENCE_NOTARY_GOVERNANCE_PRIMARY_SIGNING_KEY_ID=2026-q3
WORKFORCE_AUDIT_EVIDENCE_NOTARY_GOVERNANCE_MAX_EVENTS=100000
```

Governance encryption and signing keys must be separate from live evidence, preservation and pass-19 notary-store keys. Retain historical keys while any retained journal envelope or signed event references them.

## Monitoring

Alert on:

- provider or key compromise events;
- retroactive governance events;
- operational quorum loss;
- governance journal authentication or hash-chain failures;
- governance storage or lock unavailability;
- event-capacity thresholds;
- repeated denied or rate-limited governance writes;
- archives awaiting replacement authority attestations.

A successful cryptographic or governance verification does not establish an authority's legal qualification or evidentiary admissibility. Provider policy, jurisdiction, contractual status and legal procedure remain external responsibilities.
