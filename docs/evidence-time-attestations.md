# Independent evidence time attestations

Pass 19 adds independently signed time attestations for verified pass-18 preservation receipts. The control separates **when BasitClaw says it archived evidence** from **when an external authority cryptographically attests that the receipt existed**.

BasitClaw does not claim that a configured provider is a qualified trust service, RFC 3161 authority, court-certified notary or legally admissible authority. Those properties depend on the provider, contract, policy, jurisdiction and operating procedure. The platform verifies the configured asymmetric signature and preserves the resulting evidence.

## Trust boundary

Each authority retains its private key. BasitClaw stores only:

- the authority public key and algorithm;
- an encrypted attestation record;
- the authority timestamp, policy ID and nonce;
- hashes of the signed preservation receipt and encrypted preservation object;
- the hash-linked attestation sequence.

Supported signature algorithms:

- `ed25519`;
- `rsa-pss-sha256` with RSA keys of at least 2048 bits.

A disposition policy may require attestations from multiple distinct providers. Multiple records or keys from one provider count only once toward quorum.

## Canonical signature input

Authorities sign the UTF-8 bytes of this exact newline-separated value:

```text
basitclaw-evidence-time-attestation-v1
<providerId>
<keyId>
<tenantId>
<archiveId>
<receiptSha256>
<objectEnvelopeSha256>
<timestamp>
<policyId>
<nonce>
```

For Ed25519, sign these bytes directly. For RSA, use RSA-PSS with SHA-256 and MGF1-SHA-256. BasitClaw accepts standards-conforming authority-selected PSS salt lengths and verifies them with the configured public key. Return the signature as canonical base64.

The challenge values are available only through the authenticated governance route:

```text
GET /api/workforce-audit/evidence-preservation/{archiveId}/notary-challenge
```

Example challenge:

```json
{
  "tenantId": "tenant-a",
  "archiveId": "ARC-0123456789abcdef0123456789abcdef",
  "receiptSha256": "<sha256>",
  "objectEnvelopeSha256": "<sha256>",
  "archivedAt": "2026-07-30T00:00:00.000Z",
  "retentionUntil": "2033-07-30T00:00:00.000Z"
}
```

## Authority callback

```text
POST /api/workforce-audit/evidence-notary/attestations
Content-Type: application/json
```

```json
{
  "tenantId": "tenant-a",
  "archiveId": "ARC-0123456789abcdef0123456789abcdef",
  "providerId": "qualified-tsa-a",
  "keyId": "2026-q3",
  "receiptSha256": "<challenge receiptSha256>",
  "objectEnvelopeSha256": "<challenge objectEnvelopeSha256>",
  "timestamp": "2026-07-30T00:05:00.000Z",
  "policyId": "qualified-time-policy-v1",
  "nonce": "authority-unique-nonce-0001",
  "signature": "<canonical-base64-signature>"
}
```

The callback is authenticated by the asymmetric signature itself. Unknown providers, unknown keys, altered challenges, malformed signatures, reused provider/key nonces, timestamps before archival, excessive issuance delay and future timestamps fail closed.

## Governance routes

```text
GET  /api/workforce-audit/evidence-notary/status
GET  /api/workforce-audit/evidence-preservation/{archiveId}/notary-challenge
GET  /api/workforce-audit/evidence-preservation/{archiveId}/time-attestations
POST /api/workforce-audit/evidence-preservation/{archiveId}/time-attestations/verify
```

Governance routes require the existing `governance:read` permission. Callback submissions do not accept API keys or bearer tokens as a substitute for an authority signature.

## Disposition quorum

Configure:

```bash
WORKFORCE_AUDIT_EVIDENCE_NOTARY_MODE=shared-file
WORKFORCE_AUDIT_EVIDENCE_NOTARY_REQUIRED_FOR_DISPOSITION=true
WORKFORCE_AUDIT_EVIDENCE_NOTARY_MINIMUM_PROVIDERS=2
```

When required, every immutable evidence version must first have:

1. a verified current pass-18 preservation receipt;
2. valid time attestations bound to that exact archive;
3. the configured number of distinct authority providers.

Disposition fails with `409 EVIDENCE_TIME_ATTESTATION_REQUIRED` when preservation or authority quorum is incomplete. This gate runs inside the registry and applies to non-HTTP callers.

## Encrypted storage and chain integrity

The time-attestation index is tenant-isolated and AES-256-GCM encrypted with a dedicated keyring. The store records no authority private keys. Every accepted record contains a monotonically increasing sequence, previous hash and current hash. Verification checks:

- encryption authentication;
- tenant/index identity;
- sequence and hash-chain continuity;
- current preservation challenge binding;
- authority public-key signature;
- timestamp policy;
- distinct-provider quorum.

A reused nonce from the same provider/key is rejected even when other fields differ. An identical signed submission is idempotent.

## Key rotation

Authority-key rotation:

1. Add the new public key under a new key ID.
2. Ask the authority to sign new challenges with the new private key.
3. Keep historical public keys configured while retained attestations reference them.
4. Remove an old public key only after retention and legal review permit historical verification to cease.

Store-key rotation uses `WORKFORCE_AUDIT_EVIDENCE_NOTARY_KEYS` and `WORKFORCE_AUDIT_EVIDENCE_NOTARY_PRIMARY_KEY_ID`. Keep historical encryption keys while retained encrypted indexes reference them.

## Operational monitoring

Monitor:

- authority callback authentication failures;
- nonce replay attempts;
- timestamp-before-archive, future timestamp and delay violations;
- missing preservation receipts;
- archives below provider quorum;
- time-attestation store availability and capacity;
- hash-chain or signature verification failures;
- provider contract, qualification and policy changes;
- authority public-key expiry or compromise.

Periodically verify full tenant preservation and time-attestation chains using authorised offline procedures. A successful cryptographic verification does not replace legal review of the authority, policy ID, jurisdiction or evidence-admission rules.
