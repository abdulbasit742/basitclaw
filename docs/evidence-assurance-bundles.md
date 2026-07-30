# Governed evidence assurance bundles

Pass 21 adds controlled evidence handoff for approved external auditors, regulators and assurance providers. BasitClaw never sends bundles to arbitrary URLs. An authorised manager creates a recipient-bound export, and the approved recipient pulls an encrypted package through an HMAC-authenticated API.

## Security model

Each bundle contains one immutable evidence version and its assurance context:

- authenticated evidence bytes and SHA-256 metadata;
- evidence item and immutable version metadata;
- chain-of-custody events and verification head;
- deterministic screening decision;
- signed external scanner verdicts;
- preservation receipts;
- independent time attestations;
- current notary-governance decisions, including revoked or superseded attestations;
- a manifest with a SHA-256 digest for every section.

The package is serialised canonically in memory. A random AES-256-GCM key encrypts the package. That key is wrapped with RSA-OAEP-SHA256 to the recipient public key. The recipient private key remains outside BasitClaw. The sealed package is then stored inside a second AES-256-GCM server-side record using a dedicated bundle keyring.

No plaintext bundle, raw evidence file, recipient private key or arbitrary destination URL is stored in the outbox.

## Production configuration

```bash
WORKFORCE_AUDIT_ASSURANCE_BUNDLE_MODE=pull
WORKFORCE_AUDIT_ASSURANCE_BUNDLE_REQUIRED=true
WORKFORCE_AUDIT_ASSURANCE_BUNDLE_DIR=/var/lib/basitclaw/workforce-audit-assurance-bundles
WORKFORCE_AUDIT_ASSURANCE_BUNDLE_KEYS='{"2026-q3":"<base64-32-byte-key>"}'
WORKFORCE_AUDIT_ASSURANCE_BUNDLE_PRIMARY_KEY_ID=2026-q3
WORKFORCE_AUDIT_ASSURANCE_BUNDLE_TTL_MINUTES=1440
WORKFORCE_AUDIT_ASSURANCE_BUNDLE_CLAIM_LEASE_MS=300000
WORKFORCE_AUDIT_ASSURANCE_BUNDLE_MAX_CLAIM_BYTES=25000000
WORKFORCE_AUDIT_ASSURANCE_BUNDLE_RETENTION=10000
WORKFORCE_AUDIT_ASSURANCE_RECIPIENT_CLOCK_SKEW_SECONDS=300
WORKFORCE_AUDIT_ASSURANCE_RECIPIENTS='{"external-auditor":{"keys":{"2026-q3":"<hmac-secret>"},"primaryPublicKeyId":"2026-q3","publicKeys":{"2026-q3":"-----BEGIN PUBLIC KEY-----\n<rsa-public-key>\n-----END PUBLIC KEY-----\n"}}}'
```

Use keys dedicated to this boundary. Do not reuse evidence-custody, preservation, scanner, notary-governance or alert-signing keys.

## Governance routes

Audit managers and compliance administrators receive `evidence:export`.

```text
GET  /api/workforce-audit/assurance-bundles/status
POST /api/workforce-audit/evidence/{evidenceId}/assurance-bundles
GET  /api/workforce-audit/evidence/{evidenceId}/assurance-bundles
```

Request example:

```json
{
  "version": 1,
  "recipientId": "external-auditor",
  "purpose": "Independent regulatory workforce audit review",
  "confirmation": "EXPORT EVD-0123456789abcdef0123456789abcdef V1 TO external-auditor"
}
```

The confirmation must bind the exact evidence ID, immutable version and configured recipient. Before sealing, BasitClaw reopens and authenticates the evidence version, checks SHA-256 and size, verifies the custody chain and gathers the assurance records.

Legal-hold matter identifiers and reasons are excluded. The bundle explicitly separates historical cryptographic validity from current operational acceptability. Revoked, compromised or superseded time attestations remain visible with their governance decisions and cannot silently appear as acceptable proof.

## Recipient routes

```text
POST /api/workforce-audit/assurance-recipient/bundles/claim
POST /api/workforce-audit/assurance-recipient/bundles/{bundleId}/acknowledge
```

Recipient requests use `x-basitclaw-recipient-id`, `x-basitclaw-recipient-key-id`, `x-basitclaw-recipient-timestamp`, `x-basitclaw-recipient-nonce` and `x-basitclaw-recipient-signature`.

The HMAC-SHA256 canonical string is:

```text
recipientId\nkeyId\noperation\ntimestamp\nnonce\nsha256(rawBody)
```

`operation` is `claim` or `acknowledge:{bundleId}`. Nonces are recorded durably and cannot be replayed.

A successful claim returns a one-time claim token, package digest and sealed package. The recipient:

1. unwraps `wrappedKey` using its RSA private key with OAEP SHA-256;
2. decrypts `ciphertext` with AES-256-GCM using the supplied IV, tag and AAD;
3. verifies `plaintextSha256` and every manifest section digest;
4. verifies evidence SHA-256, custody chain, preservation receipts and time signatures;
5. evaluates the included operational notary-governance decisions;
6. acknowledges with the one-time claim token and package digest.

After acknowledgement, BasitClaw removes the sealed package and claim-token hash. Only privacy-minimised delivery metadata remains.

## Expiry and retry

Claims have a bounded lease. Undelivered bundles expire after the configured TTL and their sealed package is removed. Repeating the exact export after expiry re-verifies the source and reseals the deterministic bundle ID with fresh AES-GCM material. Claim responses obey a conservative aggregate byte ceiling.

## Trust boundary

The bundle proves what BasitClaw assembled and cryptographically delivered to the configured key. It does not prove the recipient organisation's legal authority, an authority's legal qualification, evidentiary admissibility or downstream handling. Recipient onboarding, key custody, contractual purpose, legal review and downstream retention remain enterprise responsibilities.
