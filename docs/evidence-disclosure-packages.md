# Signed selective evidence disclosure packages

Pass 22 adds governed, portable disclosure packages for workforce-audit evidence. A package is **metadata-only by default**. Evidence bytes are included only when an authorised user explicitly requests content and selects a pre-approved recipient whose RSA public key is already configured by operations.

BasitClaw signs each package with Ed25519 and returns it once to the authorised caller. The generated package is never stored by BasitClaw. Only an AES-256-GCM encrypted, hash-chained receipt is retained.

## Security boundary

The control provides:

- exact `EXPORT EVD-...` confirmation;
- the sensitive-action rate limit;
- the derived `evidence:export` permission for principals that already hold governance-read and evidence-preservation authority;
- the existing JIT privileged-access adapter for `evidence:export`;
- metadata-only output unless `includeContent` is exactly `true`;
- content sealing only to a configured recipient ID;
- no caller-supplied public key, URL or arbitrary destination;
- RSA-OAEP-SHA-256 key wrapping and AES-256-GCM content encryption;
- Ed25519 package signatures with an out-of-band public-key fingerprint;
- an encrypted, tenant-isolated disclosure-receipt chain;
- an offline verifier that performs no network requests.

A signed package does not establish legal admissibility, regulatory acceptance, completeness of every possible business record or permission to disclose personal information. Legal, privacy and records-management approval remain organisational responsibilities.

## Routes

```text
GET  /api/workforce-audit/evidence-disclosure/status
POST /api/workforce-audit/evidence/{evidenceId}/disclosure-packages
GET  /api/workforce-audit/evidence/{evidenceId}/disclosure-packages
POST /api/workforce-audit/evidence-disclosure/{packageId}/verify
```

Generation requires `evidence:export`. Listing and receipt verification require `governance:read`.

## Metadata-only request

The current immutable version is selected when `versions` is omitted.

```json
{
  "purpose": "Audit committee evidence review",
  "confirmation": "EXPORT EVD-0123456789abcdef0123456789abcdef"
}
```

The response contains:

- evidence identity and selected immutable version metadata;
- chain-of-custody verification heads;
- privacy-minimised screening reports;
- signed external scanner attestations;
- preservation receipts;
- independent time attestations with current revocation and supersession decisions;
- the disclosure policy and signature identity;
- no plaintext evidence bytes.

## Content-inclusive request

```json
{
  "versions": [1, 2],
  "purpose": "Approved external regulator submission",
  "confirmation": "EXPORT EVD-0123456789abcdef0123456789abcdef",
  "includeContent": true,
  "recipientId": "external-regulator"
}
```

The service rejects unknown recipients. It never accepts `publicKeyPem`, an outbound URL or a destination supplied by the requester. Each selected version is opened through the existing guarded evidence reader, so quarantine, rejection, disposal, tenant isolation, checksum verification and version identity remain enforced.

The total selected content must not exceed `WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_MAX_PACKAGE_BYTES`.

## Trust manifest

The manifest includes the records available from the existing controls:

1. evidence custody verification;
2. deterministic screening results;
3. signed external scanner verdicts;
4. immutable preservation receipts;
5. independent authority time attestations;
6. effective pass-20 governance decisions for revoked or superseded attestations.

For every preservation archive, `timeAttestationGovernance` distinguishes:

- **cryptographic validity** — whether the authority signature and original time-attestation chain still verify;
- **operational acceptability** — whether effective provider, key, attestation-revocation or supersession events permit the attestation to count today;
- **operational quorum** — whether enough distinct acceptable authorities remain after governance events are applied.

A revoked or superseded attestation remains visible as historical proof but is excluded from operational quorum. This prevents a package generated after a known compromise from presenting an obsolete raw quorum as currently trusted.

Legal-hold matter IDs and reasons are excluded. The manifest records only the privacy-minimised hold posture already exposed by the evidence registry.

The package signature covers the complete manifest and every sealed-content ciphertext. Altering the purpose, recipient, selected versions, trust records, governance decisions, ciphertext or signature causes offline verification to fail.

Governance decisions are a point-in-time snapshot at package generation. A later revocation cannot alter a package already delivered. Recipients should obtain a fresh package or independently query the approved governance process when current trust posture matters.

## Encrypted receipt history

BasitClaw stores only a receipt containing:

- package ID and SHA-256;
- manifest SHA-256;
- evidence ID and selected versions;
- generation actor and purpose;
- content-inclusion posture;
- recipient ID, key ID and public-key fingerprint;
- signing-key ID and fingerprint;
- sequence, previous hash and current hash.

The receipt index is tenant-isolated and encrypted with a dedicated disclosure keyring. Package JSON, sealed ciphertext and plaintext evidence are never stored in the receipt directory.

## Offline verifier

Verify signature and manifest identity:

```bash
npm run evidence:disclosure:verify -- \
  ./package.json \
  ./trusted-disclosure-signing-public-key.pem
```

Also decrypt and verify sealed content:

```bash
npm run evidence:disclosure:verify -- \
  ./package.json \
  ./trusted-disclosure-signing-public-key.pem \
  ./recipient-private-key.pem
```

The verifier checks:

- package format and ID;
- Ed25519 signature;
- trusted public-key fingerprint;
- package and manifest SHA-256;
- ciphertext SHA-256;
- RSA-OAEP key unwrapping;
- AES-GCM authentication;
- package/evidence/version identity;
- plaintext size and SHA-256.

The offline verifier authenticates the governance snapshot contained in the signed package; it does not discover governance events created after issuance.

The recipient private key should remain in an approved HSM, KMS, isolated workstation or controlled verification environment. The command-line path is intended for controlled offline verification and does not upload the key.

## Key rotation

### Package signing keys

1. Add a new Ed25519 private key under a new ID.
2. Set `WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_PRIMARY_SIGNING_KEY_ID` to that ID.
3. Distribute the matching public key and fingerprint through an authenticated out-of-band channel.
4. Retain old public keys while previously issued packages may need verification.

### Recipient keys

1. Add the new RSA public key under a new key ID.
2. Change the recipient `primaryKeyId` only after the recipient confirms private-key custody.
3. Keep old private keys available to the recipient while older packages remain relevant.
4. Never reuse scanner delivery keys unless the recipient and purpose are intentionally identical and approved.

### Receipt-encryption keys

Rotate `WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_KEYS` independently from evidence custody, preservation, notary and notary-governance keys. Historical keys must remain available while encrypted receipt indexes reference them.

## Operational controls

Monitor:

- disclosure generation and denial telemetry;
- JIT approval and expiry for `evidence:export`;
- metadata-only versus content-inclusive package counts;
- recipient-key age and fingerprint changes;
- signing-key age and public-key distribution;
- package byte-limit rejections;
- encrypted receipt-chain verification failures;
- unexpected export purposes or frequency;
- evidence exported while a legal hold is active;
- packages created before a later authority compromise or retroactive governance event;
- offline verification failures reported by recipients.

A generated package is returned once and never stored. The caller must transfer, retain and delete it through an approved disclosure procedure. BasitClaw cannot revoke a package after the recipient has received it; key compromise, erroneous disclosure, later governance changes and recipient misuse require incident response outside this service.
