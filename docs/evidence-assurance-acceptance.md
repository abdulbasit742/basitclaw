# Verified assurance recipient acceptance receipts

Pass 22 strengthens the pass-21 assurance-bundle workflow. The original acknowledgement proved that a recipient possessed a valid claim token and knew the sealed-package SHA-256. It did not prove that the recipient decrypted the package or verified its manifest, sections and evidence bytes.

When acceptance mode is `enforce`, the legacy acknowledgement endpoint fails with `409 EVIDENCE_ASSURANCE_ACCEPTANCE_REQUIRED`. Delivery completes only after the recipient submits a digest-bound verification report created by the offline verifier.

## Security boundary

The recipient verification workflow checks:

- RSA-OAEP-SHA-256 content-key unwrapping;
- AES-256-GCM authentication;
- sealed plaintext SHA-256;
- package, tenant, evidence, version and recipient identity;
- manifest `bundleDigest`;
- the exact section-name set;
- every section SHA-256;
- evidence content base64, byte length and SHA-256;
- immutable evidence-version metadata;
- the governance-aware `operationallyAcceptable` snapshot carried by pass 21.

BasitClaw then validates the reported digests against the exact package it issued. Only after all checks pass does it execute the original pass-21 acknowledgement, remove sealed package bytes and issue an Ed25519-signed acceptance receipt.

The receipt proves that an authenticated recipient workflow reported successful verification of a specific package and that BasitClaw matched that report to its issuance record. It does **not** prove that a human read the evidence, that a regulator accepted it, or that legal disclosure obligations were satisfied.

## Recipient routes

```text
POST /api/workforce-audit/assurance-recipient/bundles/claim
POST /api/workforce-audit/assurance-recipient/bundles/{bundleId}/acceptance
POST /api/workforce-audit/assurance-recipient/bundles/{bundleId}/acknowledge
```

The old `/acknowledge` route remains for backward compatibility when acceptance mode is disabled. It is blocked when acceptance mode is `enforce`.

## Offline bundle verification

Save the claimed `sealedPackage` JSON and claim token in the recipient's controlled environment. The RSA private key never enters BasitClaw.

```bash
npm run assurance:verify -- \
  ./sealed-package.json \
  ./recipient-private-key.pem \
  ./claim-token.txt
```

The command returns an `acceptanceRequest` containing:

```json
{
  "claimToken": "...",
  "packageSha256": "...",
  "plaintextSha256": "...",
  "bundleDigest": "...",
  "sectionDigestsSha256": "...",
  "verifiedAt": "2026-07-30T03:00:00.000Z",
  "verifierVersion": "basitclaw-assurance-verifier/1"
}
```

The recipient must not edit this object before signing and submitting it.

## Acceptance HMAC

The recipient submits the JSON body with the existing pass-21 HMAC identity headers:

```text
x-basitclaw-recipient-id
x-basitclaw-recipient-key-id
x-basitclaw-recipient-timestamp
x-basitclaw-recipient-nonce
x-basitclaw-recipient-signature
```

The canonical string is:

```text
recipientId\nkeyId\nacceptance:{bundleId}\ntimestamp\nnonce\nsha256(rawBodyBytes)
```

The signature is HMAC-SHA-256 encoded as canonical base64. The timestamp must be inside the configured clock-skew window. Each canonical request is accepted once; a corrected request must use a fresh nonce.

Example response:

```json
{
  "success": true,
  "data": {
    "duplicate": false,
    "bundle": {
      "bundleId": "ASB-...",
      "state": "delivered",
      "acceptanceStatus": "verified"
    },
    "acceptanceReceipt": {
      "acceptanceId": "AAR-...",
      "verificationOutcome": "verified",
      "signingAlgorithm": "ed25519",
      "signature": "..."
    }
  }
}
```

## Acceptance receipt contents

The signed receipt binds:

- bundle, evidence and version IDs;
- recipient ID, HMAC key ID and RSA public-key ID;
- sealed package SHA-256;
- decrypted plaintext SHA-256;
- manifest bundle digest;
- section-digest-map SHA-256;
- evidence-content SHA-256;
- verification time and verifier version;
- exact recipient request-body SHA-256;
- acknowledgement and recording timestamps;
- Ed25519 signing key ID and fingerprint.

The public receipt omits the tenant ID. The tenant ID remains inside the signed body and encrypted acceptance record.

## Offline receipt verification

Use the tenant ID from the decrypted assurance package together with the trusted acceptance-signing public key:

```bash
npm run assurance:acceptance:verify -- \
  ./acceptance-receipt.json \
  ./trusted-acceptance-public-key.pem \
  tenant-identifier
```

The verifier reconstructs the signed body, verifies the Ed25519 signature, confirms the trusted public-key fingerprint and validates every digest field.

## Governance routes

```text
GET  /api/workforce-audit/evidence/{evidenceId}/assurance-bundles
POST /api/workforce-audit/assurance-bundles/{bundleId}/acceptance/verify
```

Bundle listings include:

- `acceptanceStatus: pending` while the bundle is pending or claimed;
- `acceptanceStatus: verified` after a valid acceptance;
- the privacy-minimised signed acceptance receipt when available.

Governance receipt verification reopens the encrypted acceptance record, verifies its Ed25519 signature and confirms that it matches the original issuance expectation.

## Persistence and privacy

The acceptance directory stores AES-256-GCM encrypted records containing expected digests and the signed receipt. It never stores:

- evidence plaintext;
- pass-21 sealed package bytes;
- RSA private keys;
- claim tokens;
- the raw recipient verification body.

Only the verification-body SHA-256 is retained in the receipt.

## Failure and recovery

- Digest mismatch leaves the pass-21 claim in its current state and does not delete the package.
- Invalid HMAC, stale timestamp or replayed nonce fails closed.
- If pass-21 acknowledgement succeeds but acceptance-record persistence is interrupted, the recipient can retry with a fresh nonce. The underlying delivered record is idempotent, and BasitClaw can complete the missing signed receipt.
- A conflicting acceptance report for an already accepted bundle is rejected.
- Missing acceptance encryption or signing keys prevents enforced startup.

## Production configuration

```bash
WORKFORCE_AUDIT_ASSURANCE_ACCEPTANCE_MODE=enforce
WORKFORCE_AUDIT_ASSURANCE_ACCEPTANCE_DIR=/var/lib/basitclaw/workforce-audit-assurance-acceptance
WORKFORCE_AUDIT_ASSURANCE_ACCEPTANCE_KEYS='{"2026-q3":"<dedicated-base64-32-byte-key>"}'
WORKFORCE_AUDIT_ASSURANCE_ACCEPTANCE_PRIMARY_KEY_ID=2026-q3
WORKFORCE_AUDIT_ASSURANCE_ACCEPTANCE_SIGNING_KEYS='{"2026-q3":"-----BEGIN PRIVATE KEY-----\n<ed25519-private-key>\n-----END PRIVATE KEY-----\n"}'
WORKFORCE_AUDIT_ASSURANCE_ACCEPTANCE_PRIMARY_SIGNING_KEY_ID=2026-q3
WORKFORCE_AUDIT_ASSURANCE_ACCEPTANCE_MAX_RECORDS=100000
```

Use keys dedicated to acceptance receipts. Do not reuse evidence, preservation, notary, governance, assurance-bundle or recipient RSA keys.

## Key rotation

1. Add a new AES-256-GCM acceptance-record key under a new ID.
2. Add a new Ed25519 private signing key under a new ID.
3. Change both primary IDs.
4. Distribute the new Ed25519 public key and fingerprint through an authenticated out-of-band channel.
5. Retain historical encryption keys and public signing keys while old receipts remain relevant.
6. Verify a newly issued receipt before retiring any old key.

## Operational monitoring

Monitor:

- legacy acknowledgement refusal counts;
- digest mismatch and replay denials;
- claimed bundles awaiting verified acceptance;
- delivered bundles without a signed receipt;
- acceptance receipt signature failures;
- recipient HMAC and RSA key age;
- verifier-version drift;
- acceptance-record capacity;
- acceptance latency from claim to verified delivery.

Recipient verification is a machine-verifiable protocol assertion. Human review, legal admissibility, regulatory acceptance and recipient-side retention remain outside BasitClaw.
