# Recipient-bound evidence disclosure packages

Pass 29 adds governed disclosure packages for regulators, external auditors and legal counsel. It does not add a general evidence download endpoint.

A package can be created only by an authenticated principal with `evidence:export`. Every selected immutable version must:

- reopen successfully from encrypted evidence custody;
- match its recorded SHA-256 and size;
- have a verified preservation receipt covering the current retention date;
- satisfy the configured distinct-authority time-attestation quorum when `WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_REQUIRE_NOTARY_QUORUM=true`.

## Cryptographic envelope

The disclosure payload contains selected evidence bytes plus preservation receipts and time-attestation proofs. BasitClaw:

1. serialises the payload deterministically;
2. encrypts it with a fresh AES-256-GCM data key;
3. wraps that key to the recipient's RSA public key using RSA-OAEP-SHA-256;
4. signs the complete encrypted package manifest with a dedicated Ed25519 signing key;
5. stores package lifecycle metadata in a separate AES-256-GCM encrypted tenant index.

The package itself is recipient-bound. BasitClaw never receives or stores the recipient's RSA private key.

The embedded Ed25519 public key makes offline signature verification possible, but it is not self-authenticating. Recipients must compare `signingPublicKeyFingerprint` with a fingerprint received through an approved out-of-band channel.

## Routes

```text
GET  /api/workforce-audit/evidence-disclosures/status
POST /api/workforce-audit/evidence-disclosures
GET  /api/workforce-audit/evidence-disclosures
GET  /api/workforce-audit/evidence-disclosures/{packageId}
GET  /api/workforce-audit/evidence-disclosures/{packageId}/download
POST /api/workforce-audit/evidence-disclosures/{packageId}/verify
POST /api/workforce-audit/evidence-disclosures/{packageId}/revoke
```

All routes require `evidence:export`. Audit managers and compliance administrators receive that permission; auditors and viewers do not.

## Create request

```json
{
  "recipientKeyId": "regulator-2026-q3",
  "recipientPublicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
  "expiresAt": "2026-08-06T12:00:00.000Z",
  "maximumDownloads": 1,
  "purpose": "Regulatory payroll-controls evidence disclosure",
  "items": [
    { "evidenceId": "EVD-0123456789abcdef0123456789abcdef", "version": 1 }
  ],
  "confirmation": "DISCLOSE 1 EVIDENCE VERSIONS TO regulator-2026-q3"
}
```

Selections are sorted before sealing, and exact repeated requests are idempotent. Duplicate evidence/version selections and unsupported fields are rejected.

## Recipient decryption

The recipient should:

1. verify the Ed25519 signature over the canonical package object excluding `signature`;
2. compare the signing-key fingerprint through the approved out-of-band channel;
3. unwrap `wrappedKey` with the recipient RSA private key using OAEP SHA-256;
4. decrypt `ciphertext` with AES-256-GCM using `iv`, `tag`, and AAD:
   `basitclaw-evidence-disclosure-v1:<packageId>:<recipientKeyFingerprint>`;
5. verify the plaintext SHA-256 and byte length against `payloadSha256` and `payloadSizeBytes`;
6. independently verify each preservation receipt and time-attestation signature using retained trusted keys.

The JSON transport is intentionally dependency-free. It is not CMS, ASiC, RFC 3161, a qualified electronic seal, or a court-certified evidence format unless an external approved process establishes those properties.

## Expiry and download limits

Download eligibility is checked under the tenant disclosure lock. A package becomes unavailable when:

- its expiry time is reached;
- its download count reaches `maximumDownloads`;
- it is revoked;
- its file, encrypted metadata, signature, or hashes fail verification.

The download count is committed before the encrypted package is returned. Operators should therefore treat an interrupted response as a consumed delivery attempt.

## Revocation boundary

Revocation requires this exact confirmation:

```text
REVOKE DISCLOSURE DSP-...
```

Revocation prevents future BasitClaw downloads. It cannot retract or erase a package already downloaded by a recipient. For that reason, use short expiries, the minimum practical download count, recipient-specific RSA keys, and contractual handling requirements.

## Storage and key separation

Production requires dedicated values for:

```text
WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_KEYS
WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_PRIMARY_KEY_ID
WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_SIGNING_PRIVATE_KEYS
WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_PRIMARY_SIGNING_KEY_ID
```

Do not reuse live evidence, preservation, scanner, notary or API credential keys. Keep signing private keys in an approved secret manager. Retain historical public verification keys for the full package governance period.

## Operational monitoring

Monitor:

- created, duplicate, downloaded and revoked telemetry events;
- authentication and authorisation failures;
- expiry and download-limit denials;
- package-signature or encrypted-index integrity failures;
- signing-key age and out-of-band fingerprint publication;
- recipient key age, ownership and revocation status;
- disclosure directory capacity and backup policy.

BasitClaw exposes no plaintext disclosure payload, recipient private key, general evidence download endpoint or arbitrary outbound delivery URL.
