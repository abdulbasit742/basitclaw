# Recipient-signed assurance delivery receipts

Pass 29 strengthens governed assurance-bundle delivery with independently verifiable recipient signatures. HMAC continues to authenticate the recipient API request and prevent replay. A separate Ed25519 or RSA-PSS-SHA256 key signs the delivery statement itself.

BasitClaw verifies and commits the signed receipt to an encrypted append-only journal before it marks the bundle delivered or removes the sealed package.

## Receipt statement

The recipient signs this exact UTF-8 canonical string:

```text
basitclaw-assurance-delivery-receipt-v1
<recipientId>
<bundleId>
<packageSha256>
<receivedAt>
<receiptKeyId>
```

`receivedAt` must be an ISO timestamp within the configured delivery window. The signed package SHA-256 is the digest returned by the claim response, not the plaintext evidence digest.

Supported receipt algorithms:

- `ed25519`;
- `rsa-pss-sha256` with RSA keys of at least 2048 bits.

The recipient retains the receipt-signing private key. BasitClaw stores only the configured public key and fingerprint.

## Acknowledgement request

The acknowledgement remains HMAC-authenticated and replay-protected. Its JSON body is:

```json
{
  "claimToken": "<one-time-claim-token>",
  "packageSha256": "<sha256-from-claim-response>",
  "receipt": {
    "receivedAt": "2026-07-30T03:00:00.000Z",
    "keyId": "2026-q3",
    "signature": "<base64-asymmetric-signature>"
  }
}
```

When `WORKFORCE_AUDIT_ASSURANCE_RECEIPT_REQUIRED=true`, acknowledgement without `receipt` fails. Invalid signatures, unknown receipt keys and receipt timestamps outside the claim window fail before the bundle state changes.

## Commit ordering and crash recovery

The delivery sequence is:

1. verify HMAC request authentication and replay nonce;
2. verify the claim token and sealed-package SHA-256;
3. verify the recipient's asymmetric receipt signature;
4. commit the encrypted receipt record and encrypted journal index;
5. update the bundle to `delivered`;
6. erase the sealed package and claim-token hash from the bundle record.

If the receipt commit succeeds but the bundle update is interrupted, a retry with a fresh HMAC nonce returns the same receipt idempotently and completes delivery. The sealed package is never deleted before the receipt is durable.

## Journal integrity

Each encrypted receipt record binds:

- recipient ID;
- bundle ID;
- sealed-package SHA-256;
- claim and receipt times;
- receipt key ID, algorithm and public-key fingerprint;
- asymmetric signature;
- sequence number;
- previous record hash;
- current record hash.

Records use AES-256-GCM with a dedicated receipt keyring. The tenant index is encrypted separately and records the chain head. There is no receipt deletion API. When the configured maximum record count is reached, new acknowledgements fail closed rather than pruning evidence.

## Governance APIs

These routes require `governance:read`:

```text
GET  /api/workforce-audit/assurance-delivery-receipts
GET  /api/workforce-audit/assurance-delivery-receipts/{bundleId}
POST /api/workforce-audit/assurance-delivery-receipts/verify
```

The verification route reopens every encrypted record, validates identity and hash-chain continuity, checks for unindexed records and confirms the chain head.

## Production configuration

```bash
WORKFORCE_AUDIT_ASSURANCE_RECEIPT_MODE=shared-file
WORKFORCE_AUDIT_ASSURANCE_RECEIPT_REQUIRED=true
WORKFORCE_AUDIT_ASSURANCE_RECEIPT_DIR=/var/lib/basitclaw/workforce-audit-assurance-receipts
WORKFORCE_AUDIT_ASSURANCE_RECEIPT_KEYS='{"2026-q3":"<dedicated-base64-32-byte-key>"}'
WORKFORCE_AUDIT_ASSURANCE_RECEIPT_PRIMARY_KEY_ID=2026-q3
WORKFORCE_AUDIT_ASSURANCE_RECEIPT_MAX_RECORDS=100000
WORKFORCE_AUDIT_ASSURANCE_RECEIPT_CLOCK_SKEW_SECONDS=300
```

The existing recipient configuration gains a separate keyring:

```json
{
  "external-auditor": {
    "keys": { "2026-q3": "<HMAC request secret>" },
    "publicKeys": { "2026-q3": "<RSA bundle-encryption public key>" },
    "primaryPublicKeyId": "2026-q3",
    "receiptKeys": {
      "2026-q3": {
        "algorithm": "ed25519",
        "publicKeyPem": "<receipt-signing public key>"
      }
    }
  }
}
```

Do not reuse HMAC, bundle-encryption, evidence, preservation, notary, governance or alert keys for the receipt journal.

## Trust boundary

The receipt proves possession of the configured recipient receipt-signing private key and acceptance of the exact sealed-package digest at the stated time. It does not prove that the human signer had legal authority, that the recipient decrypted or reviewed every evidence item, that downstream copies were retained correctly, or that the receipt is a qualified electronic signature. Recipient identity proofing, authority, key custody and legal effect remain enterprise responsibilities.
