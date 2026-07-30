# Governed evidence disclosures

Pass 20 adds recipient-bound disclosure packages for selected immutable evidence versions. BasitClaw does not email evidence, call arbitrary recipient URLs or create plaintext download links. It creates a sealed package that only the configured recipient RSA private key can decrypt.

## Security boundary

The disclosure workflow provides:

- encrypted tenant-isolated request and event records;
- a hash-linked request, approval, rejection, packaging and revocation history;
- requester/approver separation;
- a configurable quorum of distinct approvers;
- existing JIT-protected `backup:restore` authorisation for approval, rejection, revocation and integrity verification;
- evidence revalidation at request time and again at packaging time;
- optional mandatory current preservation receipts and independent time-attestation quorum;
- RSA-OAEP-SHA256 key wrapping and AES-256-GCM package encryption;
- recipient key fingerprint binding;
- create-only package files;
- expiry and revocation checks before package retrieval;
- no recipient private-key storage.

A sealed package is still sensitive. Transfer it only through an approved enterprise channel. BasitClaw does not establish the recipient's legal authority, identity, jurisdiction, purpose limitation or downstream retention obligations.

## Configuration

```bash
WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_MODE=shared-file
WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_DIR=/var/lib/basitclaw/workforce-audit-evidence-disclosures
WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_KEYS='{"2026-q3":"<dedicated-base64-32-byte-key>"}'
WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_PRIMARY_KEY_ID=2026-q3
WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_MINIMUM_APPROVERS=2
WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_MAX_ITEMS=100
WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_MAX_BYTES=25000000
WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_MAX_TTL_HOURS=168
WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_REQUIRE_PRESERVATION=true
WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_REQUIRE_TIME_ATTESTATION=true
```

Use a disclosure keyring that is separate from live evidence, preservation and notary keys. The recipient public key must be RSA and at least 2048 bits. The recipient retains the matching private key in its own HSM, KMS or approved secret manager.

## Workflow

### 1. Create a request

```text
POST /api/workforce-audit/evidence-disclosures
```

```json
{
  "recipientId": "regulator-one",
  "recipientKeyId": "2026-q3",
  "recipientPublicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
  "caseReference": "REG-2026-0042",
  "purpose": "Controlled regulatory evidence disclosure",
  "expiresAt": "2026-08-01T01:00:00.000Z",
  "evidence": [
    { "evidenceId": "EVD-0123456789abcdef0123456789abcdef", "version": 1 }
  ]
}
```

The requester must have governance read access. The service authenticates every selected immutable version, checks its size and SHA-256, and records preservation/notary evidence when required. No evidence bytes are stored in the request index.

### 2. Approve

```text
POST /api/workforce-audit/evidence-disclosures/{requestId}/approve
```

```json
{
  "reason": "Independent disclosure approval completed",
  "confirmation": "APPROVE DISCLOSURE DSR-..."
}
```

The requester cannot approve the request. Each actor can approve once. Approval uses the existing JIT-protected restore permission, so production deployments can require step-up authentication and a current privileged-access grant.

When the approval quorum is reached, BasitClaw reopens and verifies every selected evidence version again. If any version, preservation receipt, notary quorum or package limit fails, the final approval is not committed.

### 3. Retrieve the sealed package

```text
GET /api/workforce-audit/evidence-disclosures/{requestId}/package
```

The response contains only:

- package and request identifiers;
- the recipient key ID and SHA-256 fingerprint;
- RSA-OAEP wrapped AES key;
- AES-GCM IV, authentication tag, AAD and ciphertext;
- plaintext SHA-256 and evidence count;
- seal and expiry timestamps.

The plaintext manifest is inside the ciphertext and includes evidence bytes as base64 plus immutable hashes, preservation archive IDs and time-attestation provider IDs.

### 4. Reject or revoke

```text
POST /api/workforce-audit/evidence-disclosures/{requestId}/reject
POST /api/workforce-audit/evidence-disclosures/{requestId}/revoke
```

Confirmations must be exactly:

```text
REJECT DISCLOSURE DSR-...
REVOKE DISCLOSURE DSR-...
```

Revocation prevents later package retrieval but does not delete the sealed package or audit history. This preserves evidence of what was approved and subsequently withdrawn.

## Other routes

```text
GET  /api/workforce-audit/evidence-disclosures
GET  /api/workforce-audit/evidence-disclosures/status
GET  /api/workforce-audit/evidence-disclosures/{requestId}
GET  /api/workforce-audit/evidence-disclosures/{requestId}/events
POST /api/workforce-audit/evidence-disclosures/verify
```

## Recipient decryption

1. Base64-decode `wrappedKey`.
2. Decrypt it using RSA-OAEP with SHA-256 and the recipient private key.
3. Base64-decode `iv`, `authTag`, `aad` and `ciphertext`.
4. Decrypt with AES-256-GCM using the unwrapped key, IV, AAD and authentication tag.
5. Verify the plaintext SHA-256 against `plaintextSha256`.
6. Parse the JSON manifest and verify every evidence content SHA-256 and size.

A wrong private key, altered wrapped key, AAD, IV, authentication tag or ciphertext must fail decryption.

## Operational controls

Monitor:

- requests awaiting approval;
- self-approval and duplicate-approval attempts;
- failed evidence, preservation or notary revalidation;
- package-size failures;
- expired and revoked disclosures;
- sealed-package integrity failures;
- recipient key rotation or compromise;
- the approved transfer channel and recipient acknowledgement.

Never paste recipient private keys into BasitClaw. Never transfer the platform's encrypted request index as a substitute for the recipient-sealed package.
