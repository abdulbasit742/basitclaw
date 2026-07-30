# Governed evidence disclosure

Passes 20–27 add a controlled external-disclosure boundary for clean, immutably preserved and independently time-attested evidence. The release train is intentionally cohesive:

20. approved recipient trust registry;
21. governed disclosure request;
22. two distinct human approvers;
23. recipient-specific cryptographic sealing;
24. HMAC-authenticated pull delivery and acknowledgement;
25. expiry, revocation and replay protection;
26. tenant and recipient data residency enforcement;
27. tamper-evident reporting and verification.

BasitClaw never stores plaintext evidence in the disclosure queue. Evidence is opened from the authenticated custody registry only after the approval quorum is met, revalidated against immutable SHA-256 and size metadata, encrypted with a fresh AES-256-GCM key, and that key is wrapped to the approved recipient with RSA-OAEP-SHA-256.

## Security boundary

The disclosure service:

- requires enabled evidence screening, immutable preservation and independent time attestations;
- does not automatically release quarantined evidence;
- refuses disposed or inaccessible evidence versions;
- requires a verified preservation receipt covering the current retention date;
- requires time-attestation quorum when the notary layer is enabled;
- prevents the requester from approving their own request;
- requires at least two distinct approvers;
- seals packages only to configured RSA public keys of at least 2048 bits;
- enforces both tenant-approved and recipient-approved residency zones;
- authenticates recipient claim and acknowledgement requests with HMAC-SHA-256;
- rejects stale signatures and replayed nonces;
- stores disclosure records under tenant-hashed directories using AES-256-GCM;
- records every state transition in a SHA-256 hash chain;
- removes sealed package ciphertext and claim-token state after acknowledgement or revocation;
- exposes no plaintext evidence download endpoint.

Recipient encryption does not prove that the receiving organisation will handle data correctly after decryption. Contracts, regulatory authority, recipient endpoint security, private-key custody and downstream retention remain external governance responsibilities.

## Production configuration

```bash
WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_MODE=shared-file
WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_DIR=/var/lib/basitclaw/workforce-audit-evidence/.disclosures
WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_KEYS='{"2026-q3":"<separate-base64-32-byte-disclosure-record-key>"}'
WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_PRIMARY_KEY_ID=2026-q3
WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_APPROVAL_QUORUM=2
WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_TTL_MINUTES=1440
WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_CLAIM_LEASE_MS=300000
WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_MAX_PACKAGE_BYTES=25000000
WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_MAX_RECORDS=100000
WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_TENANT_ZONES='{"tenant-a":["pk-primary"]}'
WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_RECIPIENTS='{"regulator-one":{"publicKeyId":"2026-q3","publicKeyPem":"-----BEGIN PUBLIC KEY-----\n<approved-rsa-public-key>\n-----END PUBLIC KEY-----\n","hmacKeys":{"2026-q3":"<base64-32-to-128-byte-hmac-secret>"},"allowedZones":["pk-primary"]}}'
```

Use a disclosure-record encryption keyring separate from live evidence custody, preservation and notary keys. BasitClaw stores only recipient public keys; recipient private keys must remain in the receiving organisation's controlled key-management boundary.

## Governance workflow

### 1. Request

```text
POST /api/workforce-audit/evidence/{evidenceId}/disclosures
```

```json
{
  "version": 1,
  "recipientId": "regulator-one",
  "residencyZone": "pk-primary",
  "purpose": "Provide evidence for an authorised regulatory examination",
  "expiresAt": "2026-08-01T00:00:00.000Z"
}
```

The service verifies clean screening status, opens the requested immutable version, validates preservation and notary prerequisites, and creates only encrypted request metadata. It does not yet copy evidence content into the disclosure record.

### 2. Approve

```text
POST /api/workforce-audit/evidence-disclosures/{disclosureId}/approve
```

```json
{
  "confirmation": "APPROVE DISCLOSURE DSC-0123456789abcdef0123456789abcdef"
}
```

The requester cannot approve their own request. Each approving principal is counted once. After the configured quorum is reached, the service rechecks the evidence version, preservation receipt, notary quorum, SHA-256 and size, then creates the recipient-sealed package.

### 3. Revoke

```text
POST /api/workforce-audit/evidence-disclosures/{disclosureId}/revoke
```

```json
{
  "confirmation": "REVOKE DISCLOSURE DSC-0123456789abcdef0123456789abcdef",
  "reason": "Recipient authority was withdrawn before delivery"
}
```

Revocation deletes sealed package bytes and claim state from the encrypted record. Acknowledged disclosures are historical facts and cannot be retroactively revoked.

## Recipient pull protocol

Recipient workers use:

```text
POST /api/workforce-audit/evidence-disclosure-recipient/claim
POST /api/workforce-audit/evidence-disclosure-recipient/{disclosureId}/acknowledge
```

Every request includes:

```text
X-BasitClaw-Recipient-Id
X-BasitClaw-Recipient-Key-Id
X-BasitClaw-Recipient-Timestamp
X-BasitClaw-Recipient-Nonce
X-BasitClaw-Recipient-Signature
```

The signature is lower-case hexadecimal HMAC-SHA-256 over this canonical string:

```text
recipientId + "\n" +
keyId + "\n" +
timestamp + "\n" +
nonce + "\n" +
sha256(rawRequestBody)
```

The timestamp must be within five minutes of the BasitClaw clock. A nonce must contain 16–191 safe characters and is accepted only once. Claim bodies contain `tenantId` and an optional `limit`. A claim returns a short-lived `claimToken` and the sealed package. Acknowledgement must be signed with a fresh nonce and include the exact claim token.

## Recipient decryption

1. Use the recipient RSA private key identified by `publicKeyId`.
2. Unwrap `wrappedKey` with RSA-OAEP-SHA-256.
3. Reconstruct the canonical package metadata by excluding `algorithm`, `iv`, `tag`, `ciphertext`, `wrappedKey` and `publicKeyId`.
4. Stable-sort object keys recursively and serialise the metadata as JSON.
5. Use that UTF-8 value as AES-GCM additional authenticated data.
6. Decrypt `ciphertext` with AES-256-GCM using `iv` and `tag`.
7. Verify plaintext size and SHA-256 against package metadata before use.

A failed unwrap, GCM authentication failure, SHA-256 mismatch or expired disclosure must be treated as a security incident.

## Data residency

A request is accepted only when its `residencyZone` appears in both:

- `WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_TENANT_ZONES[tenantId]`; and
- the selected recipient's `allowedZones`.

This is an application policy gate, not geographic proof. Infrastructure owners must ensure the disclosure store, recipient endpoint, network route, backups and key systems actually operate within approved jurisdictions.

## Reporting and verification

```text
GET /api/workforce-audit/evidence-disclosures/status
GET /api/workforce-audit/evidence-disclosures/report
GET /api/workforce-audit/evidence/{evidenceId}/disclosures
GET /api/workforce-audit/evidence-disclosures/{disclosureId}
```

Reports expose counts by state, recipient and residency zone. Public records omit package ciphertext, wrapped keys, local record-encryption metadata and claim-token hashes. Tenant verification authenticates every encrypted record and recomputes every event-chain hash.

Monitor:

- requests awaiting approval;
- sealed or claimed packages approaching expiry;
- revocations and recipient authentication failures;
- replay attempts;
- residency-policy denials;
- recipient key and HMAC-key age;
- acknowledgement latency;
- disclosure-store integrity failures;
- unexpected growth in recipient or zone counts.

## Key rotation

Recipient RSA and HMAC keys rotate independently.

1. Add the new RSA public key and HMAC key under new IDs.
2. Keep old private and HMAC keys available to the recipient while unacknowledged packages reference them.
3. Update `publicKeyId` for newly sealed packages.
4. Complete a signed claim, decrypt and acknowledgement exercise.
5. Retire old keys only after no active disclosure depends on them and governance retention permits removal.

Changing a recipient public key never re-encrypts an already sealed package. Revoke the old disclosure and create a new request when resealing is required.
