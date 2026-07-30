# Governed evidence disclosure

Pass 20 established append-only operational governance for revoked, compromised and superseded time authorities. Passes 21–27 build a controlled recipient-disclosure boundary on top of that trust decision:

21. approved recipient trust registry;
22. governed disclosure requests;
23. two distinct human approvers;
24. recipient-specific cryptographic sealing;
25. HMAC-authenticated pull delivery, acknowledgement, expiry and revocation;
26. tenant and recipient data residency enforcement;
27. tamper-evident disclosure reporting and verification.

BasitClaw never stores plaintext evidence in the disclosure queue. Evidence is opened from authenticated custody only after approval quorum is met, revalidated against immutable SHA-256 and size metadata, encrypted with a fresh AES-256-GCM key, and that key is wrapped to the approved recipient with RSA-OAEP-SHA-256.

## Security boundary

The disclosure service:

- requires clean evidence screening, immutable preservation, independent time attestations and Pass-20 operational notary governance;
- does not automatically release quarantined evidence;
- refuses disposed or inaccessible evidence versions;
- requires a verified preservation receipt covering current retention;
- requires operationally acceptable notary quorum, not merely valid historical signatures;
- prevents the requester from approving their own request;
- requires at least two distinct human approvers;
- seals packages only to configured RSA public keys of at least 2048 bits;
- enforces both tenant-approved and recipient-approved residency zones;
- authenticates recipient claim and acknowledgement requests with HMAC-SHA-256;
- rejects stale signatures, unsupported fields and replayed nonces;
- stores records under tenant-hashed directories using AES-256-GCM;
- records each transition in a SHA-256 hash chain;
- removes sealed package ciphertext and claim state after acknowledgement, revocation or expiry;
- exposes no plaintext evidence download endpoint.

Recipient encryption does not prove that the receiving organisation will handle data correctly after decryption. Contracts, legal authority, endpoint security, private-key custody, data residency and downstream retention remain external governance responsibilities.

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

Use a record-encryption keyring separate from live custody, preservation, notary and notary-governance keys. BasitClaw stores only recipient public keys; private keys remain inside the receiving organisation.

## Governance workflow

### Request

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

The service verifies clean screening, opens the requested version, authenticates preservation, and evaluates the Pass-20 operational notary posture. It creates encrypted request metadata but does not copy evidence content into the queue.

### Approve

```text
POST /api/workforce-audit/evidence-disclosures/{disclosureId}/approve
```

```json
{
  "confirmation": "APPROVE DISCLOSURE DSC-0123456789abcdef0123456789abcdef"
}
```

The requester cannot approve their own request and each principal counts once. At quorum, BasitClaw rechecks custody, preservation and current operational notary quorum immediately before sealing.

### Revoke

```text
POST /api/workforce-audit/evidence-disclosures/{disclosureId}/revoke
```

```json
{
  "confirmation": "REVOKE DISCLOSURE DSC-0123456789abcdef0123456789abcdef",
  "reason": "Recipient authority was withdrawn before delivery"
}
```

Revocation removes sealed package bytes and claim state. Acknowledged disclosures remain historical facts and cannot be retroactively revoked.

## Recipient pull protocol

```text
POST /api/workforce-audit/evidence-disclosure-recipient/claim
POST /api/workforce-audit/evidence-disclosure-recipient/{disclosureId}/acknowledge
```

Each request includes:

```text
X-BasitClaw-Recipient-Id
X-BasitClaw-Recipient-Key-Id
X-BasitClaw-Recipient-Timestamp
X-BasitClaw-Recipient-Nonce
X-BasitClaw-Recipient-Signature
```

The lower-case hexadecimal HMAC-SHA-256 signature covers:

```text
recipientId + "\n" +
keyId + "\n" +
timestamp + "\n" +
nonce + "\n" +
sha256(rawRequestBody)
```

The timestamp must be within five minutes of the BasitClaw clock. A nonce is accepted once and retained only for the replay window. Claims return a short-lived `claimToken` and recipient-sealed package. Acknowledgement uses a fresh signed nonce and the exact claim token.

## Recipient decryption

1. Select the RSA private key named by `publicKeyId`.
2. Unwrap `wrappedKey` with RSA-OAEP-SHA-256.
3. Exclude `algorithm`, `iv`, `tag`, `ciphertext`, `wrappedKey` and `publicKeyId` from package metadata.
4. Stable-sort metadata keys recursively and serialise as JSON.
5. Use that UTF-8 value as AES-GCM additional authenticated data.
6. Decrypt with AES-256-GCM using `iv` and `tag`.
7. Verify plaintext size and SHA-256 before use.

Failed unwrap, GCM authentication, digest mismatch or expired disclosure is a security incident.

## Data residency

A request is accepted only when its zone appears in both the tenant allowlist and recipient `allowedZones`. This is a policy gate, not geographic proof. Infrastructure owners must verify the store, network route, backups, endpoint and key systems actually operate in approved jurisdictions.

## Reporting and verification

```text
GET /api/workforce-audit/evidence-disclosures/status
GET /api/workforce-audit/evidence-disclosures/report
GET /api/workforce-audit/evidence/{evidenceId}/disclosures
GET /api/workforce-audit/evidence-disclosures/{disclosureId}
```

Reports expose counts by state, recipient and residency zone. Public records omit ciphertext, wrapped keys, local encryption metadata and claim-token hashes. Tenant verification authenticates every encrypted record and recomputes the complete event chain.

Monitor pending approvals, claimed packages, expiry, revocation, replay attempts, residency denials, key age, acknowledgement latency and integrity failures.

## Key rotation

Recipient RSA and HMAC keys rotate independently. Add new IDs first, complete a signed claim/decrypt/acknowledgement exercise, retain old keys while active packages reference them, and retire only after governance retention permits it. Changing a public key never rewrites an existing package; revoke and create a new request when resealing is necessary.
