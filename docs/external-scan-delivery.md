# Sealed external scanner delivery

Pass 17 adds a controlled pull channel for moving quarantined evidence bytes to an approved antivirus, sandbox or DLP worker. BasitClaw never posts evidence to an arbitrary URL. A scanner authenticates to BasitClaw, pulls a package encrypted to its own public key, scans the decrypted bytes inside its approved boundary, and submits the separately signed attestation introduced in pass 16.

A delivered package never auto-releases evidence. A clean signed verdict still passes through the existing quarantine confirmation, JIT privileged-access and governance controls.

## Security model

Each provider has two independent key families:

- HMAC keys authenticate claim, acknowledge, fail and attestation requests.
- RSA public keys encrypt scan-job content. The scanner retains the matching private key; BasitClaw must never receive or store that private key.

For each job BasitClaw generates a random 256-bit content key and 96-bit IV. Evidence bytes and metadata are encrypted with AES-256-GCM. The content key is wrapped with RSA-OAEP-SHA-256 using the selected provider public key. The queue contains only:

- a sealed ciphertext package;
- an RSA-wrapped content key;
- non-sensitive delivery state;
- AES-256-GCM-encrypted management metadata.

The queue does not contain plaintext evidence, filenames, tenant IDs or evidence IDs. Completed, acknowledged and dead-letter records drop the sealed ciphertext package.

## Production configuration

Use `config/evidence-screening.production.env.example` as the baseline.

```bash
WORKFORCE_AUDIT_EXTERNAL_SCANNER_MODE=enforce
WORKFORCE_AUDIT_EXTERNAL_SCANNER_REQUIRED_FOR_RELEASE=true
WORKFORCE_AUDIT_EXTERNAL_SCAN_DELIVERY_MODE=pull
WORKFORCE_AUDIT_EXTERNAL_SCAN_DELIVERY_REQUIRED=true
WORKFORCE_AUDIT_EXTERNAL_SCAN_DELIVERY_DIR=/var/lib/basitclaw/workforce-audit-evidence/.external-scan-jobs
WORKFORCE_AUDIT_EXTERNAL_SCANNER_PROVIDERS='{"managed-av":{"keys":{"2026-q3":"<base64-hmac-secret>"},"publicKeys":{"2026-q3":"-----BEGIN PUBLIC KEY-----\n<rsa-public-key>\n-----END PUBLIC KEY-----\n"}}}'
```

RSA delivery keys must be at least 2048 bits. Use separate private keys per scanner provider and environment. Store private keys in the scanner's approved HSM, KMS or secret manager.

## Governance routes

Audit managers and compliance administrators receive the `evidence:scan` permission.

```text
POST /api/workforce-audit/evidence/{evidenceId}/external-scan-jobs
GET  /api/workforce-audit/evidence/{evidenceId}/external-scan-jobs
GET  /api/workforce-audit/external-scan-delivery/status
```

Queue body:

```json
{
  "providerId": "managed-av",
  "version": 1
}
```

Only a quarantined immutable version can be queued. BasitClaw reopens the encrypted evidence object internally, authenticates its AES-GCM envelope, checks identity, SHA-256 and size, and compares those values with the screening report before creating the job. The deterministic job ID makes repeated queue requests idempotent.

## Scanner pull routes

```text
POST /api/workforce-audit/external-scanner/jobs/claim
POST /api/workforce-audit/external-scanner/jobs/{jobId}/acknowledge
POST /api/workforce-audit/external-scanner/jobs/{jobId}/fail
```

Claim body:

```json
{ "limit": 5 }
```

Acknowledge body:

```json
{ "claimToken": "<claim-token>" }
```

Failure body:

```json
{
  "claimToken": "<claim-token>",
  "retryable": true,
  "reasonCode": "sandbox_capacity"
}
```

Every request uses the same HMAC-SHA256 canonical string as external attestations:

```text
providerId + "\n" +
keyId + "\n" +
ISO8601(timestamp) + "\n" +
nonce + "\n" +
sha256(rawRequestBody)
```

Required headers:

```text
X-BasitClaw-Scan-Provider
X-BasitClaw-Scan-Key-Id
X-BasitClaw-Scan-Timestamp
X-BasitClaw-Scan-Nonce
X-BasitClaw-Scan-Signature
```

The nonce must be unique. BasitClaw stores a short-lived digest-only replay marker on the shared filesystem. Reusing the same signed request returns `401 EXTERNAL_SCAN_AUTHENTICATION_FAILED` with reason `replay_detected`.

## Package decryption

A claimed job returns `jobId`, `claimToken`, `claimExpiresAt` and `package`.

The scanner worker must:

1. Validate `format`, `version`, `algorithm`, `providerId`, `deliveryKeyId`, `jobId` and expiry.
2. Base64-decode `wrappedKey` and unwrap it with the matching RSA private key using OAEP SHA-256.
3. Base64-decode `aad`, `iv`, `tag` and `ciphertext`.
4. Verify `ciphertextSha256` before decryption.
5. Decrypt with AES-256-GCM using the unwrapped key, IV, authentication tag and supplied AAD.
6. Parse the JSON payload and validate its `jobId`, `contentSha256`, `sizeBytes` and expiry.
7. Base64-decode `contentBase64`, verify SHA-256 and size again, then scan the bytes.
8. Zero temporary plaintext buffers and delete temporary files according to the approved scanner procedure.
9. Submit a signed external attestation for the same tenant, evidence ID, version, SHA-256 and provider.

The decrypted payload format is `basitclaw-external-scan-job-payload`, version `1`.

## State model

- `pending`: sealed package is waiting for a provider claim.
- `inflight`: provider owns a time-limited claim.
- `delivered`: provider acknowledged package receipt; the queued ciphertext is removed.
- `completed`: a matching signed attestation was accepted; the queued ciphertext is removed.
- `dead-letter`: delivery expired, exceeded attempts or failed permanently; the queued ciphertext is removed.

Expired claims return to `pending` while the job TTL and attempt budget remain valid. Otherwise they move to `dead-letter`. Required delivery treats dead letters as an unavailable production boundary.

An attestation may arrive before acknowledgement. It atomically completes the deterministic matching job and invalidates any outstanding claim. A later acknowledgement is rejected because the claim is no longer owned.

## Rotation

HMAC and RSA delivery keys rotate independently.

1. Add the new HMAC key and RSA public key under new key IDs.
2. Deploy BasitClaw with both old and new key IDs retained.
3. Configure scanner workers with the new HMAC key and matching RSA private key.
4. Confirm new jobs use the new `deliveryKeyId` and new requests use the new HMAC `keyId`.
5. Keep the old RSA private key available until every job sealed to it is completed, delivered, expired or dead-lettered.
6. Remove old public and HMAC keys only after queue and attestation review confirms no dependency remains.

## Operational checks

Monitor:

- pending and inflight age;
- dead-letter count and reason codes;
- repeated authentication failures or replay detections;
- claim recovery frequency;
- jobs delivered without a timely attestation;
- delivery key IDs still represented by active jobs;
- scanner clock skew;
- outbox filesystem capacity and atomic rename semantics.

The shared-file outbox requires a durable, strongly consistent filesystem with reliable atomic directory and rename operations. Do not place it on an eventually consistent object-store mount.
