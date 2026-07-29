# External scanner delivery lifecycle controls

This supplement defines the pass-17 controls that prevent stale jobs, oversized pull responses and ambiguous RSA key rotation.

## Expiry enforcement

The managed job lifecycle shares the same filesystem mutex and resource key as the encrypted outbox. Maintenance runs before queue, claim, acknowledgement, failure, attestation completion, list, status, verification and health operations.

- An expired `pending` job moves to `dead-letter` with reason `job_expired`.
- An expired `delivered` job that has not received a matching signed attestation moves to `dead-letter` with reason `attestation_timeout`.
- The sealed evidence package is removed during either transition.
- A governed repeat queue request reseals a dead-letter job with fresh AES material and resets its delivery budget.
- Required delivery reports dead letters as an unavailable tenant boundary until they are reviewed or requeued.

The configured job TTL therefore covers both initial collection and the wait for a signed scanner attestation.

## Claim byte budget

`WORKFORCE_AUDIT_EXTERNAL_SCAN_MAX_CLAIM_BYTES` is a conservative total-response ceiling for one claim request.

BasitClaw estimates the maximum sealed package size from `WORKFORCE_AUDIT_EVIDENCE_MAX_BYTES`, including base64 and envelope overhead. It derives `maximumClaimJobs` as:

```text
floor(maxClaimBytes / estimatedMaximumPackageBytes)
```

A signed claim whose requested `limit` exceeds that derived count is rejected with:

```text
413 EXTERNAL_SCAN_CLAIM_BUDGET_EXCEEDED
```

The request is rejected before any job changes state. Production must configure a budget large enough for at least one maximum-size package. The health response exposes only the configured budget, estimate and derived count; it never exposes package data.

## Explicit RSA delivery key selection

Each scanner provider may configure:

```json
{
  "primaryPublicKeyId": "2026-q3",
  "publicKeys": {
    "2026-q2": "<old RSA public key>",
    "2026-q3": "<current RSA public key>"
  }
}
```

`primaryPublicKeyId` must exist in `publicKeys`. New jobs are sealed only to that key, independent of JSON property order. Historical public keys remain configured while active or retained jobs reference them, and the scanner retains the corresponding private keys until those jobs are completed, delivered, expired or dead-lettered.

Rotation procedure:

1. Add the new RSA public key without removing the old key.
2. Set `primaryPublicKeyId` to the new key ID.
3. Deploy and verify that new job summaries show the new `deliveryKeyId`.
4. Keep the old private key available to the scanner for existing packages.
5. Remove the old key only after queue review proves no active job depends on it.

HMAC request-key rotation remains independent from RSA delivery-key rotation.
