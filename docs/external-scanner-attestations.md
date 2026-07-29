# External scanner attestations

BasitClaw accepts signed verdicts from approved antivirus, sandbox and DLP orchestration services. The integration is provider-neutral: the external scanner processes the original immutable evidence bytes, then submits a compact attestation bound to the tenant, evidence ID, version and SHA-256 digest.

External attestations never auto-release evidence. A clean verdict only satisfies an optional release prerequisite; the existing exact-confirmation and just-in-time privileged-access workflow still performs the release decision.

## Production configuration

```bash
WORKFORCE_AUDIT_EXTERNAL_SCANNER_MODE=enforce
WORKFORCE_AUDIT_EXTERNAL_SCANNER_REQUIRED_FOR_RELEASE=true
WORKFORCE_AUDIT_EXTERNAL_SCANNER_MAX_AGE_MINUTES=1440
WORKFORCE_AUDIT_EXTERNAL_SCANNER_CLOCK_SKEW_SECONDS=300
WORKFORCE_AUDIT_EXTERNAL_SCANNER_EVENT_RETENTION=10000
WORKFORCE_AUDIT_EXTERNAL_SCANNER_MAX_RECORDS=100000
WORKFORCE_AUDIT_EXTERNAL_SCANNER_PROVIDERS='{"managed-av":{"keys":{"2026-q3":"<base64-32-to-128-byte-hmac-secret>","2026-q2":"<previous-secret>"}}}'
```

The attestation registry reuses the evidence AES-256-GCM keyring and stores encrypted tenant-isolated indexes under the evidence directory. Provider HMAC secrets are used only for callback verification and are never written to the attestation index.

Modes:

- `disabled`: callbacks and release gating are unavailable.
- `observe`: valid attestations are retained and reported, but they do not affect release decisions.
- `enforce`: a latest `suspicious`, `malicious` or `error` verdict blocks release. When `REQUIRED_FOR_RELEASE=true`, absence of a recent clean verdict also blocks release.

## Callback endpoint

```text
POST /api/workforce-audit/external-scanner/attestations
Content-Type: application/json
```

The callback uses scanner-specific HMAC authentication rather than workforce user authentication.

Required headers:

```text
X-BasitClaw-Scan-Provider: managed-av
X-BasitClaw-Scan-Key-Id: 2026-q3
X-BasitClaw-Scan-Timestamp: 2026-07-30T00:00:00.000Z
X-BasitClaw-Scan-Nonce: scanner-generated-unique-value
X-BasitClaw-Scan-Signature: <lowercase-hex-hmac-sha256>
```

The timestamp must be canonical UTC ISO-8601 with milliseconds. Build the signature over:

```text
providerId + "\n" +
keyId + "\n" +
timestamp + "\n" +
nonce + "\n" +
sha256(rawRequestBody)
```

Then calculate lowercase hexadecimal `HMAC-SHA256` with the configured provider key.

Example body:

```json
{
  "attestationId": "managed-av:scan:01J4EXAMPLE000000000000000",
  "tenantId": "tenant-acme",
  "evidenceId": "EVD-0123456789abcdef0123456789abcdef",
  "version": 1,
  "contentSha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "verdict": "clean",
  "scannedAt": "2026-07-30T00:00:00.000Z",
  "engine": "Managed AV Gateway",
  "engineVersion": "8.4.2",
  "definitionsVersion": "2026.07.30.1",
  "findings": []
}
```

Verdicts are `clean`, `suspicious`, `malicious`, or `error`. Findings may contain only `ruleId`, `severity`, and `category`; matched values, content excerpts, file bytes, stack traces and provider secrets are rejected by schema validation.

The service verifies:

- configured provider and key ID;
- HMAC signature with constant-time comparison;
- timestamp clock-skew window;
- safe nonce and attestation identifiers;
- tenant and evidence identifier syntax;
- immutable version number and SHA-256 match;
- bounded engine metadata and privacy-minimised findings;
- duplicate attestation IDs are byte-equivalent, otherwise the request fails closed.

A new attestation returns HTTP `202`. An exact replay returns HTTP `200` with `duplicate=true`. Invalid authentication returns HTTP `401` without revealing whether the provider or key ID exists.

## Auditor APIs

These routes use normal workforce authentication and require `governance:read`:

```text
GET /api/workforce-audit/external-scanner/status
GET /api/workforce-audit/evidence/{evidenceId}/external-scans
GET /api/workforce-audit/evidence/{evidenceId}/external-scans?version=1&limit=100
```

Responses expose provider ID, key ID, verdict, scanner versions, hashes, timestamps, privacy-minimised findings and attestation-chain hashes. They never expose HMAC secrets, review reasons or evidence content.

## Release gate

The normal release request remains:

```text
POST /api/workforce-audit/evidence/{evidenceId}/screening/release
```

with exact confirmation:

```text
RELEASE QUARANTINE EVD-...
```

When enforcement is active:

1. the attestation must target the current immutable evidence version;
2. its SHA-256 digest must equal the local screening digest;
3. a latest non-clean verdict always blocks release;
4. when required-for-release is enabled, a recent clean verdict must exist;
5. the clean verdict must be within the configured maximum age;
6. release still requires the protected `backup:restore` permission and the normal JIT approval policy.

The local deterministic scan verdict remains immutable. An external clean verdict and a human release decision do not erase local findings or rewrite the scan report.

## Scanner orchestration boundary

BasitClaw does not transmit quarantined bytes to arbitrary internet endpoints. Production deployments should connect an approved scanner through a controlled ingestion pipeline, sidecar, private object-store event, or isolated malware-analysis service. That system scans the original immutable bytes and submits only the signed attestation.

This separation prevents unrestricted server-side egress, avoids embedding vendor credentials in evidence records, and supports scanners that require private networks, one-way transfer, data residency, or dedicated sandbox appliances.

## Key rotation

Add the new key ID before switching scanner signers. Accept both old and new keys during the overlap period. Remove an old key only after:

- all scanner instances use the new key;
- callback failures and unknown-key events remain clear for the approved observation period;
- retained attestations have been verified;
- the old secret has been destroyed in the authoritative secret manager.

Attestation records retain the historical key ID for audit evidence, but not the secret.

## Incident response

For invalid signatures, repeated timestamp failures, digest mismatches or malicious verdicts:

1. keep the evidence quarantined;
2. preserve evidence, screening and external-attestation directories and keyrings;
3. review security telemetry and the provider's scan job logs;
4. confirm the immutable version digest independently;
5. rotate scanner HMAC keys if compromise is suspected;
6. reject or retain evidence according to legal-hold and retention policy;
7. do not release until both technical and governance reviews are complete.
