# Immutable evidence preservation

Pass 18 adds a governed write-once preservation boundary for immutable audit-evidence versions. It is designed for a separately controlled filesystem backed by WORM or object-lock storage.

BasitClaw encrypts each preservation object with AES-256-GCM, creates an independently encrypted HMAC-signed receipt, verifies the original evidence checksum before writing, and never exposes a preservation-content download or deletion endpoint.

## Security boundary

The application provides:

- tenant-hashed directories and deterministic archive IDs;
- create-only file writes using exclusive filesystem creation;
- AES-256-GCM authenticated encryption for objects and receipts;
- independent HMAC-SHA-256 receipt signing;
- immutable evidence identity, version, SHA-256, size and retention-date binding;
- exact receipt-to-object envelope verification;
- cross-process filesystem locking;
- recovery when an object was committed but its receipt was interrupted;
- no deletion endpoint and no archive-content retrieval endpoint.

This control does not make an ordinary filesystem WORM. Production infrastructure must mount a backend that independently prevents overwrite and deletion for the required retention period. Examples include an approved object-lock gateway, compliance-mode immutable volume or regulated archive appliance. Set `WORKFORCE_AUDIT_EVIDENCE_PRESERVATION_IMMUTABLE_BACKEND_CONFIRMED=true` only after infrastructure owners verify that property.

## Production configuration

```bash
WORKFORCE_AUDIT_EVIDENCE_PRESERVATION_MODE=shared-file
WORKFORCE_AUDIT_EVIDENCE_PRESERVATION_REQUIRED_FOR_DISPOSITION=true
WORKFORCE_AUDIT_EVIDENCE_PRESERVATION_DIR=/mnt/evidence-object-lock/basitclaw
WORKFORCE_AUDIT_EVIDENCE_PRESERVATION_KEYS='{"2026-q3":"<base64-32-byte-archive-key>"}'
WORKFORCE_AUDIT_EVIDENCE_PRESERVATION_PRIMARY_KEY_ID=2026-q3
WORKFORCE_AUDIT_EVIDENCE_PRESERVATION_SIGNING_SECRETS='{"2026-q3":"<base64-32-to-128-byte-signing-secret>"}'
WORKFORCE_AUDIT_EVIDENCE_PRESERVATION_PRIMARY_SIGNING_KEY_ID=2026-q3
WORKFORCE_AUDIT_EVIDENCE_PRESERVATION_IMMUTABLE_BACKEND_CONFIRMED=true
```

Use archive encryption keys and receipt-signing secrets that are separate from the live evidence-custody keys. Keep historical keys available until every retained archive using them has passed its retention and governance requirements.

## Governance routes

Audit managers and compliance administrators receive `evidence:preserve`.

```text
GET  /api/workforce-audit/evidence-preservation/status
POST /api/workforce-audit/evidence/{evidenceId}/preservations
GET  /api/workforce-audit/evidence/{evidenceId}/preservations
POST /api/workforce-audit/evidence-preservation/{archiveId}/verify
```

Preservation request:

```json
{
  "version": 1,
  "purpose": "Regulatory audit evidence preservation",
  "confirmation": "PRESERVE EVD-0123456789abcdef0123456789abcdef V1"
}
```

The confirmation must be exactly `PRESERVE EVD-... V<version>`. The service reopens and authenticates the encrypted live evidence object, verifies its identity, SHA-256 and size, then writes the preservation object and receipt.

## Archive identity and idempotency

The archive ID binds:

- tenant ID;
- evidence ID;
- evidence version;
- content SHA-256;
- retention date.

Repeating the same preservation request is idempotent and returns the original receipt. It cannot change the original actor, purpose, timestamp or cryptographic object.

A retention extension creates a different archive ID. This is deliberate: an existing write-once receipt is never edited or shortened. Before disposition, the policy accepts only a verified receipt whose retention date is at least the evidence item's current retention date.

## Legal holds

The receipt records whether a legal hold was active when the archive was created. It does not expose the legal matter identifier. The existing evidence lifecycle continues to block disposition while a legal hold is active.

Preservation does not release, shorten or replace a hold. If retention or hold requirements change, create another immutable preservation with the updated retention date after the live evidence record is updated through its governed workflow.

## Disposition gate

When `WORKFORCE_AUDIT_EVIDENCE_PRESERVATION_REQUIRED_FOR_DISPOSITION=true`, disposition fails with `409 EVIDENCE_PRESERVATION_REQUIRED` unless every immutable version has a verified receipt that:

- matches the evidence ID and version;
- matches the original content SHA-256 and size;
- authenticates successfully with the retained encryption key;
- has a valid receipt signature;
- points to the matching encrypted object envelope;
- covers the current retention date.

The gate runs inside the evidence registry, so it applies to every disposition caller and not only HTTP requests.

## Partial-write recovery

The object is committed first using exclusive create semantics. If the process stops before the receipt is committed, a repeated preservation request:

1. authenticates and decrypts the existing object;
2. verifies evidence identity, version, SHA-256, size and retention date;
3. recreates only the missing signed receipt;
4. preserves the original archive timestamp, actor and purpose.

A receipt without its object, conflicting create-only file, invalid signature, missing key or checksum mismatch fails closed.

## Key rotation

Archive encryption and receipt-signing keys rotate independently.

1. Add the new encryption and signing keys under new IDs.
2. Set both primary key IDs to the new IDs.
3. Preserve a test evidence version and verify that the result uses the new keys.
4. Retain old keys while any archived object or receipt references them.
5. Remove an old key only after retention, legal and audit requirements permit it and a full preservation verification succeeds without that key dependency.

## Operational checks

Monitor:

- preservation store health and backend confirmation;
- unpreserved versions when disposition gating is enabled;
- orphan objects or receipts;
- verification failures;
- archive key and signing-key age;
- immutable mount capacity and availability;
- retention-policy drift between BasitClaw and the backend;
- periodic restore-and-verify exercises using authorised offline procedures.

Do not mount the preservation directory on an eventually consistent object-store filesystem. The adapter requires reliable exclusive creation, durable writes, directory fsync and stable read-after-write behaviour.
