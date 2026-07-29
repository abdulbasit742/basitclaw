# Evidence screening and quarantine

BasitClaw screens every new evidence item and immutable evidence version before it can support an audit finding. Screening is deterministic and dependency-light: it detects executable signatures, the EICAR test signature, active scripts, MIME/extension mismatches, uninspected archive containers, private-key material, cloud/source-control credentials, and valid payment-card-number patterns.

The built-in engine is an admission-control baseline, not a replacement for a managed external antivirus, sandbox, or enterprise DLP platform. Production deployments should route released files through approved external scanning where regulation or risk requires deeper inspection.

## Configuration

```bash
WORKFORCE_AUDIT_EVIDENCE_SCREENING_MODE=enforce
WORKFORCE_AUDIT_EVIDENCE_SCREENING_REQUIRED=true
WORKFORCE_AUDIT_EVIDENCE_SCREENING_MAX_BYTES=10000000
WORKFORCE_AUDIT_EVIDENCE_SCREENING_EVENT_RETENTION=10000
WORKFORCE_AUDIT_EVIDENCE_ARCHIVE_POLICY=review
```

Modes:

- `disabled`: no screening metadata is created. This mode cannot be used when screening is required.
- `observe`: findings are recorded as `wouldQuarantine=true`, but the version remains usable. Use only for controlled rollout.
- `enforce`: suspicious versions are encrypted and quarantined immediately.

`WORKFORCE_AUDIT_EVIDENCE_ARCHIVE_POLICY=review` quarantines ZIP and other archive containers because the built-in engine does not recursively unpack them. `allow` permits them to pass the container rule, but external deep scanning is still recommended.

Screening uses the evidence encryption keyring and stores its own authenticated encrypted index and hash-linked event chain under the evidence directory. Keep historical evidence keys until all retained evidence and screening envelopes have been rotated or disposed through approved procedures.

## Quarantine behaviour

A quarantined or rejected version:

- remains encrypted in evidence custody;
- cannot be downloaded;
- cannot support a finding;
- appears in evidence status and screening reports;
- can still be retained under legal hold;
- can be disposed only through the normal retention, reference, hold, and JIT controls.

The screening report contains rule IDs, category, severity, hashes, size, engine version, and timestamps. It never contains matched secret values or content excerpts.

A clean later version may restore an item whose earlier version was rejected. Earlier rejected or quarantined versions remain inaccessible.

## APIs

Existing evidence ingestion and version APIs return a `screening` summary and may return public status `quarantine` or `rejected`.

- `GET /api/workforce-audit/evidence/{id}/screening`
- `GET /api/workforce-audit/evidence/{id}/screening?version=N`
- `GET /api/workforce-audit/evidence/{id}/screening/events`
- `POST /api/workforce-audit/evidence/{id}/screening/release`
- `POST /api/workforce-audit/evidence/{id}/screening/reject`

Reading reports and events requires governance access. Release and rejection require the protected `backup:restore` permission, which is governed by the just-in-time privileged-access policy.

## False-positive release

A reviewer must independently inspect the alert, source, provenance, and business need. Release requires a detailed reason and exact confirmation:

```text
RELEASE QUARANTINE EVD-...
```

The decision changes only the selected immutable version's access state. It does not remove the original findings from the screening report. The release actor and reason remain encrypted in the screening registry; public metadata exposes only the action and review time.

## Rejection

Use rejection when suspicious content must remain preserved for custody but must never be used as audit evidence. Rejection requires:

```text
REJECT EVIDENCE EVD-...
```

A rejected current version is inaccessible and cannot support findings. Uploading a later clean immutable version can make the item usable again without rewriting or deleting the rejected version.

## Incident response

For malware or credential findings:

1. Do not release or download the quarantined version.
2. Preserve the evidence and screening directories and their keyrings.
3. Review custody and screening event chains.
4. Correlate the upload with security telemetry and the source system.
5. Submit the encrypted evidence through an approved isolated malware-analysis or DLP workflow.
6. Rotate any exposed credentials through their authoritative systems.
7. Release only after an independent false-positive decision; otherwise reject and retain or dispose according to policy.

For `EVIDENCE_SCREENING_STORE_UNAVAILABLE`, stop evidence-dependent writes when screening is required. Restore the shared filesystem and encryption keys, verify evidence and screening integrity, then resume service.

## Privacy and limitations

The built-in engine scans a bounded amount of decoded content in memory. It does not execute files, expand archives, run macros, call external reputation services, perform OCR, or retain matched values. External antivirus, sandboxing, OCR-aware DLP, document-classification models, and WORM/object-lock replication remain enterprise integrations.
