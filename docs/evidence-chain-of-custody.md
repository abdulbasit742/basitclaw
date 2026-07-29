# Evidence chain of custody

BasitClaw can replace uncontrolled finding references with tenant-isolated, encrypted evidence records. Every item receives an immutable `EVD-...` identifier, one or more immutable content versions, SHA-256 checksums, retention metadata, and a hash-linked custody history.

## Production configuration

```bash
WORKFORCE_AUDIT_EVIDENCE_MODE=shared-file
WORKFORCE_AUDIT_EVIDENCE_REQUIRED=true
WORKFORCE_AUDIT_EVIDENCE_DIR=/var/lib/basitclaw/workforce-audit-evidence
WORKFORCE_AUDIT_EVIDENCE_KEYS='{"2026-q3":"<base64-32-byte-key>","2026-q2":"<previous-base64-32-byte-key>"}'
WORKFORCE_AUDIT_EVIDENCE_PRIMARY_KEY_ID=2026-q3
WORKFORCE_AUDIT_EVIDENCE_MAX_BYTES=10000000
WORKFORCE_AUDIT_EVIDENCE_DEFAULT_RETENTION_DAYS=2555
WORKFORCE_AUDIT_EVIDENCE_EVENT_RETENTION=10000
WORKFORCE_AUDIT_EVIDENCE_REFERENCE_LEASE_MS=60000
WORKFORCE_AUDIT_EVIDENCE_REFERENCE_ACQUIRE_TIMEOUT_MS=2000
WORKFORCE_AUDIT_EVIDENCE_REFERENCE_RETRY_MS=10
```

The directory must be on a durable filesystem shared by every application process, with reliable atomic directory creation and rename semantics. Do not use an eventually consistent object-store mount. Keep historical encryption keys while any retained index or content envelope may reference them.

## Ingestion and immutable versions

`POST /api/workforce-audit/evidence` accepts JSON with:

- `filename`
- `mediaType`
- canonical `contentBase64`
- optional `description`, `sourceType`, `sourceSystem`, `collectedAt`, and `retentionUntil`

The configured maximum applies to decoded content. The JSON transport ceiling is derived from that maximum to accommodate base64 expansion plus bounded metadata; it does not increase the decoded evidence limit.

`POST /api/workforce-audit/evidence/{id}/versions` creates a new immutable version. Earlier content remains retrievable with `?version=N`. The service verifies AES-256-GCM authentication, tenant/item/version identity, content size, and SHA-256 before returning bytes.

Downloads include `x-evidence-id`, `x-evidence-version`, and `x-evidence-sha256` headers.

## Finding references

When evidence storage is enabled, `POST /api/workforce-audit/findings` accepts only:

- registered active `EVD-...` records belonging to the authenticated tenant; or
- valid `PLH-...` fieldwork placeholders already governed by the audit model.

Arbitrary drive links, local paths, and unregistered identifiers are rejected. Disposed, missing, cross-tenant, corrupted, or unauthenticated evidence cannot support a finding.

A short-lived shared reference guard is acquired while validated finding evidence is committed. Disposition uses the same tenant evidence mutex, so it cannot pass between reference validation and durable finding creation. A crashed process releases the guard through bounded stale-lease recovery; retryable contention returns `423 EVIDENCE_REFERENCE_BUSY`.

## Custody and integrity APIs

- `GET /api/workforce-audit/evidence/status`
- `GET /api/workforce-audit/evidence`
- `POST /api/workforce-audit/evidence`
- `GET /api/workforce-audit/evidence/{id}`
- `GET /api/workforce-audit/evidence/{id}/content?version=N`
- `POST /api/workforce-audit/evidence/{id}/versions`
- `GET /api/workforce-audit/evidence/{id}/events`
- `POST /api/workforce-audit/evidence/{id}/verify`

Custody events are hash-linked and retained behind an anchor when the configured event limit is exceeded. Event metadata records hashes, sizes and lifecycle actions, not evidence bytes.

Local inspection commands:

```bash
npm run evidence:check -- status tenant-acme
npm run evidence:check -- verify tenant-acme
npm run evidence:check -- verify tenant-acme EVD-0123456789abcdef0123456789abcdef
npm run evidence:check -- list tenant-acme 100
npm run evidence:check -- events tenant-acme EVD-0123456789abcdef0123456789abcdef 200
```

## Legal hold

Legal hold operations require `backup:restore`, which is a protected permission under the default just-in-time privileged-access policy.

Place a hold with `POST /{id}/legal-hold`, including a matter ID, a detailed reason, and optionally a future review date. Public responses expose hold state and dates, but omit the matter identifier, reason, approvers, filesystem paths and encryption key IDs.

Release a hold through `POST /{id}/release-hold` with a reason and exact confirmation:

```text
RELEASE HOLD EVD-...
```

An active hold prevents retention shortening and disposition.

## Retention and disposition

Disposition requires all of the following:

1. the retention date has elapsed;
2. no legal hold is active;
3. no audit finding references the evidence;
4. no finding-reference guard is active;
5. the caller has an active JIT grant for `backup:restore` when privileged enforcement is enabled;
6. exact confirmation `DISPOSE EVD-...` is supplied.

The service first commits an encrypted disposition tombstone and custody event, then purges content versions. If physical deletion fails, the item remains disposed with `purgePending=true`; operators must preserve the tombstone, repair storage and complete the controlled purge rather than restoring access to the content.

## Incident response

For `EVIDENCE_INTEGRITY_FAILED`, stop using the affected evidence, preserve the storage volume, verify the tenant chain and individual item, review security telemetry, and restore only through approved forensic and recovery procedures. Do not overwrite or re-upload an item to conceal a failed integrity check.

For `EVIDENCE_STORE_UNAVAILABLE`, drain evidence-dependent writes and finding creation when the store is required. Restore the shared filesystem and keys, run `evidence:check verify`, then resume service.

## Deployment boundary

This implementation provides encrypted shared-file custody and controlled retrieval. Malware scanning, document classification, optical character recognition, external WORM/object-lock replication, data-loss-prevention inspection, and court-certified timestamping remain separate enterprise integrations.
