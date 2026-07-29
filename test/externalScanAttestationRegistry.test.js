import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createEvidenceRegistry } from '../src/evidence/evidenceRegistry.js';
import { createEvidenceScreeningEngine } from '../src/evidence/evidenceScreeningEngine.js';
import { createScreenedEvidenceRegistry } from '../src/evidence/evidenceScreeningRegistry.js';
import {
  ExternalScanAuthenticationError,
  ExternalScanRequiredError,
  createExternalScanAttestationRegistry
} from '../src/evidence/externalScanAttestationRegistry.js';
import { createExternalScanEvidenceRegistry } from '../src/evidence/externalScanEvidenceRegistry.js';
import { sha256 } from '../src/evidence/evidenceCrypto.js';

const evidenceKey = Buffer.alloc(32, 17).toString('base64');
const providerSecret = Buffer.alloc(48, 23);
const providerSecretBase64 = providerSecret.toString('base64');
const currentIso = '2026-07-30T00:00:00.000Z';

function createAttestations({ directory, mode = 'enforce', requiredForRelease = true, now = () => new Date(currentIso) } = {}) {
  return createExternalScanAttestationRegistry({
    directory,
    keys: { k1: evidenceKey },
    primaryKeyId: 'k1',
    providers: { 'managed-av': { keys: { '2026-q3': providerSecretBase64 } } },
    mode,
    requiredForRelease,
    maxAttestationAgeMinutes: 60,
    clockSkewSeconds: 300,
    eventRetention: 100,
    maxRecords: 1000,
    now
  });
}

function signedRequest(body, { timestamp = currentIso, nonce = 'nonce-0000000000000001', secret = providerSecret } = {}) {
  const bytes = Buffer.from(JSON.stringify(body));
  const canonical = `managed-av\n2026-q3\n${timestamp}\n${nonce}\n${sha256(bytes)}`;
  const signature = createHmac('sha256', secret).update(canonical).digest('hex');
  return {
    bytes,
    headers: {
      'x-basitclaw-scan-provider': 'managed-av',
      'x-basitclaw-scan-key-id': '2026-q3',
      'x-basitclaw-scan-timestamp': timestamp,
      'x-basitclaw-scan-nonce': nonce,
      'x-basitclaw-scan-signature': signature
    }
  };
}

function attestation(overrides = {}) {
  return {
    attestationId: 'managed-av:scan:0000000000000001',
    tenantId: 'tenant-a',
    evidenceId: 'EVD-0123456789abcdef0123456789abcdef',
    version: 1,
    contentSha256: 'a'.repeat(64),
    verdict: 'clean',
    scannedAt: currentIso,
    engine: 'Managed AV Gateway',
    engineVersion: '8.4.2',
    definitionsVersion: '2026.07.30.1',
    findings: [],
    ...overrides
  };
}

function filesUnder(directory) {
  const files = [];
  const walk = (path) => {
    for (const entry of readdirSync(path, { withFileTypes: true })) {
      const child = join(path, entry.name);
      entry.isDirectory() ? walk(child) : files.push(child);
    }
  };
  walk(directory);
  return files;
}

test('accepts signed hash-bound attestations, handles exact duplicates, and encrypts records', () => {
  const directory = mkdtempSync(join(tmpdir(), 'external-scan-'));
  const registry = createAttestations({ directory });
  const body = attestation();
  const request = signedRequest(body);
  const validateTarget = (input) => ({ version: input.version, contentSha256: input.contentSha256 });

  const accepted = registry.acceptSigned(request.bytes, request.headers, validateTarget);
  assert.equal(accepted.accepted, true);
  assert.equal(accepted.attestation.verdict, 'clean');
  assert.equal(registry.verify('tenant-a').valid, true);

  const duplicate = registry.acceptSigned(request.bytes, request.headers, validateTarget);
  assert.equal(duplicate.accepted, false);
  assert.equal(duplicate.duplicate, true);
  assert.equal(duplicate.attestation.hash, accepted.attestation.hash);

  const plaintext = filesUnder(directory).map((path) => readFileSync(path, 'utf8')).join('\n');
  assert.equal(plaintext.includes(body.attestationId), false);
  assert.equal(plaintext.includes('managed-av'), false);
  assert.equal(plaintext.includes('clean'), false);
});

test('rejects invalid signatures and target hash mismatches', () => {
  const directory = mkdtempSync(join(tmpdir(), 'external-scan-auth-'));
  const registry = createAttestations({ directory });
  const body = attestation();
  const invalid = signedRequest(body, { secret: Buffer.alloc(48, 99) });
  assert.throws(
    () => registry.acceptSigned(invalid.bytes, invalid.headers, () => ({ version: 1, contentSha256: body.contentSha256 })),
    ExternalScanAuthenticationError
  );

  const valid = signedRequest(body, { nonce: 'nonce-0000000000000002' });
  assert.throws(
    () => registry.acceptSigned(valid.bytes, valid.headers, () => ({ version: 1, contentSha256: 'b'.repeat(64) })),
    /does not match the immutable evidence version/
  );
});

test('requires a recent clean attestation before governed release', () => {
  const directory = mkdtempSync(join(tmpdir(), 'external-scan-release-'));
  const base = createEvidenceRegistry({ directory, keys: { k1: evidenceKey }, primaryKeyId: 'k1' });
  const screened = createScreenedEvidenceRegistry({
    registry: base,
    engine: createEvidenceScreeningEngine({ mode: 'enforce', now: () => new Date(currentIso) }),
    keys: { k1: evidenceKey },
    primaryKeyId: 'k1',
    eventRetention: 100,
    now: () => new Date(currentIso)
  });
  const attestations = createAttestations({ directory });
  const registry = createExternalScanEvidenceRegistry({ registry: screened, attestations });
  const item = registry.ingest('tenant-a', {
    filename: 'private-key.txt',
    mediaType: 'text/plain',
    contentBase64: Buffer.from('-----BEGIN PRIVATE KEY-----\nsynthetic\n-----END PRIVATE KEY-----').toString('base64')
  }, { actor: 'auditor.one' });
  assert.equal(item.status, 'quarantine');
  assert.throws(() => registry.releaseQuarantine('tenant-a', item.evidenceId, {
    confirmation: `RELEASE QUARANTINE ${item.evidenceId}`,
    reason: 'Independent review confirms synthetic test evidence'
  }, { actor: 'admin.one' }), ExternalScanRequiredError);

  const report = registry.screeningReport('tenant-a', item.evidenceId);
  const body = attestation({
    evidenceId: item.evidenceId,
    contentSha256: report.contentSha256,
    attestationId: 'managed-av:scan:0000000000000003'
  });
  const request = signedRequest(body, { nonce: 'nonce-0000000000000003' });
  registry.recordExternalScanAttestation(request.bytes, request.headers);

  const released = registry.releaseQuarantine('tenant-a', item.evidenceId, {
    confirmation: `RELEASE QUARANTINE ${item.evidenceId}`,
    reason: 'Independent review confirms synthetic test evidence'
  }, { actor: 'admin.one' });
  assert.equal(released.status, 'active');
  assert.equal(released.externalScan.verdict, 'clean');
  assert.equal(registry.screeningReport('tenant-a', item.evidenceId).decision, 'quarantine');
});

test('enforce mode blocks a latest malicious verdict even when clean attestation is optional', () => {
  const directory = mkdtempSync(join(tmpdir(), 'external-scan-malicious-'));
  const base = createEvidenceRegistry({ directory, keys: { k1: evidenceKey }, primaryKeyId: 'k1' });
  const screened = createScreenedEvidenceRegistry({
    registry: base,
    engine: createEvidenceScreeningEngine({ mode: 'enforce', now: () => new Date(currentIso) }),
    keys: { k1: evidenceKey }, primaryKeyId: 'k1', eventRetention: 100, now: () => new Date(currentIso)
  });
  const attestations = createAttestations({ directory, requiredForRelease: false });
  const registry = createExternalScanEvidenceRegistry({ registry: screened, attestations });
  const item = registry.ingest('tenant-a', {
    filename: 'script.js', mediaType: 'application/javascript', contentBase64: Buffer.from('alert(1)').toString('base64')
  }, { actor: 'auditor.one' });
  const report = registry.screeningReport('tenant-a', item.evidenceId);
  const body = attestation({
    evidenceId: item.evidenceId,
    contentSha256: report.contentSha256,
    verdict: 'malicious',
    attestationId: 'managed-av:scan:0000000000000004',
    findings: [{ ruleId: 'MALWARE.TEST', severity: 'critical', category: 'malware' }]
  });
  const request = signedRequest(body, { nonce: 'nonce-0000000000000004' });
  registry.recordExternalScanAttestation(request.bytes, request.headers);
  assert.throws(() => registry.releaseQuarantine('tenant-a', item.evidenceId, {
    confirmation: `RELEASE QUARANTINE ${item.evidenceId}`,
    reason: 'Attempted release must remain blocked by malicious verdict'
  }, { actor: 'admin.one' }), ExternalScanRequiredError);
});
