import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { sha256 } from '../src/evidence/evidenceCrypto.js';
import { EvidenceValidationError } from '../src/evidence/evidenceRegistry.js';
import { createEvidenceAssuranceBundleStore } from '../src/evidence/evidenceAssuranceBundleStore.js';
import { createEvidenceAssuranceBundleRegistry } from '../src/evidence/evidenceAssuranceBundleRegistry.js';

const rsa = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});
const tenantId = 'tenant-registry';
const evidenceId = `EVD-${'e'.repeat(32)}`;
const content = Buffer.from('governed evidence export content');
const contentSha256 = sha256(content);

function fixture() {
  const store = createEvidenceAssuranceBundleStore({
    mode: 'pull', required: true,
    directory: mkdtempSync(join(tmpdir(), 'assurance-registry-')),
    encryptionKeys: { b1: Buffer.alloc(32, 31).toString('base64') },
    encryptionPrimaryKeyId: 'b1',
    recipients: {
      regulator: {
        keys: { h1: Buffer.alloc(48, 32).toString('base64') },
        primaryPublicKeyId: 'r1',
        publicKeys: { r1: rsa.publicKey }
      }
    },
    now: () => new Date('2026-07-30T02:00:00.000Z')
  });
  const item = {
    evidenceId, tenantId, filename: 'payroll.csv', mediaType: 'text/csv', status: 'active', currentVersion: 1,
    retentionUntil: '2033-01-01T00:00:00.000Z',
    legalHold: { active: true, matterId: 'secret-matter', reason: 'privileged legal instruction', reviewAt: '2027-01-01T00:00:00.000Z' },
    versions: [{ version: 1, filename: 'payroll.csv', mediaType: 'text/csv', sha256: contentSha256, sizeBytes: content.length, createdAt: '2026-07-30T01:00:00.000Z' }]
  };
  const base = {
    get(requestTenant, requestedId) { assert.equal(requestTenant, tenantId); assert.equal(requestedId, evidenceId); return structuredClone(item); },
    readContent() { return { evidenceId, version: 1, filename: 'payroll.csv', mediaType: 'text/csv', sha256: contentSha256, sizeBytes: content.length, content: Buffer.from(content) }; },
    verify() { return { valid: true, headSequence: 4, headHash: sha256('head') }; },
    events() { return [{ sequence: 1, action: 'evidence.ingested', hash: sha256('event') }]; },
    screeningReport() { return { version: 1, decision: 'allow', findings: [] }; },
    externalScanAttestations() { return [{ attestationId: 'ATT-1', verdict: 'clean', contentSha256 }]; },
    evidencePreservationReceipts() { return [{ receiptId: 'PRR-1', archiveId: `ARC-${'f'.repeat(32)}`, evidenceVersion: 1, contentSha256 }]; },
    evidenceTimeAttestations() { return [{ attestationId: 'TSA-1', providerId: 'notary-one' }]; },
    health() { return { status: 'ready', required: true }; },
    tenantStatus() { return { status: 'ready' }; }
  };
  return { registry: createEvidenceAssuranceBundleRegistry({ registry: base, bundles: store }), store };
}

test('governed export creates a recipient-bound bundle with all assurance sections', () => {
  const { registry } = fixture();
  const result = registry.createAssuranceBundle(tenantId, evidenceId, {
    version: 1,
    recipientId: 'regulator',
    purpose: 'Regulatory workforce audit evidence examination',
    confirmation: `EXPORT ${evidenceId} V1 TO regulator`
  }, { actor: 'manager.one' });
  assert.equal(result.duplicate, false);
  assert.equal(result.bundle.recipientId, 'regulator');
  assert.equal(result.bundle.contentSha256, contentSha256);
  assert.equal(registry.assuranceBundles(tenantId, evidenceId).length, 1);
  assert.equal(registry.assuranceBundleStatus(tenantId).pending, 1);
});

test('governed export requires exact recipient-bound confirmation', () => {
  const { registry } = fixture();
  assert.throws(() => registry.createAssuranceBundle(tenantId, evidenceId, {
    version: 1,
    recipientId: 'regulator',
    purpose: 'Regulatory workforce audit evidence examination',
    confirmation: `EXPORT ${evidenceId}`
  }, { actor: 'manager.one' }), EvidenceValidationError);
});

test('assurance bundle health fails closed only when required store is unavailable', () => {
  const base = {
    readContent() {}, events() {}, health() { return { status: 'ready', required: true }; }, tenantStatus() { return { status: 'ready' }; }
  };
  const bundles = {
    enabled: true, required: true, queue() {}, list() { return []; }, claimSigned() {}, acknowledgeSigned() {},
    health() { return { status: 'unavailable', enabled: true, required: true }; },
    tenantStatus() { return { status: 'unavailable', enabled: true, required: true }; }
  };
  const registry = createEvidenceAssuranceBundleRegistry({ registry: base, bundles });
  assert.equal(registry.health().status, 'unavailable');
  assert.equal(registry.tenantStatus(tenantId).status, 'unavailable');
});
