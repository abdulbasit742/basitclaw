import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createEvidenceRegistry } from '../src/evidence/evidenceRegistry.js';
import {
  EvidencePreservationIntegrityError,
  EvidencePreservationRequiredError,
  EvidencePreservationStoreError,
  createEvidencePreservationStore,
  createEvidencePreservationStoreFromEnvironment
} from '../src/evidence/evidencePreservationStore.js';
import { createEvidencePreservationRegistry } from '../src/evidence/evidencePreservationRegistry.js';

const encryptionKey = Buffer.alloc(32, 17).toString('base64');
const signingKey = Buffer.alloc(48, 29).toString('base64');
const tenantId = 'tenant-preservation';
const evidenceId = `EVD-${'a'.repeat(32)}`;

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

function storeFixture(options = {}) {
  const directory = mkdtempSync(join(tmpdir(), 'preservation-'));
  const store = createEvidencePreservationStore({
    mode: 'shared-file',
    requiredForDisposition: options.requiredForDisposition ?? false,
    directory,
    encryptionKeys: { archive: encryptionKey },
    encryptionPrimaryKeyId: 'archive',
    signingSecrets: { receipt: signingKey },
    signingPrimaryKeyId: 'receipt',
    immutableBackendConfirmed: options.immutableBackendConfirmed ?? true,
    now: options.now
  });
  return { store, directory };
}

function preservationInput(overrides = {}) {
  const content = Buffer.from(overrides.text ?? 'immutable payroll evidence');
  return {
    tenantId,
    evidenceId,
    version: 1,
    filename: 'payroll.csv',
    mediaType: 'text/csv',
    contentSha256: createHash('sha256').update(content).digest('hex'),
    sizeBytes: content.length,
    retentionUntil: '2033-07-30T00:00:00.000Z',
    legalHold: { active: false },
    content,
    ...overrides
  };
}

function preserve(store, input = preservationInput(), actor = 'manager.one') {
  return store.preserve(input, {
    actor,
    purpose: 'Regulatory audit evidence preservation'
  });
}

test('creates encrypted write-once preservation objects and signed receipts', () => {
  const { store, directory } = storeFixture();
  const result = preserve(store);
  assert.equal(result.archived, true);
  assert.match(result.receipt.archiveId, /^ARC-/);
  assert.equal(store.verify(tenantId, result.receipt.archiveId).valid, true);
  assert.equal(store.list(tenantId, { evidenceId }).length, 1);
  const raw = filesUnder(directory)
    .filter((path) => path.endsWith('.object') || path.endsWith('.receipt'))
    .map((path) => readFileSync(path, 'utf8'))
    .join('\n');
  assert.equal(raw.includes('immutable payroll evidence'), false);
  assert.equal(raw.includes(tenantId), false);
  assert.equal(raw.includes(evidenceId), false);
  assert.equal(store.health().deletionApi, false);
  assert.equal(store.health().independentEncryptionKeys, true);
});

test('duplicate preservation is idempotent and cannot overwrite history', () => {
  const { store } = storeFixture();
  const first = preserve(store);
  const second = store.preserve(preservationInput(), {
    actor: 'manager.two',
    purpose: 'A different request that must not rewrite history'
  });
  assert.equal(second.duplicate, true);
  assert.equal(second.receipt.archiveId, first.receipt.archiveId);
  assert.equal(second.receipt.archivedBy, 'manager.one');
  assert.equal(second.receipt.purpose, 'Regulatory audit evidence preservation');
});

test('recovers a missing receipt without rewriting the immutable object', () => {
  const { store, directory } = storeFixture();
  const first = preserve(store);
  const receiptPath = filesUnder(directory).find((path) => path.endsWith('.receipt'));
  const objectPath = filesUnder(directory).find((path) => path.endsWith('.object'));
  const originalObject = readFileSync(objectPath, 'utf8');
  rmSync(receiptPath);
  const recovered = store.preserve(preservationInput(), {
    actor: 'manager.two',
    purpose: 'Recovery request must retain original metadata'
  });
  assert.equal(recovered.recoveredReceipt, true);
  assert.equal(readFileSync(objectPath, 'utf8'), originalObject);
  assert.equal(recovered.receipt.archiveId, first.receipt.archiveId);
  assert.equal(recovered.receipt.archivedBy, 'manager.one');
});

test('tampered archive ciphertext fails closed', () => {
  const { store, directory } = storeFixture();
  const result = preserve(store);
  const objectPath = filesUnder(directory).find((path) => path.endsWith('.object'));
  const envelope = JSON.parse(readFileSync(objectPath, 'utf8'));
  envelope.ciphertext = envelope.ciphertext.replace(/^./, envelope.ciphertext[0] === 'A' ? 'B' : 'A');
  writeFileSync(objectPath, JSON.stringify(envelope));
  assert.throws(
    () => store.verify(tenantId, result.receipt.archiveId),
    EvidencePreservationIntegrityError
  );
});

test('tenant hashes and authenticated receipts prevent cross-tenant reads', () => {
  const { store } = storeFixture();
  const result = preserve(store);
  assert.equal(store.list('tenant-other', { evidenceId }).length, 0);
  assert.throws(
    () => store.verify('tenant-other', result.receipt.archiveId),
    EvidencePreservationIntegrityError
  );
});

test('required preservation fails closed without a confirmed immutable backend', () => {
  assert.throws(() => createEvidencePreservationStore({
    mode: 'shared-file',
    requiredForDisposition: true,
    directory: mkdtempSync(join(tmpdir(), 'preservation-required-')),
    encryptionKeys: { archive: encryptionKey },
    encryptionPrimaryKeyId: 'archive',
    signingSecrets: { receipt: signingKey },
    signingPrimaryKeyId: 'receipt',
    immutableBackendConfirmed: false
  }), /confirmed immutable backend/);
});

test('enabled environment mode requires dedicated preservation keys and signing secrets', () => {
  const directory = mkdtempSync(join(tmpdir(), 'preservation-env-'));
  const evidenceRegistry = { enabled: true, directory };
  const base = {
    WORKFORCE_AUDIT_EVIDENCE_PRESERVATION_MODE: 'shared-file',
    WORKFORCE_AUDIT_EVIDENCE_KEYS: JSON.stringify({ live: encryptionKey }),
    WORKFORCE_AUDIT_EVIDENCE_PRIMARY_KEY_ID: 'live'
  };
  assert.throws(
    () => createEvidencePreservationStoreFromEnvironment({ env: base, evidenceRegistry }),
    (error) => error instanceof EvidencePreservationStoreError
      && error.details.reason === 'missing_preservation_encryption_keys'
  );
  assert.throws(
    () => createEvidencePreservationStoreFromEnvironment({
      env: {
        ...base,
        WORKFORCE_AUDIT_EVIDENCE_PRESERVATION_KEYS: JSON.stringify({ archive: encryptionKey }),
        WORKFORCE_AUDIT_EVIDENCE_PRESERVATION_PRIMARY_KEY_ID: 'archive'
      },
      evidenceRegistry
    }),
    (error) => error instanceof EvidencePreservationStoreError
      && error.details.reason === 'missing_preservation_signing_secrets'
  );
});

test('tenant status compares archive ID sets instead of trusting equal counts', () => {
  const { store, directory } = storeFixture();
  preserve(store);
  const receiptPath = filesUnder(directory).find((path) => path.endsWith('.receipt'));
  const fakeArchiveId = `ARC-${'f'.repeat(32)}`;
  const replacement = receiptPath.replace(/ARC-[a-f0-9]{32}\.receipt$/, `${fakeArchiveId}.receipt`);
  renameSync(receiptPath, replacement);
  const status = store.tenantStatus(tenantId);
  assert.equal(status.status, 'unavailable');
  assert.equal(status.orphanObjects, 1);
  assert.equal(status.orphanReceipts, 1);
  assert.throws(() => store.verifyTenant(tenantId), EvidencePreservationIntegrityError);
});

test('evidence-scoped limits are applied before decrypting unrelated receipts', () => {
  let clock = new Date('2026-07-30T00:00:00.000Z');
  const { store } = storeFixture({ now: () => new Date(clock) });
  const otherEvidenceId = `EVD-${'b'.repeat(32)}`;
  preserve(store, preservationInput({ evidenceId, text: 'first evidence' }));
  clock = new Date(clock.getTime() + 1000);
  preserve(store, preservationInput({ evidenceId: otherEvidenceId, text: 'other evidence' }), 'manager.two');
  clock = new Date(clock.getTime() + 1000);
  preserve(store, preservationInput({ evidenceId, version: 2, text: 'second evidence version' }), 'manager.three');
  const rows = store.list(tenantId, { evidenceId, limit: 1 });
  assert.equal(rows.length, 1);
  assert.equal(rows[0].evidenceId, evidenceId);
  assert.equal(rows[0].evidenceVersion, 2);
});

test('disposition requires a verified preservation for every immutable version', () => {
  let current = new Date('2026-07-30T00:00:00.000Z');
  const evidenceDirectory = mkdtempSync(join(tmpdir(), 'evidence-preservation-registry-'));
  const base = createEvidenceRegistry({
    directory: evidenceDirectory,
    keys: { evidence: encryptionKey },
    primaryKeyId: 'evidence',
    now: () => new Date(current),
    defaultRetentionDays: 1,
    eventRetention: 100
  });
  const { store } = storeFixture({ requiredForDisposition: true });
  const registry = createEvidencePreservationRegistry({ registry: base, preservation: store });
  const item = registry.ingest(tenantId, {
    filename: 'a.txt',
    mediaType: 'text/plain',
    contentBase64: Buffer.from('version one').toString('base64'),
    retentionUntil: '2026-07-31T00:00:00.000Z'
  }, { actor: 'auditor.one' });
  current = new Date('2026-08-02T00:00:00.000Z');
  assert.throws(() => registry.dispose(tenantId, item.evidenceId, {
    confirmation: `DISPOSE ${item.evidenceId}`,
    reason: 'Retention completed after approved review'
  }, { actor: 'admin.one' }), EvidencePreservationRequiredError);
  registry.preserveEvidence(tenantId, item.evidenceId, {
    version: 1,
    purpose: 'Required preservation before approved disposition',
    confirmation: `PRESERVE ${item.evidenceId} V1`
  }, { actor: 'manager.one' });
  assert.equal(registry.dispose(tenantId, item.evidenceId, {
    confirmation: `DISPOSE ${item.evidenceId}`,
    reason: 'Retention completed after approved review'
  }, { actor: 'admin.one' }).status, 'disposed');
});

test('retention extensions require a new immutable preservation receipt', () => {
  const evidenceDirectory = mkdtempSync(join(tmpdir(), 'evidence-preservation-extension-'));
  const base = createEvidenceRegistry({
    directory: evidenceDirectory,
    keys: { evidence: encryptionKey },
    primaryKeyId: 'evidence',
    defaultRetentionDays: 1,
    eventRetention: 100
  });
  const { store } = storeFixture({ requiredForDisposition: true });
  const registry = createEvidencePreservationRegistry({ registry: base, preservation: store });
  const item = registry.ingest(tenantId, {
    filename: 'a.txt',
    mediaType: 'text/plain',
    contentBase64: Buffer.from('version one').toString('base64'),
    retentionUntil: '2030-07-31T00:00:00.000Z'
  }, { actor: 'auditor.one' });
  const first = registry.preserveEvidence(tenantId, item.evidenceId, {
    version: 1,
    purpose: 'Initial regulatory preservation receipt',
    confirmation: `PRESERVE ${item.evidenceId} V1`
  }, { actor: 'manager.one' });
  registry.addVersion(tenantId, item.evidenceId, {
    filename: 'a.txt',
    mediaType: 'text/plain',
    contentBase64: Buffer.from('version two').toString('base64'),
    retentionUntil: '2035-07-31T00:00:00.000Z'
  }, { actor: 'auditor.two' });
  const replacement = registry.preserveEvidence(tenantId, item.evidenceId, {
    version: 1,
    purpose: 'Extended regulatory retention preservation',
    confirmation: `PRESERVE ${item.evidenceId} V1`
  }, { actor: 'manager.one' });
  assert.notEqual(replacement.receipt.archiveId, first.receipt.archiveId);
  assert.equal(registry.get(tenantId, item.evidenceId).preservation.preservedVersions, 1);
});
