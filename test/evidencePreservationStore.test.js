import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createEvidenceRegistry } from '../src/evidence/evidenceRegistry.js';
import {
  EvidencePreservationIntegrityError,
  EvidencePreservationRequiredError,
  createEvidencePreservationStore
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

test('creates encrypted write-once preservation objects and signed receipts', () => {
  const { store, directory } = storeFixture();
  const result = store.preserve(preservationInput(), {
    actor: 'manager.one',
    purpose: 'Regulatory audit evidence preservation'
  });
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
});

test('duplicate preservation is idempotent and cannot overwrite history', () => {
  const { store } = storeFixture();
  const first = store.preserve(preservationInput(), {
    actor: 'manager.one',
    purpose: 'Regulatory audit evidence preservation'
  });
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
  const first = store.preserve(preservationInput(), {
    actor: 'manager.one',
    purpose: 'Regulatory audit evidence preservation'
  });
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
  const result = store.preserve(preservationInput(), {
    actor: 'manager.one',
    purpose: 'Regulatory audit evidence preservation'
  });
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
  const result = store.preserve(preservationInput(), {
    actor: 'manager.one',
    purpose: 'Regulatory audit evidence preservation'
  });
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
