import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { publicEvidenceHealth } from '../src/evidence/evidenceHealthView.js';
import {
  EvidenceConflictError,
  EvidenceIntegrityError,
  EvidenceValidationError,
  createEvidenceRegistry,
  createEvidenceRegistryFromEnvironment
} from '../src/evidence/evidenceRegistry.js';

const key = Buffer.alloc(32, 7).toString('base64');
const content = Buffer.from('payroll evidence row 1').toString('base64');

function fixture(nowValue = '2026-07-30T00:00:00.000Z') {
  let current = new Date(nowValue);
  const directory = mkdtempSync(join(tmpdir(), 'evidence-'));
  const registry = createEvidenceRegistry({
    directory,
    keys: { k1: key },
    primaryKeyId: 'k1',
    now: () => new Date(current),
    defaultRetentionDays: 1,
    eventRetention: 100
  });
  return { registry, directory, setNow: (value) => { current = new Date(value); } };
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

test('ingests encrypted evidence and verifies checksum and chain', () => {
  const { registry, directory } = fixture();
  const item = registry.ingest('tenant-a', {
    filename: 'payroll.csv',
    mediaType: 'text/csv',
    contentBase64: content,
    sourceType: 'system_export'
  }, { actor: 'auditor.one' });
  assert.match(item.evidenceId, /^EVD-/);
  assert.equal(registry.readContent('tenant-a', item.evidenceId).content.toString(), 'payroll evidence row 1');
  assert.equal(registry.verify('tenant-a', item.evidenceId).valid, true);
  assert.equal(filesUnder(directory).some((path) => readFileSync(path).includes('payroll evidence row 1')), false);
});

test('adds immutable versions, preserves omitted provenance, and validates registered references', () => {
  const { registry } = fixture();
  const item = registry.ingest('tenant-a', {
    filename: 'a.txt',
    mediaType: 'text/plain',
    contentBase64: Buffer.from('a').toString('base64'),
    sourceType: 'system_export',
    sourceSystem: 'payroll-core'
  }, { actor: 'auditor.one' });
  const updated = registry.addVersion('tenant-a', item.evidenceId, {
    filename: 'a.txt',
    mediaType: 'text/plain',
    contentBase64: Buffer.from('b').toString('base64')
  }, { actor: 'auditor.two' });
  assert.equal(updated.currentVersion, 2);
  assert.equal(updated.sourceType, 'system_export');
  assert.equal(updated.sourceSystem, 'payroll-core');
  assert.equal(registry.readContent('tenant-a', item.evidenceId, { version: 1 }).content.toString(), 'a');
  assert.equal(registry.readContent('tenant-a', item.evidenceId).content.toString(), 'b');
  assert.equal(registry.assertUsableReferences('tenant-a', [item.evidenceId]).length, 1);
});

test('accepts generated placeholder IDs and rejects malformed PLH input', () => {
  const { registry } = fixture();
  assert.deepEqual(registry.assertUsableReferences('tenant-a', ['PLH-ENG-2026-005-01']), []);
  for (const reference of ['PLH-', 'PLH-../../x', 'PLH-<img>', 'PLH-ENG-26-5-1']) {
    assert.throws(
      () => registry.assertUsableReferences('tenant-a', [reference]),
      EvidenceValidationError
    );
  }
});

test('legal hold blocks disposal and release requires exact confirmation', () => {
  const { registry, setNow } = fixture();
  const item = registry.ingest('tenant-a', {
    filename: 'a.txt',
    mediaType: 'text/plain',
    contentBase64: Buffer.from('a').toString('base64'),
    retentionUntil: '2026-07-31T00:00:00.000Z'
  }, { actor: 'auditor.one' });
  registry.placeLegalHold('tenant-a', item.evidenceId, {
    matterId: 'MAT-1',
    reason: 'Regulatory investigation hold'
  }, { actor: 'admin.one' });
  setNow('2026-08-02T00:00:00.000Z');
  assert.throws(() => registry.dispose('tenant-a', item.evidenceId, {
    confirmation: `DISPOSE ${item.evidenceId}`,
    reason: 'Retention completed after approved review'
  }, { actor: 'admin.one' }), EvidenceConflictError);
  assert.throws(() => registry.releaseLegalHold('tenant-a', item.evidenceId, {
    confirmation: 'wrong',
    reason: 'Matter formally closed'
  }, { actor: 'admin.two' }));
  registry.releaseLegalHold('tenant-a', item.evidenceId, {
    confirmation: `RELEASE HOLD ${item.evidenceId}`,
    reason: 'Matter formally closed'
  }, { actor: 'admin.two' });
  assert.equal(registry.dispose('tenant-a', item.evidenceId, {
    confirmation: `DISPOSE ${item.evidenceId}`,
    reason: 'Retention completed after approved review'
  }, { actor: 'admin.one' }).status, 'disposed');
});

test('referenced evidence cannot be disposed', () => {
  const { registry, setNow } = fixture();
  const item = registry.ingest('tenant-a', {
    filename: 'a.txt',
    mediaType: 'text/plain',
    contentBase64: Buffer.from('a').toString('base64'),
    retentionUntil: '2026-07-31T00:00:00.000Z'
  }, { actor: 'auditor.one' });
  setNow('2026-08-02T00:00:00.000Z');
  assert.throws(() => registry.dispose('tenant-a', item.evidenceId, {
    confirmation: `DISPOSE ${item.evidenceId}`,
    reason: 'Retention completed after approved review'
  }, { actor: 'admin.one', referencedBy: ['FND-1'] }), EvidenceConflictError);
});

test('tampered content fails closed', () => {
  const { registry, directory } = fixture();
  const item = registry.ingest('tenant-a', {
    filename: 'a.txt',
    mediaType: 'text/plain',
    contentBase64: Buffer.from('a').toString('base64')
  }, { actor: 'auditor.one' });
  const contentFile = filesUnder(directory)
    .find((path) => path.endsWith('.evidence') && !path.endsWith('index.evidence'));
  const envelope = JSON.parse(readFileSync(contentFile, 'utf8'));
  envelope.ciphertext = envelope.ciphertext.replace(/^./, envelope.ciphertext[0] === 'A' ? 'B' : 'A');
  writeFileSync(contentFile, JSON.stringify(envelope));
  assert.throws(() => registry.readContent('tenant-a', item.evidenceId), EvidenceIntegrityError);
});

test('blank optional environment values receive safe defaults', () => {
  const directory = mkdtempSync(join(tmpdir(), 'evidence-env-'));
  const registry = createEvidenceRegistryFromEnvironment({
    WORKFORCE_AUDIT_EVIDENCE_MODE: 'shared-file',
    WORKFORCE_AUDIT_EVIDENCE_REQUIRED: '',
    WORKFORCE_AUDIT_EVIDENCE_DIR: directory,
    WORKFORCE_AUDIT_EVIDENCE_KEYS: JSON.stringify({ k1: key }),
    WORKFORCE_AUDIT_EVIDENCE_PRIMARY_KEY_ID: 'k1',
    WORKFORCE_AUDIT_EVIDENCE_MAX_BYTES: ' ',
    WORKFORCE_AUDIT_EVIDENCE_DEFAULT_RETENTION_DAYS: '',
    WORKFORCE_AUDIT_EVIDENCE_EVENT_RETENTION: ''
  });
  const health = registry.health();
  assert.equal(health.status, 'ready');
  assert.equal(health.maxBytes, 10_000_000);
  assert.equal(health.defaultRetentionDays, 2555);
  assert.equal(health.eventRetention, 10_000);
});

test('public evidence health recursively removes operational secrets', () => {
  const source = {
    status: 'ready',
    directory: '/secret/evidence',
    primaryKeyId: 'key-current',
    configuredKeyIds: ['key-current', 'key-old'],
    nested: { keyId: 'key-old', directory: '/nested/path' },
    mutex: { status: 'ready', directory: '/secret/locks' }
  };
  const view = publicEvidenceHealth(source);
  assert.equal(view.directory, undefined);
  assert.equal(view.primaryKeyId, undefined);
  assert.equal(view.configuredKeyIds, undefined);
  assert.equal(view.nested.keyId, undefined);
  assert.equal(view.nested.directory, undefined);
  assert.equal(view.mutex.directory, undefined);
  assert.equal(source.directory, '/secret/evidence');
});
