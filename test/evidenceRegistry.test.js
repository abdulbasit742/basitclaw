import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createEvidenceRegistry, EvidenceConflictError, EvidenceIntegrityError } from '../src/evidence/evidenceRegistry.js';

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

test('ingests encrypted evidence and verifies checksum and chain', () => {
  const { registry, directory } = fixture();
  const item = registry.ingest('tenant-a', {
    filename: 'payroll.csv', mediaType: 'text/csv', contentBase64: content, sourceType: 'system_export'
  }, { actor: 'auditor.one' });
  assert.match(item.evidenceId, /^EVD-/);
  assert.equal(registry.readContent('tenant-a', item.evidenceId).content.toString(), 'payroll evidence row 1');
  assert.equal(registry.verify('tenant-a', item.evidenceId).valid, true);
  const files = [];
  const walk = (path) => {
    for (const entry of readdirSync(path, { withFileTypes: true })) {
      const child = join(path, entry.name);
      entry.isDirectory() ? walk(child) : files.push(child);
    }
  };
  walk(directory);
  assert.equal(files.some((path) => readFileSync(path).includes('payroll evidence row 1')), false);
});

test('adds immutable versions and validates registered references', () => {
  const { registry } = fixture();
  const item = registry.ingest('tenant-a', {
    filename: 'a.txt', mediaType: 'text/plain', contentBase64: Buffer.from('a').toString('base64')
  }, { actor: 'auditor.one' });
  const updated = registry.addVersion('tenant-a', item.evidenceId, {
    filename: 'a.txt', mediaType: 'text/plain', contentBase64: Buffer.from('b').toString('base64')
  }, { actor: 'auditor.two' });
  assert.equal(updated.currentVersion, 2);
  assert.equal(registry.readContent('tenant-a', item.evidenceId, { version: 1 }).content.toString(), 'a');
  assert.equal(registry.readContent('tenant-a', item.evidenceId).content.toString(), 'b');
  assert.equal(registry.assertUsableReferences('tenant-a', [item.evidenceId]).length, 1);
});

test('legal hold blocks disposal and release requires exact confirmation', () => {
  const { registry, setNow } = fixture();
  const item = registry.ingest('tenant-a', {
    filename: 'a.txt', mediaType: 'text/plain', contentBase64: Buffer.from('a').toString('base64'),
    retentionUntil: '2026-07-31T00:00:00.000Z'
  }, { actor: 'auditor.one' });
  registry.placeLegalHold('tenant-a', item.evidenceId, {
    matterId: 'MAT-1', reason: 'Regulatory investigation hold'
  }, { actor: 'admin.one' });
  setNow('2026-08-02T00:00:00.000Z');
  assert.throws(() => registry.dispose('tenant-a', item.evidenceId, {
    confirmation: `DISPOSE ${item.evidenceId}`, reason: 'Retention completed after approved review'
  }, { actor: 'admin.one' }), EvidenceConflictError);
  assert.throws(() => registry.releaseLegalHold('tenant-a', item.evidenceId, {
    confirmation: 'wrong', reason: 'Matter formally closed'
  }, { actor: 'admin.two' }));
  registry.releaseLegalHold('tenant-a', item.evidenceId, {
    confirmation: `RELEASE HOLD ${item.evidenceId}`, reason: 'Matter formally closed'
  }, { actor: 'admin.two' });
  assert.equal(registry.dispose('tenant-a', item.evidenceId, {
    confirmation: `DISPOSE ${item.evidenceId}`, reason: 'Retention completed after approved review'
  }, { actor: 'admin.one' }).status, 'disposed');
});

test('referenced evidence cannot be disposed', () => {
  const { registry, setNow } = fixture();
  const item = registry.ingest('tenant-a', {
    filename: 'a.txt', mediaType: 'text/plain', contentBase64: Buffer.from('a').toString('base64'),
    retentionUntil: '2026-07-31T00:00:00.000Z'
  }, { actor: 'auditor.one' });
  setNow('2026-08-02T00:00:00.000Z');
  assert.throws(() => registry.dispose('tenant-a', item.evidenceId, {
    confirmation: `DISPOSE ${item.evidenceId}`, reason: 'Retention completed after approved review'
  }, { actor: 'admin.one', referencedBy: ['FND-1'] }), EvidenceConflictError);
});

test('tampered content fails closed', () => {
  const { registry, directory } = fixture();
  const item = registry.ingest('tenant-a', {
    filename: 'a.txt', mediaType: 'text/plain', contentBase64: Buffer.from('a').toString('base64')
  }, { actor: 'auditor.one' });
  const files = [];
  const walk = (path) => {
    for (const entry of readdirSync(path, { withFileTypes: true })) {
      const child = join(path, entry.name);
      entry.isDirectory() ? walk(child) : files.push(child);
    }
  };
  walk(directory);
  const contentFile = files.find((path) => path.endsWith('.evidence') && !path.endsWith('index.evidence'));
  const envelope = JSON.parse(readFileSync(contentFile, 'utf8'));
  envelope.ciphertext = envelope.ciphertext.replace(/^./, envelope.ciphertext[0] === 'A' ? 'B' : 'A');
  writeFileSync(contentFile, JSON.stringify(envelope));
  assert.throws(() => registry.readContent('tenant-a', item.evidenceId), EvidenceIntegrityError);
});
