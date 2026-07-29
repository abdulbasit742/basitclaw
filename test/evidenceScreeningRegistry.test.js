import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createEvidenceRegistry } from '../src/evidence/evidenceRegistry.js';
import { createEvidenceScreeningEngine } from '../src/evidence/evidenceScreeningEngine.js';
import {
  EvidenceQuarantinedError,
  createScreenedEvidenceRegistry
} from '../src/evidence/evidenceScreeningRegistry.js';

const key = Buffer.alloc(32, 11).toString('base64');
const encode = (value) => Buffer.from(value).toString('base64');

function fixture({ now = () => new Date(), eventRetention = 100 } = {}) {
  const directory = mkdtempSync(join(tmpdir(), 'screened-evidence-'));
  const base = createEvidenceRegistry({
    directory,
    keys: { k1: key },
    primaryKeyId: 'k1',
    defaultRetentionDays: 30,
    eventRetention: 100
  });
  const engine = createEvidenceScreeningEngine({ mode: 'enforce' });
  const registry = createScreenedEvidenceRegistry({
    registry: base,
    engine,
    keys: { k1: key },
    primaryKeyId: 'k1',
    eventRetention,
    now
  });
  return { registry, directory };
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

test('quarantined evidence cannot be downloaded or referenced until exact release', () => {
  const { registry } = fixture();
  const secret = '-----BEGIN PRIVATE KEY-----\nquarantine-me\n-----END PRIVATE KEY-----';
  const item = registry.ingest('tenant-a', {
    filename: 'secret.txt',
    mediaType: 'text/plain',
    contentBase64: encode(secret)
  }, { actor: 'auditor.one' });

  assert.equal(item.status, 'quarantine');
  assert.throws(() => registry.readContent('tenant-a', item.evidenceId), EvidenceQuarantinedError);
  assert.throws(() => registry.assertUsableReferences('tenant-a', [item.evidenceId]), EvidenceQuarantinedError);
  assert.throws(() => registry.releaseQuarantine('tenant-a', item.evidenceId, {
    confirmation: 'wrong', reason: 'Approved false positive after secure review'
  }, { actor: 'admin.one' }));

  const released = registry.releaseQuarantine('tenant-a', item.evidenceId, {
    confirmation: `RELEASE QUARANTINE ${item.evidenceId}`,
    reason: 'Approved false positive after secure review'
  }, { actor: 'admin.one' });
  assert.equal(released.status, 'active');
  assert.equal(registry.readContent('tenant-a', item.evidenceId).content.toString(), secret);
  assert.equal(registry.verify('tenant-a', item.evidenceId).screening.valid, true);
});

test('rejected versions remain inaccessible but a later clean version can recover the item', () => {
  const { registry } = fixture();
  const item = registry.ingest('tenant-a', {
    filename: 'script.js', mediaType: 'application/javascript', contentBase64: encode('alert(1)')
  }, { actor: 'auditor.one' });
  assert.equal(item.status, 'quarantine');
  const rejected = registry.rejectQuarantine('tenant-a', item.evidenceId, {
    confirmation: `REJECT EVIDENCE ${item.evidenceId}`,
    reason: 'Active script content is not permitted as audit evidence'
  }, { actor: 'admin.one' });
  assert.equal(rejected.status, 'rejected');
  assert.throws(() => registry.readContent('tenant-a', item.evidenceId), EvidenceQuarantinedError);

  const remediated = registry.addVersion('tenant-a', item.evidenceId, {
    filename: 'script.txt', mediaType: 'text/plain', contentBase64: encode('reviewed static transcript')
  }, { actor: 'auditor.two' });
  assert.equal(remediated.status, 'active');
  assert.equal(remediated.currentVersion, 2);
  assert.equal(registry.readContent('tenant-a', item.evidenceId).content.toString(), 'reviewed static transcript');
  assert.throws(() => registry.readContent('tenant-a', item.evidenceId, { version: 1 }), EvidenceQuarantinedError);
});

test('screening metadata and matched secrets remain encrypted on disk', () => {
  const { registry, directory } = fixture();
  registry.ingest('tenant-a', {
    filename: 'secret.txt', mediaType: 'text/plain', contentBase64: encode('AKIAABCDEFGHIJKLMNOP')
  }, { actor: 'auditor.one' });
  const text = filesUnder(directory).map((path) => readFileSync(path, 'utf8')).join('\n');
  assert.equal(text.includes('DLP_CLOUD_ACCESS_KEY'), false);
  assert.equal(text.includes('AKIAABCDEFGHIJKLMNOP'), false);
});

test('tampered screening index fails closed', () => {
  const { registry, directory } = fixture();
  const item = registry.ingest('tenant-a', {
    filename: 'a.txt', mediaType: 'text/plain', contentBase64: encode('clean')
  }, { actor: 'auditor.one' });
  const screeningFile = filesUnder(directory).find((path) => path.endsWith('screening.evidence'));
  const envelope = JSON.parse(readFileSync(screeningFile, 'utf8'));
  envelope.ciphertext = envelope.ciphertext.replace(/^./, envelope.ciphertext[0] === 'A' ? 'B' : 'A');
  writeFileSync(screeningFile, JSON.stringify(envelope));
  assert.throws(() => registry.get('tenant-a', item.evidenceId));
});

test('tenant status reports quarantined and rejected evidence posture', () => {
  const { registry } = fixture();
  registry.ingest('tenant-a', {
    filename: 'script.js', mediaType: 'application/javascript', contentBase64: encode('alert(1)')
  }, { actor: 'auditor.one' });
  const status = registry.tenantStatus('tenant-a');
  assert.equal(status.status, 'attention');
  assert.equal(status.screening.quarantined, 1);
  assert.equal(status.screening.rejected, 0);
});

test('screening events honour the injected clock and configured retention anchor', () => {
  const occurredAt = '2030-01-02T03:04:05.000Z';
  const { registry } = fixture({ now: () => new Date(occurredAt), eventRetention: 100 });
  const item = registry.ingest('tenant-a', {
    filename: 'version-0.txt', mediaType: 'text/plain', contentBase64: encode('version-0')
  }, { actor: 'auditor.one' });
  for (let version = 1; version <= 100; version += 1) {
    registry.addVersion('tenant-a', item.evidenceId, {
      filename: `version-${version}.txt`,
      mediaType: 'text/plain',
      contentBase64: encode(`version-${version}`)
    }, { actor: 'auditor.one' });
  }
  const events = registry.screeningEvents('tenant-a', { limit: 500 });
  assert.equal(events.length, 100);
  assert.equal(events[0].sequence, 101);
  assert.equal(events.at(-1).sequence, 2);
  assert.ok(events.every((event) => event.occurredAt === occurredAt));
  const integrity = registry.verify('tenant-a', item.evidenceId).screening;
  assert.equal(integrity.anchorSequence, 1);
  assert.equal(integrity.headSequence, 101);
});
