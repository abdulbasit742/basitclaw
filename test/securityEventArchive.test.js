import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createSecurityEventArchive } from '../src/security/securityEventArchive.js';

const key = Buffer.alloc(32, 23).toString('base64');

function setup(t) {
  const root = mkdtempSync(join(tmpdir(), 'basitclaw-security-archive-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}

function event(id, type = 'authentication.failed') {
  return {
    id, sequence: Number(id.split('-').at(-1)), occurredAt: '2026-07-29T00:00:00.000Z',
    type, severity: 'warning', outcome: 'denied', requestId: `req-${id}`,
    ipFingerprint: 'abcdef0123456789abcdef01', keyId: 'key-a', subject: null,
    tenantId: null, method: 'GET', route: '/api/workforce-audit/overview',
    details: { reason: 'invalid_key' }, previousHash: null, hash: 'source-hash'
  };
}

test('archive encrypts events and verifies a cross-process sequence', (t) => {
  const root = setup(t);
  const first = createSecurityEventArchive({ directory: root, encryptionKey: key });
  const second = createSecurityEventArchive({ directory: root, encryptionKey: key });
  first.append(event('SEC-1'));
  second.append(event('SEC-2', 'request.rate_limited'));
  const segment = join(root, 'segments', readdirSync(join(root, 'segments'))[0]);
  const stored = readFileSync(segment, 'utf8');
  assert.doesNotMatch(stored, /authentication\.failed|request\.rate_limited|invalid_key/);
  const integrity = first.verify();
  assert.equal(integrity.valid, true);
  assert.equal(integrity.headSequence, 2);
  const listed = second.list({ limit: 10 });
  assert.equal(listed.events.length, 2);
  assert.equal(listed.events[1].type, 'request.rate_limited');
});

test('archive recovers a committed segment when head update was interrupted', (t) => {
  const root = setup(t);
  const archive = createSecurityEventArchive({ directory: root, encryptionKey: key });
  archive.append(event('SEC-1'));
  const headPath = join(root, 'head.json');
  const firstHead = readFileSync(headPath, 'utf8');
  archive.append(event('SEC-2'));
  writeFileSync(headPath, firstHead);
  const reopened = createSecurityEventArchive({ directory: root, encryptionKey: key });
  reopened.append(event('SEC-3'));
  const integrity = reopened.verify();
  assert.equal(integrity.valid, true);
  assert.equal(integrity.headSequence, 3);
});

test('archive detects ciphertext tampering', (t) => {
  const root = setup(t);
  const archive = createSecurityEventArchive({ directory: root, encryptionKey: key });
  archive.append(event('SEC-1'));
  const segment = join(root, 'segments', readdirSync(join(root, 'segments'))[0]);
  const envelope = JSON.parse(readFileSync(segment, 'utf8'));
  envelope.ciphertext = `${envelope.ciphertext.slice(0, -2)}AA`;
  writeFileSync(segment, `${JSON.stringify(envelope)}\n`);
  assert.equal(archive.verify().valid, false);
});

test('retention prunes old segments and preserves a signed anchor', (t) => {
  const root = setup(t);
  let current = new Date('2026-07-01T00:00:00.000Z');
  const archive = createSecurityEventArchive({
    directory: root, encryptionKey: key, retentionDays: 2, maxSegmentBytes: 1024,
    now: () => new Date(current)
  });
  archive.append(event('SEC-1'));
  current = new Date('2026-07-10T00:00:00.000Z');
  archive.append(event('SEC-2'));
  const integrity = archive.verify();
  assert.equal(integrity.valid, true);
  assert.equal(integrity.anchorSequence, 1);
  assert.equal(integrity.headSequence, 2);
  assert.equal(readdirSync(join(root, 'segments')).length, 1);
});
