import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { createSecurityArchiveCodec } from '../src/security/securityArchiveCodec.js';
import { createSecurityEventArchive } from '../src/security/securityEventArchive.js';
import { createSecurityArchiveKeyLifecycle } from '../src/security/securityKeyLifecycle.js';

const oldKey = Buffer.alloc(32, 11).toString('base64');
const newKey = Buffer.alloc(32, 22).toString('base64');

async function directory() {
  return mkdtemp(resolve(tmpdir(), 'basitclaw-key-rotation-'));
}

function event(id) {
  return { id, type: 'authentication.failed', severity: 'high', hash: id.padEnd(64, 'a') };
}

async function withArchiveEnvironment(values, operation) {
  const names = [
    'WORKFORCE_AUDIT_SECURITY_ARCHIVE_KEYS',
    'WORKFORCE_AUDIT_SECURITY_ARCHIVE_PRIMARY_KEY_ID'
  ];
  const previous = Object.fromEntries(names.map((name) => [name, process.env[name]]));
  try {
    for (const name of names) delete process.env[name];
    for (const [name, value] of Object.entries(values)) process.env[name] = value;
    return await operation();
  } finally {
    for (const name of names) {
      if (previous[name] === undefined) delete process.env[name];
      else process.env[name] = previous[name];
    }
  }
}

test('rotated archive appends with the new primary and reads historical envelopes', async () => {
  const root = await directory();
  await withArchiveEnvironment({}, async () => {
    const archive = createSecurityEventArchive({ directory: root, encryptionKey: oldKey, keyId: 'old-key' });
    assert.equal(archive.append(event('SEC-OLD')).keyId, 'old-key');
  });

  await withArchiveEnvironment({
    WORKFORCE_AUDIT_SECURITY_ARCHIVE_KEYS: JSON.stringify({ 'old-key': oldKey, 'new-key': newKey }),
    WORKFORCE_AUDIT_SECURITY_ARCHIVE_PRIMARY_KEY_ID: 'new-key'
  }, async () => {
    const archive = createSecurityEventArchive({ directory: root, encryptionKey: oldKey, keyId: 'old-key' });
    assert.equal(archive.list().events.length, 1);
    assert.equal(archive.append(event('SEC-NEW')).keyId, 'new-key');
    const events = archive.list().events;
    assert.deepEqual(events.map((item) => item.archive.keyId), ['old-key', 'new-key']);
    assert.equal(archive.verify().valid, true);
  });

  const lifecycle = createSecurityArchiveKeyLifecycle({
    directory: root,
    encryptionKeys: { 'old-key': oldKey, 'new-key': newKey },
    primaryKeyId: 'new-key'
  });
  const status = lifecycle.status();
  assert.equal(status.status, 'ready');
  assert.equal(status.references['old-key'].envelopes, 1);
  assert.equal(status.references['new-key'].envelopes, 1);
  assert.equal(lifecycle.canRetire('old-key').safe, false);
  assert.equal(lifecycle.canRetire('old-key').reason, 'retained_references');
  assert.equal(lifecycle.canRetire('new-key').reason, 'primary_key');
});

test('missing historical archive keys fail lifecycle inspection closed', async () => {
  const root = await directory();
  await withArchiveEnvironment({}, async () => {
    createSecurityEventArchive({ directory: root, encryptionKey: oldKey, keyId: 'old-key' }).append(event('SEC-OLD'));
  });
  const lifecycle = createSecurityArchiveKeyLifecycle({
    directory: root,
    encryptionKeys: { 'new-key': newKey },
    primaryKeyId: 'new-key'
  });
  const status = lifecycle.status();
  assert.equal(status.status, 'unavailable');
  assert.deepEqual(status.missingKeyIds, ['old-key']);
});

test('retention signatures remain verifiable across primary-key rotation', () => {
  const oldCodec = createSecurityArchiveCodec({ keys: { 'old-key': oldKey }, primaryKeyId: 'old-key' });
  const keyringCodec = createSecurityArchiveCodec({
    keys: { 'old-key': oldKey, 'new-key': newKey },
    primaryKeyId: 'new-key'
  });
  const anchor = { version: 1, sequence: 12, hash: 'b'.repeat(64), prunedAt: '2026-07-29T00:00:00.000Z' };
  const oldSignature = oldCodec.signAnchor(anchor);
  assert.equal(keyringCodec.verifySigned(anchor, oldSignature, keyringCodec.signAnchor), true);
  assert.equal(keyringCodec.identifySignedKey(anchor, oldSignature, keyringCodec.signAnchor), 'old-key');
  assert.equal(keyringCodec.identifySignedKey(anchor, keyringCodec.signAnchor(anchor), keyringCodec.signAnchor), 'new-key');
});
