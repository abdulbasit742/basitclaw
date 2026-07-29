import test from 'node:test';
import assert from 'node:assert/strict';
import {
  constants,
  createDecipheriv,
  createHmac,
  generateKeyPairSync,
  privateDecrypt
} from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, readdirSync, renameSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { sha256 } from '../src/evidence/evidenceCrypto.js';
import { ExternalScanAuthenticationError } from '../src/evidence/externalScanAttestationRegistry.js';
import { createExternalScanJobOutbox } from '../src/evidence/externalScanJobOutbox.js';

const evidenceKey = Buffer.alloc(32, 17).toString('base64');
const providerSecret = Buffer.alloc(48, 29);
const providerSecretBase64 = providerSecret.toString('base64');
const currentIso = '2026-07-30T01:00:00.000Z';
const keys = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

function createOutbox({ directory, now = () => new Date(currentIso), required = true, maxAttempts = 3 } = {}) {
  return createExternalScanJobOutbox({
    mode: 'pull',
    required,
    directory,
    evidenceKeys: { k1: evidenceKey },
    evidencePrimaryKeyId: 'k1',
    providers: {
      'managed-av': {
        keys: { '2026-q3': providerSecretBase64 },
        publicKeys: { '2026-q3': keys.publicKey }
      }
    },
    jobTtlMinutes: 60,
    claimLeaseMs: 10_000,
    maxAttempts,
    completedRetention: 100,
    deadLetterRetention: 100,
    clockSkewSeconds: 300,
    now
  });
}

function contentRecord(overrides = {}) {
  const content = Buffer.from('synthetic private-key evidence for managed scanning');
  return {
    tenantId: 'tenant-a',
    evidenceId: 'EVD-0123456789abcdef0123456789abcdef',
    version: 1,
    filename: 'private-key.txt',
    mediaType: 'text/plain',
    contentSha256: sha256(content),
    sizeBytes: content.length,
    content,
    ...overrides
  };
}

function signedBody(body, { nonce = 'nonce-0000000000000001', timestamp = currentIso } = {}) {
  const bytes = Buffer.from(JSON.stringify(body));
  const canonical = `managed-av\n2026-q3\n${timestamp}\n${nonce}\n${sha256(bytes)}`;
  const signature = createHmac('sha256', providerSecret).update(canonical).digest('hex');
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

function decryptPackage(pkg) {
  const key = privateDecrypt({
    key: keys.privateKey,
    padding: constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: 'sha256'
  }, Buffer.from(pkg.wrappedKey, 'base64'));
  const ciphertext = Buffer.from(pkg.ciphertext, 'base64');
  assert.equal(sha256(ciphertext), pkg.ciphertextSha256);
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(pkg.iv, 'base64'));
  decipher.setAAD(Buffer.from(pkg.aad, 'base64'));
  decipher.setAuthTag(Buffer.from(pkg.tag, 'base64'));
  return JSON.parse(Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8'));
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

test('queues encrypted records and scanner can decrypt only with its RSA private key', () => {
  const directory = mkdtempSync(join(tmpdir(), 'scan-jobs-sealed-'));
  const outbox = createOutbox({ directory });
  const content = contentRecord();
  const queued = outbox.queue(content, 'managed-av', { actor: 'audit.manager' });
  assert.equal(queued.queued, true);
  assert.equal(queued.job.state, 'pending');

  const raw = filesUnder(directory).map((path) => readFileSync(path, 'utf8')).join('\n');
  assert.equal(raw.includes(content.content.toString()), false);
  assert.equal(raw.includes(content.evidenceId), false);
  assert.equal(raw.includes(content.filename), false);
  assert.equal(raw.includes('managed-av'), false);
  assert.equal(raw.includes('"state"'), false);

  const claim = signedBody({ limit: 1 });
  const claimed = outbox.claimSigned(claim.bytes, claim.headers);
  assert.equal(claimed.jobs.length, 1);
  const payload = decryptPackage(claimed.jobs[0].package);
  assert.equal(payload.format, 'basitclaw-external-scan-job-payload');
  assert.equal(payload.evidenceId, content.evidenceId);
  assert.equal(payload.contentSha256, content.contentSha256);
  assert.equal(Buffer.from(payload.contentBase64, 'base64').toString(), content.content.toString());

  const ack = signedBody({ claimToken: claimed.jobs[0].claimToken }, { nonce: 'nonce-0000000000000002' });
  const delivered = outbox.acknowledgeSigned(claimed.jobs[0].jobId, ack.bytes, ack.headers);
  assert.equal(delivered.state, 'delivered');
  assert.equal(outbox.list('tenant-a', { evidenceId: content.evidenceId })[0].state, 'delivered');
});

test('signed scanner pull requests are protected against replay', () => {
  const directory = mkdtempSync(join(tmpdir(), 'scan-jobs-replay-'));
  const outbox = createOutbox({ directory });
  outbox.queue(contentRecord(), 'managed-av', { actor: 'audit.manager' });
  const request = signedBody({ limit: 1 }, { nonce: 'nonce-0000000000000010' });
  assert.equal(outbox.claimSigned(request.bytes, request.headers).jobs.length, 1);
  assert.throws(() => outbox.claimSigned(request.bytes, request.headers), ExternalScanAuthenticationError);
});

test('matching signed attestation completes the deterministic delivery job and removes package bytes', () => {
  const directory = mkdtempSync(join(tmpdir(), 'scan-jobs-complete-'));
  const outbox = createOutbox({ directory });
  const content = contentRecord();
  const queued = outbox.queue(content, 'managed-av', { actor: 'audit.manager' });
  const completed = outbox.completeFromAttestation({
    receiptId: 'ESC-0123456789abcdef0123456789abcdef',
    attestationId: 'managed-av:scan:0000000000000100',
    providerId: 'managed-av',
    tenantId: content.tenantId,
    evidenceId: content.evidenceId,
    version: content.version,
    contentSha256: content.contentSha256,
    verdict: 'clean',
    scannedAt: currentIso
  });
  assert.equal(completed.matched, true);
  assert.equal(completed.job.jobId, queued.job.jobId);
  assert.equal(completed.job.state, 'completed');
  assert.equal(outbox.list('tenant-a')[0].state, 'completed');
  const encryptedRecord = readFileSync(filesUnder(join(directory, 'completed')).find((path) => path.endsWith('.json')), 'utf8');
  assert.equal(encryptedRecord.includes('"package"'), false);
  assert.equal(encryptedRecord.includes('completed'), false);
  assert.equal(outbox.verify('tenant-a').valid, true);
});

test('permanent scanner failures dead-letter and a governed repeat queue reseals the job', () => {
  const directory = mkdtempSync(join(tmpdir(), 'scan-jobs-dead-'));
  const outbox = createOutbox({ directory });
  const content = contentRecord();
  outbox.queue(content, 'managed-av', { actor: 'audit.manager' });
  const claimRequest = signedBody({ limit: 1 }, { nonce: 'nonce-0000000000000020' });
  const claimed = outbox.claimSigned(claimRequest.bytes, claimRequest.headers).jobs[0];
  const failRequest = signedBody({ claimToken: claimed.claimToken, retryable: false, reasonCode: 'decrypt_failed' }, { nonce: 'nonce-0000000000000021' });
  const failed = outbox.failSigned(claimed.jobId, failRequest.bytes, failRequest.headers);
  assert.equal(failed.state, 'dead-letter');
  assert.equal(outbox.health().status, 'degraded');
  assert.equal(outbox.tenantStatus('tenant-a').deadLetters, 1);

  const requeued = outbox.queue(content, 'managed-av', { actor: 'audit.manager' });
  assert.equal(requeued.requeued, true);
  assert.equal(requeued.job.state, 'pending');
  assert.equal(outbox.health().status, 'ready');
});

test('expired claims are recovered and cannot be acknowledged with the old token', () => {
  const directory = mkdtempSync(join(tmpdir(), 'scan-jobs-expired-'));
  let clock = new Date(currentIso);
  const outbox = createOutbox({ directory, now: () => new Date(clock) });
  outbox.queue(contentRecord(), 'managed-av', { actor: 'audit.manager' });
  const claimRequest = signedBody({ limit: 1 }, { nonce: 'nonce-0000000000000030' });
  const claimed = outbox.claimSigned(claimRequest.bytes, claimRequest.headers).jobs[0];
  clock = new Date(clock.getTime() + 11_000);
  const ack = signedBody({ claimToken: claimed.claimToken }, { nonce: 'nonce-0000000000000031' });
  assert.throws(() => outbox.acknowledgeSigned(claimed.jobId, ack.bytes, ack.headers), /not found or is no longer claimable/);
  assert.equal(outbox.list('tenant-a')[0].state, 'pending');
});

test('crash-interrupted directory moves are reconciled from encrypted record state', () => {
  const directory = mkdtempSync(join(tmpdir(), 'scan-jobs-reconcile-'));
  const outbox = createOutbox({ directory });
  const queued = outbox.queue(contentRecord(), 'managed-av', { actor: 'audit.manager' });
  const filename = `${queued.job.jobId}.json`;
  const pending = join(directory, 'pending', filename);
  const misplaced = join(directory, 'inflight', filename);
  renameSync(pending, misplaced);
  assert.equal(existsSync(misplaced), true);
  assert.equal(outbox.list('tenant-a')[0].state, 'pending');
  assert.equal(existsSync(pending), true);
  assert.equal(existsSync(misplaced), false);
});

test('multiple outbox instances keep job lookup isolated by directory', () => {
  const first = createOutbox({ directory: mkdtempSync(join(tmpdir(), 'scan-jobs-one-')) });
  const second = createOutbox({ directory: mkdtempSync(join(tmpdir(), 'scan-jobs-two-')) });
  const a = first.queue(contentRecord(), 'managed-av', { actor: 'audit.manager' });
  const b = second.queue(contentRecord(), 'managed-av', { actor: 'audit.manager' });
  assert.equal(a.job.jobId, b.job.jobId);
  assert.equal(first.list('tenant-a').length, 1);
  assert.equal(second.list('tenant-a').length, 1);
});
