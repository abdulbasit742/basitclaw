import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac, generateKeyPairSync } from 'node:crypto';
import { createServer, request as httpRequest } from 'node:http';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { sha256 } from '../src/evidence/evidenceCrypto.js';
import { createExternalScanJobDeliveryHandler } from '../src/evidence/externalScanJobDeliveryHandler.js';
import { createExternalScanJobGovernanceHandler } from '../src/evidence/externalScanJobGovernanceHandler.js';
import { createExternalScanJobOutbox } from '../src/evidence/externalScanJobOutbox.js';

const evidenceKey = Buffer.alloc(32, 71).toString('base64');
const providerSecret = Buffer.alloc(48, 73);
const rsa = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

async function listen(handler) {
  const server = createServer((req, res) => handler.handle(req, res));
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });
  return { server, port: server.address().port };
}

async function closeServer(server) {
  server.closeAllConnections?.();
  await new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}

function rawRequest(port, path, body = '{}') {
  return new Promise((resolve, reject) => {
    const req = httpRequest({
      host: '127.0.0.1', port, method: 'POST', path,
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(body),
        connection: 'close'
      }
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) }));
    });
    req.on('error', reject);
    req.end(body);
  });
}

test('malformed percent encoding in governance evidence IDs returns 400 instead of 500', async (t) => {
  const registry = {
    queueExternalScanJob() { throw new Error('must not be called'); },
    externalScanJobStatus() { return { status: 'ready' }; },
    get() { throw new Error('must not be called'); },
    externalScanJobs() { return []; }
  };
  const authenticationGateway = {
    mode: 'api-key',
    async authenticate() { return { subject: 'manager', tenantId: 'tenant-a', keyId: 'key-1', permissions: ['evidence:scan', 'governance:read'] }; },
    authorise(principal, permission) { assert.equal(principal.permissions.includes(permission), true); }
  };
  const handler = createExternalScanJobGovernanceHandler({ registry, authenticationGateway });
  const { server, port } = await listen(handler);
  t.after(() => closeServer(server));
  const response = await rawRequest(port, '/api/workforce-audit/evidence/%E0%A4%A/external-scan-jobs');
  assert.equal(response.status, 400);
  assert.match(response.body.error, /invalid percent encoding/);
});

test('malformed percent encoding in scanner job IDs returns 400 instead of 500', async (t) => {
  const registry = {
    claimExternalScanJobs() { throw new Error('must not be called'); },
    acknowledgeExternalScanJob() { throw new Error('must not be called'); },
    failExternalScanJob() { throw new Error('must not be called'); }
  };
  const handler = createExternalScanJobDeliveryHandler({ registry });
  const { server, port } = await listen(handler);
  t.after(() => closeServer(server));
  const response = await rawRequest(port, '/api/workforce-audit/external-scanner/jobs/%E0%A4%A/acknowledge');
  assert.equal(response.status, 400);
  assert.match(response.body.error, /invalid percent encoding/);
});

function candidate(index) {
  const suffix = index.toString(16).padStart(32, '0');
  const evidenceId = `EVD-${suffix}`;
  const content = Buffer.from(`chronological-retention-${index}`);
  const contentSha256 = sha256(content);
  const stable = `tenant-a\u0000${evidenceId}\u00001\u0000managed-av\u0000${contentSha256}`;
  const jobId = `SCNJOB-${createHash('sha256').update(stable).digest('hex').slice(0, 32)}`;
  return { evidenceId, content, contentSha256, jobId };
}

function signed(body, timestamp, nonce) {
  const bytes = Buffer.from(JSON.stringify(body));
  const canonical = `managed-av\nh1\n${timestamp}\n${nonce}\n${sha256(bytes)}`;
  return {
    bytes,
    headers: {
      'x-basitclaw-scan-provider': 'managed-av',
      'x-basitclaw-scan-key-id': 'h1',
      'x-basitclaw-scan-timestamp': timestamp,
      'x-basitclaw-scan-nonce': nonce,
      'x-basitclaw-scan-signature': createHmac('sha256', providerSecret).update(canonical).digest('hex')
    }
  };
}

test('dead-letter retention removes the oldest terminal job by timestamp, not job hash order', () => {
  const directory = mkdtempSync(join(tmpdir(), 'scan-review-retention-'));
  let clock = new Date('2026-07-30T03:00:00.000Z');
  const outbox = createExternalScanJobOutbox({
    mode: 'pull', required: true, directory,
    evidenceKeys: { k1: evidenceKey }, evidencePrimaryKeyId: 'k1',
    providers: { 'managed-av': { keys: { h1: providerSecret.toString('base64') }, publicKeys: { r1: rsa.publicKey } } },
    deadLetterRetention: 2, completedRetention: 100, claimLeaseMs: 10_000,
    now: () => new Date(clock)
  });

  const options = Array.from({ length: 24 }, (_, index) => candidate(index + 1)).sort((a, b) => b.jobId.localeCompare(a.jobId));
  const selected = [options[0], options.at(-1), options[Math.floor(options.length / 2)]];
  const terminalOrder = [];
  selected.forEach((item, index) => {
    const queued = outbox.queue({
      tenantId: 'tenant-a', evidenceId: item.evidenceId, version: 1,
      filename: `retention-${index}.bin`, mediaType: 'application/octet-stream',
      contentSha256: item.contentSha256, sizeBytes: item.content.length, content: item.content
    }, 'managed-av', { actor: 'audit.manager' });
    assert.equal(queued.job.jobId, item.jobId);
    const timestamp = clock.toISOString();
    const claim = signed({ limit: 1 }, timestamp, `nonce-retention-${index}-0000001`);
    const claimed = outbox.claimSigned(claim.bytes, claim.headers).jobs[0];
    const fail = signed({ claimToken: claimed.claimToken, retryable: false, reasonCode: 'permanent_failure' }, timestamp, `nonce-retention-${index}-0000002`);
    outbox.failSigned(claimed.jobId, fail.bytes, fail.headers);
    terminalOrder.push(claimed.jobId);
    clock = new Date(clock.getTime() + 60_000);
  });

  const retained = outbox.list('tenant-a', { limit: 10 }).map((job) => job.jobId);
  assert.equal(retained.length, 2);
  assert.equal(retained.includes(terminalOrder[0]), false);
  assert.equal(retained.includes(terminalOrder[1]), true);
  assert.equal(retained.includes(terminalOrder[2]), true);
  assert.notEqual([...terminalOrder].sort()[0], terminalOrder[0], 'test fixture must distinguish hash order from chronological order');
});
