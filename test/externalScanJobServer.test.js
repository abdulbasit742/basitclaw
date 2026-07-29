import test from 'node:test';
import assert from 'node:assert/strict';
import {
  constants,
  createDecipheriv,
  createHmac,
  generateKeyPairSync,
  privateDecrypt
} from 'node:crypto';
import { createServer } from 'node:http';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuthorizationError } from '../src/security/accessControl.js';
import { sha256 } from '../src/evidence/evidenceCrypto.js';
import { createEvidenceRegistry } from '../src/evidence/evidenceRegistry.js';
import { createEvidenceScreeningEngine } from '../src/evidence/evidenceScreeningEngine.js';
import { createScreenedEvidenceRegistry } from '../src/evidence/evidenceScreeningRegistry.js';
import { createExternalScanAttestationRegistry } from '../src/evidence/externalScanAttestationRegistry.js';
import { createExternalScanContentReader } from '../src/evidence/externalScanContentReader.js';
import { createExternalScanEvidenceRegistry } from '../src/evidence/externalScanEvidenceRegistry.js';
import { createExternalScanJobOutbox } from '../src/evidence/externalScanJobOutbox.js';
import { createExternalScanJobDeliveryHandler } from '../src/evidence/externalScanJobDeliveryHandler.js';
import { createExternalScanJobGovernanceHandler } from '../src/evidence/externalScanJobGovernanceHandler.js';

const currentIso = '2026-07-30T01:30:00.000Z';
const evidenceKey = Buffer.alloc(32, 37).toString('base64');
const providerSecret = Buffer.alloc(48, 43);
const rsa = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), 'scan-job-http-'));
  const base = createEvidenceRegistry({ directory, keys: { k1: evidenceKey }, primaryKeyId: 'k1' });
  const screened = createScreenedEvidenceRegistry({
    registry: base,
    engine: createEvidenceScreeningEngine({ mode: 'enforce', now: () => new Date(currentIso) }),
    keys: { k1: evidenceKey },
    primaryKeyId: 'k1',
    eventRetention: 100,
    now: () => new Date(currentIso)
  });
  const providers = {
    'managed-av': {
      keys: { '2026-q3': providerSecret.toString('base64') },
      publicKeys: { '2026-q3': rsa.publicKey }
    }
  };
  const attestations = createExternalScanAttestationRegistry({
    directory,
    keys: { k1: evidenceKey },
    primaryKeyId: 'k1',
    providers,
    mode: 'enforce',
    requiredForRelease: true,
    maxAttestationAgeMinutes: 60,
    clockSkewSeconds: 300,
    eventRetention: 100,
    maxRecords: 1000,
    now: () => new Date(currentIso)
  });
  const jobs = createExternalScanJobOutbox({
    mode: 'pull',
    required: true,
    directory: join(directory, '.external-scan-jobs'),
    evidenceKeys: { k1: evidenceKey },
    evidencePrimaryKeyId: 'k1',
    providers,
    completedRetention: 100,
    deadLetterRetention: 100,
    now: () => new Date(currentIso)
  });
  const contentReader = createExternalScanContentReader({ registry: screened, keys: { k1: evidenceKey }, primaryKeyId: 'k1' });
  const registry = createExternalScanEvidenceRegistry({ registry: screened, attestations, jobs, contentReader });
  const item = registry.ingest('tenant-a', {
    filename: 'active-script.js',
    mediaType: 'application/javascript',
    contentBase64: Buffer.from('alert("scan me")').toString('base64')
  }, { actor: 'auditor.one' });
  return { registry, item };
}

function gateway(permissions = ['governance:read', 'evidence:scan']) {
  const principal = { subject: 'audit.manager', tenantId: 'tenant-a', keyId: 'key-1', role: 'audit_manager', permissions };
  return {
    mode: 'api-key',
    authenticate: async () => principal,
    authorise(candidate, permission) {
      if (!candidate.permissions.includes(permission)) throw new AuthorizationError(undefined, { permission });
      return candidate;
    }
  };
}

function signed(body, { nonce = 'nonce-0000000000000100', valid = true } = {}) {
  const bytes = Buffer.from(JSON.stringify(body));
  const canonical = `managed-av\n2026-q3\n${currentIso}\n${nonce}\n${sha256(bytes)}`;
  const secret = valid ? providerSecret : Buffer.alloc(48, 1);
  return {
    bytes,
    headers: {
      'content-type': 'application/json',
      'x-basitclaw-scan-provider': 'managed-av',
      'x-basitclaw-scan-key-id': '2026-q3',
      'x-basitclaw-scan-timestamp': currentIso,
      'x-basitclaw-scan-nonce': nonce,
      'x-basitclaw-scan-signature': createHmac('sha256', secret).update(canonical).digest('hex')
    }
  };
}

function decrypt(pkg) {
  const key = privateDecrypt({ key: rsa.privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, Buffer.from(pkg.wrappedKey, 'base64'));
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(pkg.iv, 'base64'));
  decipher.setAAD(Buffer.from(pkg.aad, 'base64'));
  decipher.setAuthTag(Buffer.from(pkg.tag, 'base64'));
  return JSON.parse(Buffer.concat([decipher.update(Buffer.from(pkg.ciphertext, 'base64')), decipher.final()]).toString('utf8'));
}

async function listen(handler) {
  const server = createServer((req, res) => handler.handle(req, res));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { server, base: `http://127.0.0.1:${server.address().port}` };
}

test('manager queues a quarantined version and approved scanner pulls only a sealed package', async (t) => {
  const { registry, item } = fixture();
  const governance = createExternalScanJobGovernanceHandler({ registry, authenticationGateway: gateway() });
  const governanceServer = await listen(governance);
  t.after(() => governanceServer.server.close());

  const queuedResponse = await fetch(`${governanceServer.base}/api/workforce-audit/evidence/${item.evidenceId}/external-scan-jobs`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ providerId: 'managed-av', version: 1 })
  });
  assert.equal(queuedResponse.status, 202);
  const queued = (await queuedResponse.json()).data.job;
  assert.equal(queued.state, 'pending');

  const delivery = createExternalScanJobDeliveryHandler({ registry });
  const deliveryServer = await listen(delivery);
  t.after(() => deliveryServer.server.close());
  const claimRequest = signed({ limit: 1 });
  const claimResponse = await fetch(`${deliveryServer.base}/api/workforce-audit/external-scanner/jobs/claim`, {
    method: 'POST', headers: claimRequest.headers, body: claimRequest.bytes
  });
  assert.equal(claimResponse.status, 200);
  const claim = (await claimResponse.json()).data.jobs[0];
  const payload = decrypt(claim.package);
  assert.equal(payload.evidenceId, item.evidenceId);
  assert.equal(payload.jobId, queued.jobId);
  assert.equal(JSON.stringify(claim).includes('active-script.js'), false);
});

test('signed attestation completes the matching queued delivery job', () => {
  const { registry, item } = fixture();
  const queued = registry.queueExternalScanJob('tenant-a', item.evidenceId, { providerId: 'managed-av' }, { actor: 'audit.manager' });
  const report = registry.screeningReport('tenant-a', item.evidenceId);
  const body = {
    attestationId: 'managed-av:scan:0000000000000200',
    tenantId: 'tenant-a', evidenceId: item.evidenceId, version: 1,
    contentSha256: report.contentSha256, verdict: 'clean', scannedAt: currentIso,
    engine: 'Managed AV Gateway', engineVersion: '9.1', definitionsVersion: '2026.07.30.2', findings: []
  };
  const request = signed(body, { nonce: 'nonce-0000000000000200' });
  const accepted = registry.recordExternalScanAttestation(request.bytes, request.headers);
  assert.equal(accepted.jobCompletion.matched, true);
  const jobs = registry.externalScanJobs('tenant-a', item.evidenceId);
  assert.equal(jobs[0].jobId, queued.job.jobId);
  assert.equal(jobs[0].state, 'completed');
});

test('auditors without evidence scan permission cannot queue scanner jobs', async (t) => {
  const { registry, item } = fixture();
  const handler = createExternalScanJobGovernanceHandler({ registry, authenticationGateway: gateway(['governance:read']) });
  const { server, base } = await listen(handler);
  t.after(() => server.close());
  const response = await fetch(`${base}/api/workforce-audit/evidence/${item.evidenceId}/external-scan-jobs`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ providerId: 'managed-av' })
  });
  assert.equal(response.status, 403);
});

test('scanner pull rejects invalid HMAC signatures and exact request replays', async (t) => {
  const { registry, item } = fixture();
  registry.queueExternalScanJob('tenant-a', item.evidenceId, { providerId: 'managed-av' }, { actor: 'audit.manager' });
  const handler = createExternalScanJobDeliveryHandler({ registry });
  const { server, base } = await listen(handler);
  t.after(() => server.close());

  const invalid = signed({ limit: 1 }, { valid: false, nonce: 'nonce-0000000000000300' });
  const denied = await fetch(`${base}/api/workforce-audit/external-scanner/jobs/claim`, { method: 'POST', headers: invalid.headers, body: invalid.bytes });
  assert.equal(denied.status, 401);

  const valid = signed({ limit: 1 }, { nonce: 'nonce-0000000000000301' });
  const first = await fetch(`${base}/api/workforce-audit/external-scanner/jobs/claim`, { method: 'POST', headers: valid.headers, body: valid.bytes });
  assert.equal(first.status, 200);
  const replay = await fetch(`${base}/api/workforce-audit/external-scanner/jobs/claim`, { method: 'POST', headers: valid.headers, body: valid.bytes });
  assert.equal(replay.status, 401);
  assert.equal((await replay.json()).details.reason, 'replay_detected');
});
