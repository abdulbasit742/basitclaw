import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { createServer, request as httpRequest } from 'node:http';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuthenticationError, AuthorizationError } from '../src/security/accessControl.js';
import { createEvidenceTimeAttestationRequestHandler } from '../src/evidence/evidenceTimeAttestationRequestHandler.js';
import {
  canonicalEvidenceNotaryRequest,
  createEvidenceTimeAttestationRequestOutbox
} from '../src/evidence/evidenceTimeAttestationRequestOutbox.js';

const tenantId = 'tenant-notary-request-http';
const archiveId = `ARC-${'5'.repeat(32)}`;
const challenge = {
  tenantId,
  archiveId,
  receiptSha256: '6'.repeat(64),
  objectEnvelopeSha256: '7'.repeat(64),
  archivedAt: '2026-07-30T00:00:00.000Z',
  retentionUntil: '2033-07-30T00:00:00.000Z'
};
const nowValue = '2026-07-30T00:05:00.000Z';

function fixture() {
  const authority = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  const other = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  const outbox = createEvidenceTimeAttestationRequestOutbox({
    mode: 'pull', required: true,
    directory: mkdtempSync(join(tmpdir(), 'notary-request-http-')),
    encryptionKeys: { request: Buffer.alloc(32, 73).toString('base64') },
    encryptionPrimaryKeyId: 'request',
    providers: {
      'authority-one': { keys: { k1: { algorithm: 'ed25519', publicKeyPem: authority.publicKey } } }
    },
    completedRetention: 100, deadLetterRetention: 10, eventRetention: 100,
    now: () => new Date(nowValue)
  });
  let queueCalls = 0;
  const registry = {
    queueTimeAttestationRequest(requestedTenant, requestedArchive, input, context) {
      queueCalls += 1;
      assert.equal(requestedTenant, tenantId);
      assert.equal(requestedArchive, archiveId);
      assert.equal(input.confirmation, `REQUEST NOTARY ${archiveId} authority-one`);
      return outbox.queue(challenge, input.providerId, { actor: context.actor, purpose: input.purpose });
    },
    requeueTimeAttestationRequest(requestedTenant, jobId, input, context) {
      return outbox.requeue(requestedTenant, jobId, { actor: context.actor, purpose: input.purpose });
    },
    claimTimeAttestationRequests(input) { return outbox.claimSigned(input); },
    acknowledgeTimeAttestationRequest(jobId, input) { return outbox.acknowledgeSigned(jobId, input); },
    failTimeAttestationRequest(jobId, input) { return outbox.failSigned(jobId, input); },
    evidenceTimeAttestationRequests(requestedTenant, requestedArchive, options) {
      return outbox.list(requestedTenant, { archiveId: requestedArchive, ...options });
    },
    evidenceTimeAttestationRequestStatus(requestedTenant) { return outbox.tenantStatus(requestedTenant); },
    verifyEvidenceTimeAttestationRequests(requestedTenant) { return outbox.verifyTenant(requestedTenant); }
  };
  const authenticationGateway = {
    mode: 'api-key',
    async authenticate(req) {
      if (req.headers['x-api-key'] === 'manager-key') {
        return { subject: 'manager.one', tenantId, keyId: 'manager-key-id', permissions: ['governance:read', 'evidence:notarize'] };
      }
      if (req.headers['x-api-key'] === 'auditor-key') {
        return { subject: 'auditor.one', tenantId, keyId: 'auditor-key-id', permissions: ['governance:read'] };
      }
      throw new AuthenticationError();
    },
    authorise(principal, permission) {
      if (!principal.permissions.includes(permission)) throw new AuthorizationError();
    }
  };
  return {
    handler: createEvidenceTimeAttestationRequestHandler({ registry, authenticationGateway }),
    authority,
    other,
    queueCalls: () => queueCalls
  };
}

function signed(privateKey, input) {
  return {
    ...input,
    signature: sign(null, Buffer.from(canonicalEvidenceNotaryRequest(input)), privateKey).toString('base64')
  };
}

async function listen(handler) {
  const server = createServer((req, res) => handler.handle(req, res));
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return { server, port: server.address().port };
}

async function closeServer(server) {
  server.closeIdleConnections?.();
  server.closeAllConnections?.();
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

function requestJson(port, path, { method = 'GET', body = null, apiKey = null } = {}) {
  const bytes = body === null ? null : Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const headers = { connection: 'close' };
    if (apiKey) headers['x-api-key'] = apiKey;
    if (bytes) {
      headers['content-type'] = 'application/json';
      headers['content-length'] = bytes.length;
    }
    const req = httpRequest({ host: '127.0.0.1', port, method, path, headers }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        resolve({ status: res.statusCode, headers: res.headers, body: text ? JSON.parse(text) : null });
      });
    });
    req.on('error', reject);
    req.end(bytes ?? undefined);
  });
}

test('manager queues and authority claims a notary request', async (t) => {
  const { handler, authority } = fixture();
  const { server, port } = await listen(handler);
  t.after(() => closeServer(server));
  const queued = await requestJson(port, `/api/workforce-audit/evidence-preservation/${archiveId}/notary-requests`, {
    method: 'POST', apiKey: 'manager-key',
    body: {
      providerId: 'authority-one',
      purpose: 'Independent time authority request',
      confirmation: `REQUEST NOTARY ${archiveId} authority-one`
    }
  });
  assert.equal(queued.status, 202);
  const claimInput = {
    action: 'claim', providerId: 'authority-one', keyId: 'k1', timestamp: nowValue,
    nonce: 'authority-http-claim-0001', limit: 1
  };
  const claimed = await requestJson(port, '/api/workforce-audit/evidence-notary/requests/claim', {
    method: 'POST', body: signed(authority.privateKey, claimInput)
  });
  assert.equal(claimed.status, 200);
  assert.equal(claimed.body.data.jobs.length, 1);
  assert.equal(claimed.body.data.jobs[0].challenge.archiveId, archiveId);
});

test('auditors cannot queue notary requests', async (t) => {
  const { handler, queueCalls } = fixture();
  const { server, port } = await listen(handler);
  t.after(() => closeServer(server));
  const response = await requestJson(port, `/api/workforce-audit/evidence-preservation/${archiveId}/notary-requests`, {
    method: 'POST', apiKey: 'auditor-key',
    body: {
      providerId: 'authority-one', purpose: 'Independent time authority request',
      confirmation: `REQUEST NOTARY ${archiveId} authority-one`
    }
  });
  assert.equal(response.status, 403);
  assert.equal(queueCalls(), 0);
});

test('invalid authority signature is rejected before any claim is issued', async (t) => {
  const { handler, other } = fixture();
  const { server, port } = await listen(handler);
  t.after(() => closeServer(server));
  const input = {
    action: 'claim', providerId: 'authority-one', keyId: 'k1', timestamp: nowValue,
    nonce: 'authority-http-invalid-001', limit: 1
  };
  const response = await requestJson(port, '/api/workforce-audit/evidence-notary/requests/claim', {
    method: 'POST', body: signed(other.privateKey, input)
  });
  assert.equal(response.status, 401);
  assert.equal(response.body.code, 'EVIDENCE_NOTARY_REQUEST_AUTHENTICATION_FAILED');
  assert.match(response.headers['www-authenticate'], /^Signature /);
});

test('malformed encoded request IDs return 400', async (t) => {
  const { handler } = fixture();
  const { server, port } = await listen(handler);
  t.after(() => closeServer(server));
  const response = await requestJson(port, '/api/workforce-audit/evidence-notary/requests/%E0%A4%A/requeue', {
    method: 'POST', apiKey: 'manager-key',
    body: { purpose: 'Approved retry after authority recovery', confirmation: 'invalid' }
  });
  assert.equal(response.status, 400);
  assert.match(response.body.error, /invalid percent encoding/);
});
