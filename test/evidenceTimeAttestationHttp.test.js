import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { createServer, request as httpRequest } from 'node:http';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuthenticationError, AuthorizationError } from '../src/security/accessControl.js';
import { createEvidenceTimeAttestationHandler } from '../src/evidence/evidenceTimeAttestationHandler.js';
import {
  EvidenceTimeAttestationAuthenticationError,
  canonicalTimeAttestation,
  createEvidenceTimeAttestationStore
} from '../src/evidence/evidenceTimeAttestationStore.js';

const tenantId = 'tenant-notary-http';
const archiveId = `ARC-${'1'.repeat(32)}`;
const challenge = {
  tenantId,
  archiveId,
  receiptSha256: '2'.repeat(64),
  objectEnvelopeSha256: '3'.repeat(64),
  archivedAt: '2026-07-30T00:00:00.000Z',
  retentionUntil: '2033-07-30T00:00:00.000Z'
};
const nowValue = '2026-07-30T00:05:00.000Z';

function fixture() {
  const authority = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  const otherAuthority = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  const store = createEvidenceTimeAttestationStore({
    mode: 'shared-file',
    directory: mkdtempSync(join(tmpdir(), 'time-attestation-http-')),
    encryptionKeys: { n1: Buffer.alloc(32, 101).toString('base64') },
    encryptionPrimaryKeyId: 'n1',
    providers: {
      'authority-one': {
        keys: { k1: { algorithm: 'ed25519', publicKeyPem: authority.publicKey } }
      }
    },
    resolveChallenge: (requestedTenant, requestedArchive) => {
      assert.equal(requestedTenant, tenantId);
      assert.equal(requestedArchive, archiveId);
      return challenge;
    },
    now: () => new Date(nowValue),
    maxRecords: 100
  });
  const registry = {
    recordTimeAttestation(input) { return store.record(input); },
    evidenceTimeAttestationStatus(requestedTenant) { return store.tenantStatus(requestedTenant); },
    timeAttestationChallenge(requestedTenant, requestedArchive) {
      return store.challenge(requestedTenant, requestedArchive);
    },
    evidenceTimeAttestations(requestedTenant, requestedArchive, options) {
      return store.list(requestedTenant, { archiveId: requestedArchive, ...options });
    },
    verifyEvidenceTimeAttestations(requestedTenant, requestedArchive) {
      return store.verifyArchive(requestedTenant, requestedArchive);
    }
  };
  const authenticationGateway = {
    mode: 'api-key',
    async authenticate(req) {
      if (req.headers['x-api-key'] !== 'manager-key') throw new AuthenticationError();
      return {
        subject: 'manager.one', tenantId, keyId: 'manager-key-id', permissions: ['governance:read']
      };
    },
    authorise(principal, permission) {
      if (!principal.permissions.includes(permission)) throw new AuthorizationError();
    }
  };
  const handler = createEvidenceTimeAttestationHandler({ registry, authenticationGateway });
  return { handler, store, authority, otherAuthority };
}

function signedSubmission(privateKey, nonce = 'authority-http-nonce-0001') {
  const input = {
    tenantId,
    archiveId,
    providerId: 'authority-one',
    keyId: 'k1',
    receiptSha256: challenge.receiptSha256,
    objectEnvelopeSha256: challenge.objectEnvelopeSha256,
    timestamp: nowValue,
    policyId: 'qualified-time-policy-v1',
    nonce
  };
  return {
    ...input,
    signature: sign(null, Buffer.from(canonicalTimeAttestation(input)), privateKey).toString('base64')
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

test('signed callback accepts and idempotently replays an authority attestation', async (t) => {
  const { handler, authority } = fixture();
  const { server, port } = await listen(handler);
  t.after(() => closeServer(server));
  const submission = signedSubmission(authority.privateKey);
  const first = await requestJson(port, '/api/workforce-audit/evidence-notary/attestations', {
    method: 'POST', body: submission
  });
  assert.equal(first.status, 202);
  assert.equal(first.body.data.accepted, true);
  const duplicate = await requestJson(port, '/api/workforce-audit/evidence-notary/attestations', {
    method: 'POST', body: submission
  });
  assert.equal(duplicate.status, 200);
  assert.equal(duplicate.body.data.duplicate, true);
});

test('callback rejects invalid asymmetric signatures with a signature challenge', async (t) => {
  const { handler, otherAuthority } = fixture();
  const { server, port } = await listen(handler);
  t.after(() => closeServer(server));
  const response = await requestJson(port, '/api/workforce-audit/evidence-notary/attestations', {
    method: 'POST', body: signedSubmission(otherAuthority.privateKey, 'authority-http-invalid-0001')
  });
  assert.equal(response.status, 401);
  assert.equal(response.body.code, 'EVIDENCE_TIME_ATTESTATION_AUTHENTICATION_FAILED');
  assert.match(response.headers['www-authenticate'], /^Signature /);
});

test('governance routes require authentication and expose challenge, records and verification', async (t) => {
  const { handler, authority } = fixture();
  const { server, port } = await listen(handler);
  t.after(() => closeServer(server));
  const denied = await requestJson(port, '/api/workforce-audit/evidence-notary/status');
  assert.equal(denied.status, 401);

  const challengeResponse = await requestJson(
    port,
    `/api/workforce-audit/evidence-preservation/${archiveId}/notary-challenge`,
    { apiKey: 'manager-key' }
  );
  assert.equal(challengeResponse.status, 200);
  assert.equal(challengeResponse.body.data.receiptSha256, challenge.receiptSha256);

  await requestJson(port, '/api/workforce-audit/evidence-notary/attestations', {
    method: 'POST', body: signedSubmission(authority.privateKey)
  });
  const rows = await requestJson(
    port,
    `/api/workforce-audit/evidence-preservation/${archiveId}/time-attestations`,
    { apiKey: 'manager-key' }
  );
  assert.equal(rows.status, 200);
  assert.equal(rows.body.data.length, 1);

  const verified = await requestJson(
    port,
    `/api/workforce-audit/evidence-preservation/${archiveId}/time-attestations/verify`,
    { method: 'POST', apiKey: 'manager-key' }
  );
  assert.equal(verified.status, 200);
  assert.equal(verified.body.data.quorumSatisfied, true);
});

test('malformed encoded archive IDs return controlled validation errors', async (t) => {
  const { handler } = fixture();
  const { server, port } = await listen(handler);
  t.after(() => closeServer(server));
  const response = await requestJson(
    port,
    '/api/workforce-audit/evidence-preservation/%E0%A4%A/notary-challenge',
    { apiKey: 'manager-key' }
  );
  assert.equal(response.status, 400);
  assert.match(response.body.error, /invalid percent encoding/);
});

test('callback authentication failures never invoke challenge resolution', () => {
  const { store, otherAuthority } = fixture();
  assert.throws(
    () => store.record(signedSubmission(otherAuthority.privateKey, 'authority-http-cheap-reject-0001')),
    EvidenceTimeAttestationAuthenticationError
  );
});
