import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request as httpRequest } from 'node:http';
import { AuthenticationError, AuthorizationError } from '../src/security/accessControl.js';
import { createEvidenceDisclosureHandler } from '../src/evidence/evidenceDisclosureHandler.js';

const tenantId = 'tenant-disclosure-http';
const packageId = `DSP-${'d'.repeat(32)}`;

function fixture({ permissions = ['evidence:export'] } = {}) {
  const calls = [];
  const registry = {
    evidenceDisclosureStatus() { return { status: 'ready', enabled: true }; },
    listEvidenceDisclosures() { return []; },
    createEvidenceDisclosure(_tenant, input, context) {
      calls.push({ operation: 'create', input, context });
      return { created: true, duplicate: false, disclosure: { packageId, itemCount: 1, recipientKeyId: input.recipientKeyId } };
    },
    evidenceDisclosureMetadata() { return { packageId }; },
    downloadEvidenceDisclosure() {
      calls.push({ operation: 'download' });
      return { disclosure: { packageId, downloadCount: 1, maximumDownloads: 1 }, package: { format: 'basitclaw-evidence-disclosure-v1', packageId } };
    },
    verifyEvidenceDisclosure() { return { valid: true, disclosure: { packageId } }; },
    revokeEvidenceDisclosure(_tenant, requestedPackage, input, context) {
      calls.push({ operation: 'revoke', requestedPackage, input, context });
      return { packageId, revokedAt: '2026-07-30T01:00:00.000Z' };
    }
  };
  const authenticationGateway = {
    mode: 'api-key',
    async authenticate(req) {
      if (req.headers['x-api-key'] !== 'manager-key') throw new AuthenticationError();
      return { subject: 'manager.one', tenantId, keyId: 'manager-key-id', permissions };
    },
    authorise(principal, permission) {
      if (!principal.permissions.includes(permission)) throw new AuthorizationError();
    }
  };
  return { handler: createEvidenceDisclosureHandler({ registry, authenticationGateway }), calls };
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

test('disclosure routes require authentication and evidence export permission', async (t) => {
  const unauthenticated = fixture();
  const first = await listen(unauthenticated.handler);
  t.after(() => closeServer(first.server));
  const denied = await requestJson(first.port, '/api/workforce-audit/evidence-disclosures');
  assert.equal(denied.status, 401);

  const forbiddenFixture = fixture({ permissions: ['governance:read'] });
  const second = await listen(forbiddenFixture.handler);
  t.after(() => closeServer(second.server));
  const forbidden = await requestJson(second.port, '/api/workforce-audit/evidence-disclosures', { apiKey: 'manager-key' });
  assert.equal(forbidden.status, 403);
});

test('creates and downloads only the recipient-encrypted package', async (t) => {
  const { handler, calls } = fixture();
  const { server, port } = await listen(handler);
  t.after(() => closeServer(server));
  const created = await requestJson(port, '/api/workforce-audit/evidence-disclosures', {
    method: 'POST', apiKey: 'manager-key', body: { recipientKeyId: 'regulator-key' }
  });
  assert.equal(created.status, 201);
  assert.equal(calls[0].context.actor, 'manager.one');

  const downloaded = await requestJson(port, `/api/workforce-audit/evidence-disclosures/${packageId}/download`, { apiKey: 'manager-key' });
  assert.equal(downloaded.status, 200);
  assert.match(downloaded.headers['content-disposition'], new RegExp(packageId));
  assert.equal(downloaded.body.data.package.format, 'basitclaw-evidence-disclosure-v1');
});

test('revocation and verification use controlled package routes', async (t) => {
  const { handler, calls } = fixture();
  const { server, port } = await listen(handler);
  t.after(() => closeServer(server));
  const verified = await requestJson(port, `/api/workforce-audit/evidence-disclosures/${packageId}/verify`, {
    method: 'POST', apiKey: 'manager-key'
  });
  assert.equal(verified.status, 200);
  assert.equal(verified.body.data.valid, true);

  const revoked = await requestJson(port, `/api/workforce-audit/evidence-disclosures/${packageId}/revoke`, {
    method: 'POST', apiKey: 'manager-key', body: {
      confirmation: `REVOKE DISCLOSURE ${packageId}`,
      reason: 'Recipient authority was withdrawn before delivery'
    }
  });
  assert.equal(revoked.status, 200);
  assert.equal(calls.at(-1).context.actor, 'manager.one');
});

test('malformed encoded package IDs return controlled validation errors', async (t) => {
  const { handler } = fixture();
  const { server, port } = await listen(handler);
  t.after(() => closeServer(server));
  const response = await requestJson(port, '/api/workforce-audit/evidence-disclosures/%E0%A4%A/download', { apiKey: 'manager-key' });
  assert.equal(response.status, 400);
  assert.match(response.body.error, /invalid percent encoding/);
});
