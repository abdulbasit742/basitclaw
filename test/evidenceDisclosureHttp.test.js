import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request as httpRequest } from 'node:http';
import { AuthorizationError } from '../src/security/accessControl.js';
import { createEvidenceDisclosureHandler } from '../src/evidence/evidenceDisclosureHandler.js';

const evidenceId = `EVD-${'1'.repeat(32)}`;
const bundleId = `DSC-${'2'.repeat(32)}`;

async function listen(handler) {
  const server = createServer((req, res) => handler.handle(req, res));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { server, port: server.address().port };
}
async function closeServer(server) {
  server.closeAllConnections?.();
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}
function request(port, { method = 'GET', path = '/', body = null, role = 'manager' } = {}) {
  const bytes = body === null ? null : Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const req = httpRequest({
      host: '127.0.0.1', port, method, path,
      headers: { 'x-test-role': role, connection: 'close', ...(bytes ? { 'content-type': 'application/json', 'content-length': bytes.length } : {}) },
      agent: false
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        resolve({ status: res.statusCode, headers: res.headers, body: text ? JSON.parse(text) : null });
      });
    });
    req.on('error', reject);
    req.end(bytes);
  });
}
function authenticationGateway() {
  return {
    mode: 'api-key',
    async authenticate(req) {
      const manager = req.headers['x-test-role'] !== 'viewer';
      return {
        subject: manager ? 'manager.one' : 'viewer.one', tenantId: 'tenant-http', keyId: manager ? 'manager-key' : 'viewer-key',
        permissions: manager ? ['evidence:disclose', 'governance:read'] : ['governance:read']
      };
    },
    authorise(principal, permission) { if (!principal.permissions.includes(permission)) throw new AuthorizationError(undefined, { reason: 'permission_denied', permission }); }
  };
}
function registry() {
  return {
    createDisclosureBundle(tenantId, requestedEvidenceId, input, context) {
      assert.equal(tenantId, 'tenant-http');
      assert.equal(requestedEvidenceId, evidenceId);
      assert.equal(input.recipientId, 'external-auditor');
      assert.equal(context.actor, 'manager.one');
      return { created: true, duplicate: false, bundle: { bundleId, evidenceId, recipientId: 'external-auditor', versionCount: 1, rawEvidenceIncluded: false }, verification: { valid: true, bundleId } };
    },
    disclosureBundles() { return [{ bundleId, evidenceId, rawEvidenceIncluded: false }]; },
    disclosurePackage() { return { format: 'basitclaw-assurance-disclosure-package-v1', version: 1, bundleId, recipientKeyId: 'external-auditor:rsa-1', signingKeyId: 'enterprise-1', ciphertext: 'YQ==' }; },
    verifyDisclosureBundle() { return { valid: true, bundleId, sealed: true }; },
    disclosureStatus() { return { status: 'ready', enabled: true, rawEvidenceIncluded: false }; }
  };
}

test('manager creates a disclosure bundle through the dedicated permission', async (t) => {
  const handler = createEvidenceDisclosureHandler({ registry: registry(), authenticationGateway: authenticationGateway() });
  const { server, port } = await listen(handler);
  t.after(() => closeServer(server));
  const response = await request(port, {
    method: 'POST', path: `/api/workforce-audit/evidence/${evidenceId}/disclosure-bundles`,
    body: { recipientId: 'external-auditor', idempotencyKey: 'audit-001', purpose: 'Independent annual controls review', confirmation: `CREATE DISCLOSURE ${evidenceId}` }
  });
  assert.equal(response.status, 201);
  assert.equal(response.body.data.bundle.bundleId, bundleId);
});

test('viewer cannot create disclosures but can list governed records', async (t) => {
  const handler = createEvidenceDisclosureHandler({ registry: registry(), authenticationGateway: authenticationGateway() });
  const { server, port } = await listen(handler);
  t.after(() => closeServer(server));
  const denied = await request(port, {
    method: 'POST', role: 'viewer', path: `/api/workforce-audit/evidence/${evidenceId}/disclosure-bundles`,
    body: { recipientId: 'external-auditor', idempotencyKey: 'audit-001', purpose: 'Independent annual controls review', confirmation: `CREATE DISCLOSURE ${evidenceId}` }
  });
  assert.equal(denied.status, 403);
  const listed = await request(port, { role: 'viewer', path: `/api/workforce-audit/evidence/${evidenceId}/disclosure-bundles` });
  assert.equal(listed.status, 200);
  assert.equal(listed.body.data.length, 1);
});

test('sealed package download uses an attachment name and metadata-only policy header', async (t) => {
  const handler = createEvidenceDisclosureHandler({ registry: registry(), authenticationGateway: authenticationGateway() });
  const { server, port } = await listen(handler);
  t.after(() => closeServer(server));
  const response = await request(port, { path: `/api/workforce-audit/disclosure-bundles/${bundleId}` });
  assert.equal(response.status, 200);
  assert.match(response.headers['content-disposition'], new RegExp(bundleId));
  assert.equal(response.headers['x-basitclaw-content-policy'], 'metadata-only-recipient-encrypted');
  assert.equal(response.body.bundleId, bundleId);
});

test('malformed percent encoding returns a controlled 400 response', async (t) => {
  const handler = createEvidenceDisclosureHandler({ registry: registry(), authenticationGateway: authenticationGateway() });
  const { server, port } = await listen(handler);
  t.after(() => closeServer(server));
  const response = await request(port, { path: '/api/workforce-audit/disclosure-bundles/%E0%A4%A' });
  assert.equal(response.status, 400);
  assert.match(response.body.error, /percent-encoded/);
});
