import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request as httpRequest } from 'node:http';
import { AuthenticationError, AuthorizationError } from '../src/security/accessControl.js';
import { EvidenceAssuranceBundleAuthenticationError } from '../src/evidence/evidenceAssuranceBundleStore.js';
import { createEvidenceAssuranceBundleHandler } from '../src/evidence/evidenceAssuranceBundleHandler.js';

async function listen(handler) {
  const server = createServer((req, res) => handler.handle(req, res));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { server, port: server.address().port };
}
function close(server) { return new Promise((resolve, reject) => { server.close((error) => error ? reject(error) : resolve()); server.closeAllConnections?.(); }); }
function request(port, method, path, body = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const bytes = body === null ? null : Buffer.from(JSON.stringify(body));
    const req = httpRequest({ host: '127.0.0.1', port, method, path, headers: { connection: 'close', ...(bytes ? { 'content-type': 'application/json', 'content-length': bytes.length } : {}), ...headers } }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) }));
    });
    req.on('error', reject);
    req.end(bytes);
  });
}

function fixture(role = 'audit_manager') {
  const registry = {
    assuranceBundleStatus() { return { status: 'ready', enabled: true, required: true, pending: 1 }; },
    assuranceBundles() { return [{ bundleId: `ASB-${'a'.repeat(32)}`, state: 'pending' }]; },
    createAssuranceBundle(tenantId, evidenceId, input, context) {
      assert.equal(tenantId, 'tenant-a'); assert.match(evidenceId, /^EVD-/); assert.equal(context.actor, 'manager.one');
      return { duplicate: false, bundle: { bundleId: `ASB-${'a'.repeat(32)}`, evidenceId, evidenceVersion: input.version, recipientId: input.recipientId } };
    },
    claimAssuranceBundles() { throw new EvidenceAssuranceBundleAuthenticationError(); },
    acknowledgeAssuranceBundle() { throw new EvidenceAssuranceBundleAuthenticationError(); }
  };
  const authenticationGateway = {
    mode: 'api-key',
    async authenticate(req) { if (!req.headers['x-api-key']) throw new AuthenticationError(); return { subject: 'manager.one', tenantId: 'tenant-a', keyId: 'key-1', role, permissions: role === 'audit_manager' ? ['governance:read', 'evidence:export'] : ['audit:read'] }; },
    authorise(principal, permission) { if (!principal.permissions.includes(permission)) throw new AuthorizationError(); }
  };
  return createEvidenceAssuranceBundleHandler({ registry, authenticationGateway });
}

test('governance API queues a recipient-bound assurance bundle', async (t) => {
  const { server, port } = await listen(fixture());
  t.after(() => close(server));
  const evidenceId = `EVD-${'b'.repeat(32)}`;
  const response = await request(port, 'POST', `/api/workforce-audit/evidence/${evidenceId}/assurance-bundles`, {
    version: 1,
    recipientId: 'external-auditor',
    purpose: 'Independent external workforce audit review',
    confirmation: `EXPORT ${evidenceId} V1 TO external-auditor`
  }, { 'x-api-key': 'local-development-key' });
  assert.equal(response.status, 202);
  assert.equal(response.body.data.bundle.recipientId, 'external-auditor');
});

test('roles without evidence export permission receive 403', async (t) => {
  const { server, port } = await listen(fixture('auditor'));
  t.after(() => close(server));
  const evidenceId = `EVD-${'c'.repeat(32)}`;
  const response = await request(port, 'POST', `/api/workforce-audit/evidence/${evidenceId}/assurance-bundles`, {
    version: 1, recipientId: 'external-auditor', purpose: 'Independent external workforce audit review', confirmation: `EXPORT ${evidenceId} V1 TO external-auditor`
  }, { 'x-api-key': 'local-development-key' });
  assert.equal(response.status, 403);
});

test('malformed encoded evidence IDs return controlled 400 responses', async (t) => {
  const { server, port } = await listen(fixture());
  t.after(() => close(server));
  const response = await request(port, 'GET', '/api/workforce-audit/evidence/%E0%A4%A/assurance-bundles', null, { 'x-api-key': 'local-development-key' });
  assert.equal(response.status, 400);
  assert.match(response.body.error, /percent encoding/);
});

test('recipient authentication failures are non-disclosing 401 responses', async (t) => {
  const { server, port } = await listen(fixture());
  t.after(() => close(server));
  const response = await request(port, 'POST', '/api/workforce-audit/assurance-recipient/bundles/claim', { limit: 1 });
  assert.equal(response.status, 401);
  assert.equal(response.body.code, 'EVIDENCE_ASSURANCE_RECIPIENT_AUTHENTICATION_FAILED');
});
