import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request as httpRequest } from 'node:http';
import { AuthenticationError, AuthorizationError } from '../src/security/accessControl.js';
import { createEvidenceAssuranceGovernanceHandler } from '../src/evidence/evidenceAssuranceGovernanceHandler.js';

const tenantId = 'tenant-assurance-http';
const evidenceId = `EVD-${'a'.repeat(32)}`;
const requestId = `AGR-${'b'.repeat(32)}`;

function fixture() {
  const registry = {
    requestAssuranceBundle(_tenant, _evidence, input, context) {
      return { requestId, evidenceId, state: 'pending', recipientId: input.recipientId, purposeCode: input.purposeCode, residencyZone: input.residencyZone, requestedBy: context.actor };
    },
    approveAssuranceRequest(_tenant, _request, context) {
      return { request: { requestId, state: context.actor === 'admin.two' ? 'sealed' : 'pending' }, bundle: context.actor === 'admin.two' ? { bundleId: `ASB-${'c'.repeat(32)}` } : null };
    },
    sealApprovedRequest() { return { request: { requestId, state: 'sealed' }, bundle: { bundleId: `ASB-${'c'.repeat(32)}` } }; },
    rejectAssuranceRequest() { return { requestId, state: 'rejected' }; },
    revokeAssuranceRequest() { return { requestId, state: 'revoked' }; },
    assuranceRequest() { return { requestId, evidenceId, state: 'pending' }; },
    assuranceRequests() { return [{ requestId, evidenceId, state: 'pending' }]; },
    assuranceBundles() { return []; },
    assuranceGovernanceStatus() { return { status: 'ready', enabled: true }; },
    assuranceGovernanceReport() { return { total: 1, byState: { pending: 1 } }; },
    claimAssuranceBundles() { return { recipientId: 'regulator-one', bundles: [] }; },
    acknowledgeAssuranceBundle(bundleId) { return { bundleId, recipientId: 'regulator-one', state: 'delivered' }; }
  };
  const authenticationGateway = {
    mode: 'api-key',
    async authenticate(req) {
      const key = req.headers['x-api-key'];
      if (!key) throw new AuthenticationError();
      return {
        subject: key === 'admin-key' ? 'admin.two' : key === 'manager-two-key' ? 'manager.two' : 'manager.one',
        tenantId,
        keyId: String(key),
        role: key === 'admin-key' ? 'compliance_admin' : 'audit_manager',
        permissions: ['governance:read', 'evidence:export', 'privileged:revoke']
      };
    },
    authorise(principal, permission) {
      if (!principal.permissions.includes(permission)) throw new AuthorizationError();
    }
  };
  return createEvidenceAssuranceGovernanceHandler({ registry, authenticationGateway });
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
    if (bytes) { headers['content-type'] = 'application/json'; headers['content-length'] = bytes.length; }
    const req = httpRequest({ host: '127.0.0.1', port, method, path, headers }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) }));
    });
    req.on('error', reject);
    req.end(bytes ?? undefined);
  });
}

test('the original assurance-bundle POST now creates a governed request', async (t) => {
  const { server, port } = await listen(fixture());
  t.after(() => closeServer(server));
  const response = await requestJson(port, `/api/workforce-audit/evidence/${evidenceId}/assurance-bundles`, {
    method: 'POST',
    apiKey: 'manager-one-key',
    body: {
      version: 1,
      recipientId: 'regulator-one',
      purpose: 'Authorised regulatory examination response',
      purposeCode: 'regulatory-exam',
      legalBasis: 'statutory-notice',
      residencyZone: 'pk-primary',
      confirmation: `REQUEST EXPORT ${evidenceId} V1 TO regulator-one`
    }
  });
  assert.equal(response.status, 202);
  assert.equal(response.body.data.requestId, requestId);
  assert.equal(response.body.data.state, 'pending');
});

test('approval and revocation require exact governed confirmations', async (t) => {
  const { server, port } = await listen(fixture());
  t.after(() => closeServer(server));
  const approved = await requestJson(port, `/api/workforce-audit/assurance-requests/${requestId}/approve`, {
    method: 'POST', apiKey: 'manager-two-key', body: { confirmation: `APPROVE ASSURANCE ${requestId}` }
  });
  assert.equal(approved.status, 200);
  const revoked = await requestJson(port, `/api/workforce-audit/assurance-requests/${requestId}/revoke`, {
    method: 'POST', apiKey: 'admin-key', body: { confirmation: `REVOKE ASSURANCE ${requestId}`, reason: 'Recipient authority was withdrawn before delivery' }
  });
  assert.equal(revoked.status, 200);
  assert.equal(revoked.body.data.state, 'revoked');
});

test('malformed request IDs return controlled 400 responses and servers close cleanly', async (t) => {
  const { server, port } = await listen(fixture());
  t.after(() => closeServer(server));
  const response = await requestJson(port, '/api/workforce-audit/assurance-requests/%E0%A4%A', { apiKey: 'manager-one-key' });
  assert.equal(response.status, 400);
  assert.match(response.body.error, /invalid percent encoding/);
});
