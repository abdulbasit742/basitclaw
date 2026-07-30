import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request as httpRequest } from 'node:http';
import { AuthenticationError, AuthorizationError } from '../src/security/accessControl.js';
import { EvidenceAssuranceAcceptanceRequiredError } from '../src/evidence/evidenceAssuranceAcceptanceStore.js';
import { createEvidenceAssuranceBundleHandler } from '../src/evidence/evidenceAssuranceBundleHandler.js';

const evidenceId = `EVD-${'a'.repeat(32)}`;
const bundleId = `ASB-${'b'.repeat(32)}`;
const acceptanceId = `AAR-${'c'.repeat(32)}`;

function fixture({ permissions = ['governance:read', 'evidence:export'] } = {}) {
  const calls = { accept: 0, verify: 0, acknowledge: 0 };
  const registry = {
    assuranceBundleStatus() { return { status: 'ready', enabled: true, verifiedAcceptanceRequired: true }; },
    assuranceBundles() { return [{ bundleId, evidenceId, state: 'delivered', acceptanceStatus: 'verified' }]; },
    createAssuranceBundle() { return { duplicate: false, bundle: { bundleId, evidenceId, evidenceVersion: 1, recipientId: 'regulator' } }; },
    claimAssuranceBundles() { return { recipientId: 'regulator', bundles: [], jobs: [] }; },
    acknowledgeAssuranceBundle() { calls.acknowledge += 1; throw new EvidenceAssuranceAcceptanceRequiredError(bundleId); },
    acceptAssuranceBundle(requestedBundleId, body, headers) {
      calls.accept += 1;
      assert.equal(requestedBundleId, bundleId);
      assert.equal(Buffer.isBuffer(body), true);
      assert.equal(headers['x-basitclaw-recipient-id'], 'regulator');
      return {
        duplicate: false,
        bundle: { bundleId, recipientId: 'regulator', state: 'delivered', acceptanceStatus: 'verified' },
        acceptanceReceipt: { acceptanceId, bundleId, verificationOutcome: 'verified' }
      };
    },
    verifyAssuranceAcceptanceReceipt(_tenantId, requestedBundleId) {
      calls.verify += 1;
      assert.equal(requestedBundleId, bundleId);
      return { valid: true, acceptanceReceipt: { acceptanceId, bundleId } };
    }
  };
  const authenticationGateway = {
    mode: 'api-key',
    async authenticate(req) {
      if (req.headers['x-api-key'] !== 'manager-key') throw new AuthenticationError();
      return { subject: 'manager.one', tenantId: 'tenant-a', keyId: 'manager-key-id', permissions };
    },
    authorise(principal, permission) {
      if (!principal.permissions.includes(permission)) throw new AuthorizationError();
    }
  };
  return { handler: createEvidenceAssuranceBundleHandler({ registry, authenticationGateway }), calls };
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
function requestJson(port, path, { method = 'POST', body = {}, apiKey = null, recipientHeaders = {} } = {}) {
  const bytes = Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const headers = {
      connection: 'close',
      'content-type': 'application/json',
      'content-length': bytes.length,
      ...recipientHeaders
    };
    if (apiKey) headers['x-api-key'] = apiKey;
    const req = httpRequest({ host: '127.0.0.1', port, method, path, headers }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        resolve({ status: res.statusCode, body: text ? JSON.parse(text) : null });
      });
    });
    req.on('error', reject);
    req.end(bytes);
  });
}

test('recipient acceptance route completes verified delivery and returns the signed receipt', async (t) => {
  const { handler, calls } = fixture();
  const { server, port } = await listen(handler);
  t.after(() => closeServer(server));
  const response = await requestJson(port, `/api/workforce-audit/assurance-recipient/bundles/${bundleId}/acceptance`, {
    body: { claimToken: 'claim-token-value-with-sufficient-length', packageSha256: 'd'.repeat(64) },
    recipientHeaders: { 'x-basitclaw-recipient-id': 'regulator' }
  });
  assert.equal(response.status, 200);
  assert.equal(response.body.data.bundle.acceptanceStatus, 'verified');
  assert.equal(response.body.data.acceptanceReceipt.acceptanceId, acceptanceId);
  assert.equal(calls.accept, 1);
});

test('legacy acknowledgement route is refused when verified acceptance is enforced', async (t) => {
  const { handler, calls } = fixture();
  const { server, port } = await listen(handler);
  t.after(() => closeServer(server));
  const response = await requestJson(port, `/api/workforce-audit/assurance-recipient/bundles/${bundleId}/acknowledge`, {
    body: { claimToken: 'claim-token-value-with-sufficient-length', packageSha256: 'd'.repeat(64) },
    recipientHeaders: { 'x-basitclaw-recipient-id': 'regulator' }
  });
  assert.equal(response.status, 409);
  assert.equal(response.body.code, 'EVIDENCE_ASSURANCE_ACCEPTANCE_REQUIRED');
  assert.equal(calls.acknowledge, 1);
});

test('governance users can verify acceptance receipts but unauthenticated callers cannot', async (t) => {
  const { handler, calls } = fixture();
  const { server, port } = await listen(handler);
  t.after(() => closeServer(server));
  const denied = await requestJson(port, `/api/workforce-audit/assurance-bundles/${bundleId}/acceptance/verify`);
  assert.equal(denied.status, 401);
  const verified = await requestJson(port, `/api/workforce-audit/assurance-bundles/${bundleId}/acceptance/verify`, { apiKey: 'manager-key' });
  assert.equal(verified.status, 200);
  assert.equal(verified.body.data.valid, true);
  assert.equal(calls.verify, 1);
});

test('malformed encoded bundle IDs return controlled validation responses', async (t) => {
  const { handler } = fixture();
  const { server, port } = await listen(handler);
  t.after(() => closeServer(server));
  const response = await requestJson(port, '/api/workforce-audit/assurance-bundles/%E0%A4%A/acceptance/verify', { apiKey: 'manager-key' });
  assert.equal(response.status, 400);
  assert.match(response.body.error, /invalid percent encoding/);
});
