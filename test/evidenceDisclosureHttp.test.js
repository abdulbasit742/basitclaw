import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request as httpRequest } from 'node:http';
import { AuthenticationError, AuthorizationError } from '../src/security/accessControl.js';
import { createEvidenceDisclosureHandler } from '../src/evidence/evidenceDisclosureHandler.js';

const tenantId = 'tenant-disclosure-http';
const evidenceId = `EVD-${'b'.repeat(32)}`;
const disclosureId = `DSC-${'c'.repeat(32)}`;

function fixture() {
  const records = new Map();
  const registry = {
    health() { return { disclosures: { status: 'ready', enabled: true, approvalQuorum: 2 } }; },
    get(_tenant, requestedEvidenceId) {
      assert.equal(_tenant, tenantId);
      assert.equal(requestedEvidenceId, evidenceId);
      return { evidenceId };
    },
    requestEvidenceDisclosure(_tenant, requestedEvidenceId, input, context) {
      assert.equal(_tenant, tenantId);
      assert.equal(requestedEvidenceId, evidenceId);
      const row = {
        disclosureId,
        evidenceId,
        evidenceVersion: input.version ?? 1,
        recipientId: input.recipientId,
        residencyZone: input.residencyZone,
        state: 'requested',
        approvals: [],
        requestedBy: context.actor
      };
      records.set(disclosureId, row);
      return row;
    },
    approveEvidenceDisclosure(_tenant, requestedDisclosureId, context) {
      assert.equal(_tenant, tenantId);
      assert.equal(requestedDisclosureId, disclosureId);
      const row = records.get(disclosureId);
      row.approvals.push({ actor: context.actor });
      row.state = row.approvals.length >= 2 ? 'sealed' : 'requested';
      return { ...row };
    },
    revokeEvidenceDisclosure(_tenant, requestedDisclosureId) {
      const row = records.get(requestedDisclosureId);
      row.state = 'revoked';
      return { ...row };
    },
    evidenceDisclosure(_tenant, requestedDisclosureId) { return { ...records.get(requestedDisclosureId) }; },
    evidenceDisclosures() { return [...records.values()].map((row) => ({ ...row })); },
    evidenceDisclosureReport() { return { total: records.size, byState: { requested: records.size }, byRecipient: {}, byResidencyZone: {}, approvalQuorum: 2 }; },
    claimEvidenceDisclosures() {
      return { recipientId: 'regulator-one', tenantId, jobs: [{ disclosureId, claimToken: 'claim-token-value', package: { ciphertext: 'sealed' } }] };
    },
    acknowledgeEvidenceDisclosure(requestedDisclosureId) {
      return { disclosureId: requestedDisclosureId, recipientId: 'regulator-one', state: 'acknowledged' };
    }
  };
  const authenticationGateway = {
    mode: 'api-key',
    async authenticate(req) {
      const key = req.headers['x-api-key'];
      if (!key) throw new AuthenticationError();
      const role = key === 'admin-key' ? 'compliance_admin' : 'audit_manager';
      return {
        subject: key === 'manager-two-key' ? 'manager.two' : key === 'admin-key' ? 'admin.one' : 'manager.one',
        tenantId,
        keyId: String(key),
        role,
        permissions: ['governance:read', 'evidence:disclose:request', 'evidence:disclose:approve', 'evidence:disclose:revoke']
      };
    },
    authorise(principal, permission) {
      if (!principal.permissions.includes(permission)) throw new AuthorizationError();
    }
  };
  return { handler: createEvidenceDisclosureHandler({ registry, authenticationGateway }), records };
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

test('governance request and approval flow requires distinct authenticated principals', async (t) => {
  const { handler } = fixture();
  const { server, port } = await listen(handler);
  t.after(() => closeServer(server));

  const request = await requestJson(port, `/api/workforce-audit/evidence/${evidenceId}/disclosures`, {
    method: 'POST',
    apiKey: 'manager-one-key',
    body: {
      version: 1,
      recipientId: 'regulator-one',
      residencyZone: 'pk-primary',
      purpose: 'Authorised regulatory evidence disclosure'
    }
  });
  assert.equal(request.status, 202);
  assert.equal(request.body.data.state, 'requested');

  const first = await requestJson(port, `/api/workforce-audit/evidence-disclosures/${disclosureId}/approve`, {
    method: 'POST',
    apiKey: 'manager-two-key',
    body: { confirmation: `APPROVE DISCLOSURE ${disclosureId}` }
  });
  assert.equal(first.status, 200);
  assert.equal(first.body.data.approvals.length, 1);

  const second = await requestJson(port, `/api/workforce-audit/evidence-disclosures/${disclosureId}/approve`, {
    method: 'POST',
    apiKey: 'admin-key',
    body: { confirmation: `APPROVE DISCLOSURE ${disclosureId}` }
  });
  assert.equal(second.status, 200);
  assert.equal(second.body.data.state, 'sealed');
});

test('recipient pull and acknowledgement flow stays outside workforce authentication', async (t) => {
  const { handler } = fixture();
  const { server, port } = await listen(handler);
  t.after(() => closeServer(server));

  const claim = await requestJson(port, '/api/workforce-audit/evidence-disclosure-recipient/claim', {
    method: 'POST',
    body: { tenantId, limit: 1 }
  });
  assert.equal(claim.status, 200);
  assert.equal(claim.body.data.jobs[0].package.ciphertext, 'sealed');

  const acknowledged = await requestJson(port, `/api/workforce-audit/evidence-disclosure-recipient/${disclosureId}/acknowledge`, {
    method: 'POST',
    body: { tenantId, claimToken: 'claim-token-value' }
  });
  assert.equal(acknowledged.status, 200);
  assert.equal(acknowledged.body.data.state, 'acknowledged');
});

test('governance routes require authentication', async (t) => {
  const { handler } = fixture();
  const { server, port } = await listen(handler);
  t.after(() => closeServer(server));
  const response = await requestJson(port, '/api/workforce-audit/evidence-disclosures/report');
  assert.equal(response.status, 401);
  assert.match(response.headers['www-authenticate'], /realm="workforce-audit"/);
});

test('malformed encoded disclosure IDs return controlled 400 errors', async (t) => {
  const { handler } = fixture();
  const { server, port } = await listen(handler);
  t.after(() => closeServer(server));
  const response = await requestJson(port, '/api/workforce-audit/evidence-disclosures/%E0%A4%A', {
    apiKey: 'admin-key'
  });
  assert.equal(response.status, 400);
  assert.match(response.body.error, /invalid percent encoding/);
});
