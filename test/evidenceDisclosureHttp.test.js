import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request as httpRequest } from 'node:http';
import { AuthenticationError, AuthorizationError } from '../src/security/accessControl.js';
import { createEvidenceDisclosureHandler } from '../src/evidence/evidenceDisclosureHandler.js';

async function listen(handler) {
  const server = createServer((req, res) => handler.handle(req, res));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { server, port: server.address().port };
}

async function close(server) {
  server.closeAllConnections?.();
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

function request(port, method, path, body = null, headers = {}) {
  const bytes = body === null ? null : Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const req = httpRequest({
      host: '127.0.0.1',
      port,
      method,
      path,
      headers: {
        connection: 'close',
        ...(bytes ? {
          'content-type': 'application/json',
          'content-length': bytes.length
        } : {}),
        ...headers
      }
    }, (res) => {
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

function registry() {
  return {
    evidenceDisclosureStatus() { return { status: 'ready', enabled: true, total: 1 }; },
    evidenceDisclosures() { return [{ requestId: `DSR-${'a'.repeat(32)}`, state: 'pending' }]; },
    createEvidenceDisclosure(_tenant, input, context) {
      return {
        created: true,
        duplicate: false,
        request: {
          requestId: `DSR-${'a'.repeat(32)}`,
          state: 'pending',
          recipientId: input.recipientId,
          evidence: input.evidence,
          requestedBy: context.actor
        }
      };
    },
    approveEvidenceDisclosure(_tenant, requestId) {
      return { approved: true, packaged: true, request: { requestId, state: 'packaged', packageId: `DSP-${'b'.repeat(32)}` } };
    },
    rejectEvidenceDisclosure() { throw new Error('not expected'); },
    revokeEvidenceDisclosure() { throw new Error('not expected'); },
    evidenceDisclosurePackage(_tenant, requestId) {
      return { format: 'basitclaw-evidence-disclosure-package', packageId: `DSP-${'b'.repeat(32)}`, requestId };
    },
    evidenceDisclosureEvents() { return []; },
    evidenceDisclosure(_tenant, requestId) { return { requestId, state: 'pending' }; },
    verifyEvidenceDisclosures() { return { valid: true, checkedRequests: 1, checkedPackages: 1 }; }
  };
}

function auth({ authenticated = true, allowed = true, seen = [] } = {}) {
  return {
    mode: 'api-key',
    async authenticate() {
      if (!authenticated) throw new AuthenticationError();
      return {
        subject: 'audit.manager', tenantId: 'tenant-a', keyId: 'key-1', permissions: []
      };
    },
    authorise(principal, permission) {
      seen.push(permission);
      if (!allowed) throw new AuthorizationError();
      return principal;
    }
  };
}

test('create and approval routes request separate permissions', async (t) => {
  const seen = [];
  const handler = createEvidenceDisclosureHandler({
    registry: registry(),
    authenticationGateway: auth({ seen })
  });
  const { server, port } = await listen(handler);
  t.after(() => close(server));
  const created = await request(port, 'POST', '/api/workforce-audit/evidence-disclosures', {
    recipientId: 'regulator-one',
    evidence: [{ evidenceId: `EVD-${'c'.repeat(32)}`, version: 1 }]
  });
  assert.equal(created.status, 201);
  const requestId = created.body.data.request.requestId;
  const approved = await request(port, 'POST', `/api/workforce-audit/evidence-disclosures/${requestId}/approve`, {
    reason: 'Independent approval completed',
    confirmation: `APPROVE DISCLOSURE ${requestId}`
  });
  assert.equal(approved.status, 200);
  assert.deepEqual(seen, ['evidence:disclose', 'evidence:disclose:approve']);
});

test('authentication and authorisation failures are controlled', async (t) => {
  const unauthenticated = createEvidenceDisclosureHandler({
    registry: registry(),
    authenticationGateway: auth({ authenticated: false })
  });
  const first = await listen(unauthenticated);
  t.after(() => close(first.server));
  const deniedAuth = await request(first.port, 'GET', '/api/workforce-audit/evidence-disclosures');
  assert.equal(deniedAuth.status, 401);
  assert.equal(deniedAuth.body.code, 'UNAUTHENTICATED');

  const forbidden = createEvidenceDisclosureHandler({
    registry: registry(),
    authenticationGateway: auth({ allowed: false })
  });
  const second = await listen(forbidden);
  t.after(() => close(second.server));
  const deniedPermission = await request(second.port, 'GET', '/api/workforce-audit/evidence-disclosures');
  assert.equal(deniedPermission.status, 403);
  assert.equal(deniedPermission.body.code, 'FORBIDDEN');
});

test('malformed encoded request IDs return 400 and never reach the registry', async (t) => {
  const stub = registry();
  stub.evidenceDisclosure = () => { throw new Error('must not be called'); };
  const handler = createEvidenceDisclosureHandler({
    registry: stub,
    authenticationGateway: auth()
  });
  const { server, port } = await listen(handler);
  t.after(() => close(server));
  const response = await request(port, 'GET', '/api/workforce-audit/evidence-disclosures/%E0%A4%A');
  assert.equal(response.status, 400);
  assert.match(response.body.error, /invalid percent encoding/);
});

test('sealed package route returns only the recipient-sealed envelope', async (t) => {
  const handler = createEvidenceDisclosureHandler({
    registry: registry(),
    authenticationGateway: auth()
  });
  const { server, port } = await listen(handler);
  t.after(() => close(server));
  const requestId = `DSR-${'a'.repeat(32)}`;
  const response = await request(port, 'GET', `/api/workforce-audit/evidence-disclosures/${requestId}/package`);
  assert.equal(response.status, 200);
  assert.equal(response.body.data.format, 'basitclaw-evidence-disclosure-package');
  assert.equal('contentBase64' in response.body.data, false);
});
