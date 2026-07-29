import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { createFederatedApp } from '../src/federatedServer.js';
import { AuthenticationError } from '../src/security/accessControl.js';

function limiter() {
  const decisions = [];
  return {
    decisions,
    clientAddress: () => 'client-1',
    consume: (key, policy) => { decisions.push({ key, policy }); return { allowed: true, policy, limit: 8, remaining: 7, resetAt: new Date().toISOString(), retryAfterSeconds: 0 }; },
    headers: () => ({}),
    health: () => ({ status: 'ready' })
  };
}
function innerFactory({ accessController }) {
  const server = createServer((req, res) => {
    try {
      const principal = accessController.authenticate(req);
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ subject: principal.subject, authMethod: principal.authMethod }));
    } catch (error) {
      res.writeHead(401, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ code: error.code }));
    }
  });
  server.resilienceScheduler = { start() {}, stop() {} };
  server.apiSecurity = {};
  return server;
}
async function request(server, headers = {}) {
  const address = server.address();
  const response = await fetch(`http://127.0.0.1:${address.port}/api/workforce-audit/session`, { headers });
  return { status: response.status, body: await response.json() };
}

test('bridges async OIDC authentication into the synchronous inner access boundary', async () => {
  const rateLimiter = limiter();
  const gateway = {
    mode: 'hybrid',
    apiKeyController: { authenticate: () => ({ subject: 'api-user' }) },
    authenticate: async () => ({ subject: 'oidc-user', authMethod: 'oidc' }),
    authorise: (principal) => principal,
    tenantIds: () => [], credentialHealth: () => ({ status: 'ready' }), principalCount: 1
  };
  const app = createFederatedApp({
    authenticationGateway: gateway,
    rateLimiter,
    registry: {}, securityArchive: {}, securityTelemetry: { record() {} },
    innerAppFactory: innerFactory
  });
  app.listen(0, '127.0.0.1');
  await once(app, 'listening');
  try {
    const oidc = await request(app, { authorization: 'Bearer a.b.c' });
    assert.equal(oidc.status, 200);
    assert.deepEqual(oidc.body, { subject: 'oidc-user', authMethod: 'oidc' });
    assert.equal(rateLimiter.decisions.length, 0, 'successful OIDC is rate-limited only by the inner application');
    const api = await request(app, { 'x-api-key': 'value' });
    assert.deepEqual(api.body, { subject: 'api-user', authMethod: 'api_key' });
  } finally { app.close(); }
});

test('failed OIDC authentication is throttled and returns a bearer challenge', async () => {
  const rateLimiter = limiter();
  const events = [];
  const gateway = {
    mode: 'oidc', apiKeyController: null,
    authenticate: async () => { throw new AuthenticationError('bad token', { code: 'OIDC_SIGNATURE_INVALID', details: { reason: 'bad_signature' } }); },
    authorise: (principal) => principal, tenantIds: () => [], credentialHealth: () => ({ status: 'ready' }), principalCount: 0
  };
  const app = createFederatedApp({
    authenticationGateway: gateway,
    rateLimiter,
    registry: {}, securityArchive: {}, securityTelemetry: { record: (event) => events.push(event) },
    innerAppFactory: innerFactory
  });
  app.listen(0, '127.0.0.1');
  await once(app, 'listening');
  try {
    const address = app.address();
    const response = await fetch(`http://127.0.0.1:${address.port}/api/workforce-audit/session`, { headers: { authorization: 'Bearer bad' } });
    assert.equal(response.status, 401);
    assert.equal(response.headers.get('www-authenticate'), 'Bearer realm="workforce-audit"');
    assert.equal((await response.json()).code, 'OIDC_SIGNATURE_INVALID');
    assert.equal(rateLimiter.decisions[0].policy, 'authFailure');
    assert.equal(events[0].type, 'authentication.failed');
  } finally { app.close(); }
});
