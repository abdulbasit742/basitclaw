import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { permissionsForRole } from '../src/security/accessControl.js';
import { createAuthenticationGateway } from '../src/security/authenticationGateway.js';
import { createFederatedApp } from '../src/federatedServer.js';
import {
  PrivilegedAccessStoreError,
  createPrivilegedAccessRegistry
} from '../src/security/privilegedAccessRegistry.js';

const key = Buffer.alloc(32, 13).toString('base64');
const principal = (subject) => ({
  subject,
  tenantId: 'tenant-a',
  role: 'compliance_admin',
  permissions: permissionsForRole('compliance_admin'),
  authMethod: 'oidc',
  externalSubjectHash: subject.padEnd(24, 'a').slice(0, 24),
  authenticationContext: { amr: ['mfa'], acr: 'urn:high' },
  keyId: `oidc-${subject}`
});

function limiter() {
  return {
    clientAddress: () => 'client-1',
    consume: (_key, policy) => ({ allowed: true, policy, limit: 100, remaining: 99, resetAt: new Date().toISOString(), retryAfterSeconds: 0 }),
    headers: () => ({}),
    health: () => ({ status: 'ready' })
  };
}

function innerFactory({ accessController } = {}) {
  const server = createServer((req, res) => {
    let effective = null;
    if (accessController) {
      const authenticated = accessController.authenticate(req);
      effective = accessController.authorise(authenticated, 'security:read');
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({
      success: true,
      data: {
        reachedInnerServer: true,
        privilegedRequestId: effective?.privilegedAccess?.requestId ?? null
      }
    }));
  });
  server.resilienceScheduler = { start() {}, stop() {} };
  server.apiSecurity = {};
  return server;
}

async function registry() {
  return createPrivilegedAccessRegistry({
    mode: 'enforce',
    directory: await mkdtemp(resolve(tmpdir(), 'basitclaw-pam-integration-')),
    keys: { k1: key },
    primaryKeyId: 'k1',
    requiredAmr: ['mfa'],
    requiredAcr: ['urn:high']
  });
}

test('authentication gateway blocks protected permissions until a grant is active', async () => {
  const privilegedAccess = await registry();
  const requester = principal('requester');
  const gateway = createAuthenticationGateway({
    mode: 'oidc',
    oidcAuthenticator: { authenticateToken: async () => requester, health: () => ({ status: 'ready' }) },
    entitlementRegistry: { enforce: (value) => value, tenantIds: () => [], health: () => ({ status: 'disabled', required: false }) },
    privilegedAccessRegistry: privilegedAccess
  });
  assert.throws(() => gateway.authorise(requester, 'security:read'), (error) => (
    error.code === 'FORBIDDEN'
      && error.details?.reason === 'PRIVILEGED_ACCESS_REQUIRED'
      && error.details?.permission === 'security:read'
  ));
  let request = privilegedAccess.requestAccess(requester, {
    permissions: ['security:read'], durationMinutes: 30,
    reason: 'Temporary access to investigate a high-severity security event.', ticketRef: 'SEC-101'
  });
  request = privilegedAccess.approve(request.id, principal('approver-one'), { expectedVersion: request.version, comment: 'Validated the incident and requested evidence scope.' });
  request = privilegedAccess.approve(request.id, principal('approver-two'), { expectedVersion: request.version, comment: 'Independent approval for the time-boxed investigation.' });
  assert.equal(gateway.authorise(requester, 'security:read').privilegedAccess.requestId, request.id);
});

test('tenant enumeration survives privileged-store failure while health remains degraded', () => {
  const gateway = createAuthenticationGateway({
    mode: 'api-key',
    apiKeyController: {
      authenticate: async () => principal('api-user'),
      tenantIds: () => ['tenant-api'],
      credentialHealth: () => ({ status: 'ready' }),
      principalCount: 1
    },
    entitlementRegistry: {
      enforce: (value) => value,
      tenantIds: () => ['tenant-scim'],
      health: () => ({ status: 'ready', required: false })
    },
    privilegedAccessRegistry: {
      mode: 'enforce',
      authorise: (value) => value,
      tenantIds() { throw new PrivilegedAccessStoreError(); },
      health: () => ({ status: 'unavailable', required: true })
    }
  });
  assert.deepEqual(gateway.tenantIds().sort(), ['tenant-api', 'tenant-scim']);
  assert.equal(gateway.credentialHealth().status, 'unavailable');
});

test('federated server pre-authorises protected routes and reuses the effective principal', async () => {
  const privilegedAccess = await registry();
  const requester = principal('requester');
  let authoriseCalls = 0;
  const gateway = {
    mode: 'oidc',
    apiKeyController: null,
    authenticate: async () => requester,
    authorise: (value, permission) => {
      authoriseCalls += 1;
      if (!value.permissions.includes(permission)) throw new Error('permission missing');
      return privilegedAccess.authorise(value, permission);
    },
    tenantIds: () => ['tenant-a'],
    credentialHealth: () => ({ status: 'ready' }),
    principalCount: 0
  };
  const events = [];
  const app = createFederatedApp({
    privilegedAccess,
    authenticationGateway: gateway,
    rateLimiter: limiter(),
    registry: {},
    securityArchive: {},
    securityTelemetry: { record: (event) => events.push(event) },
    innerAppFactory: innerFactory
  });
  app.listen(0, '127.0.0.1');
  await once(app, 'listening');
  try {
    const origin = `http://127.0.0.1:${app.address().port}`;
    const denied = await fetch(`${origin}/api/workforce-audit/security-status`, { headers: { authorization: 'Bearer token' } });
    assert.equal(denied.status, 403);
    assert.equal((await denied.json()).code, 'PRIVILEGED_ACCESS_REQUIRED');

    const invalid = await fetch(`${origin}/api/workforce-audit/privileged-access/requests`, {
      method: 'POST',
      headers: { authorization: 'Bearer token', 'content-type': 'application/json' },
      body: JSON.stringify({ permissions: ['security:read'], durationMinutes: 'invalid' })
    });
    assert.equal(invalid.status, 400);
    assert.equal((await invalid.json()).code, 'PRIVILEGED_ACCESS_INPUT_INVALID');

    const invalidFilter = await fetch(`${origin}/api/workforce-audit/privileged-access/requests?subject=x`, {
      headers: { authorization: 'Bearer token' }
    });
    assert.equal(invalidFilter.status, 400);
    assert.equal((await invalidFilter.json()).code, 'PRIVILEGED_ACCESS_INPUT_INVALID');

    const created = await fetch(`${origin}/api/workforce-audit/privileged-access/requests`, {
      method: 'POST',
      headers: { authorization: 'Bearer token', 'content-type': 'application/json' },
      body: JSON.stringify({
        permissions: ['security:read'], durationMinutes: 30,
        reason: 'Temporary access to investigate a high-severity security event.', ticketRef: 'SEC-102'
      })
    });
    assert.equal(created.status, 201);
    const request = (await created.json()).data;
    let approved = privilegedAccess.approve(request.id, principal('approver-one'), { expectedVersion: request.version, comment: 'Validated the incident and requested evidence scope.' });
    approved = privilegedAccess.approve(request.id, principal('approver-two'), { expectedVersion: approved.version, comment: 'Independent approval for the time-boxed investigation.' });

    authoriseCalls = 0;
    const allowed = await fetch(`${origin}/api/workforce-audit/security-status`, { headers: { authorization: 'Bearer token' } });
    assert.equal(allowed.status, 200);
    const payload = await allowed.json();
    assert.equal(payload.data.reachedInnerServer, true);
    assert.equal(payload.data.privilegedRequestId, request.id);
    assert.equal(authoriseCalls, 1);
    assert.ok(events.some((event) => event.type === 'privileged_access.requested'));
  } finally {
    app.close();
  }
});

test('api security exposes live privileged health instead of a startup snapshot', () => {
  let state = 'ready';
  const privilegedAccess = {
    mode: 'disabled',
    authorise: (value) => value,
    tenantIds: () => [],
    health: () => ({ status: state, required: false })
  };
  const gateway = {
    mode: 'api-key', apiKeyController: { authenticate: async () => principal('user') },
    authenticate: async () => principal('user'), authorise: (value) => value,
    tenantIds: () => [], credentialHealth: () => ({ status: 'ready' }), principalCount: 1
  };
  const handler = {
    matches: () => false,
    handle: async () => undefined,
    health: () => ({ status: state })
  };
  const app = createFederatedApp({
    privilegedAccess,
    privilegedAccessHandler: handler,
    authenticationGateway: gateway,
    rateLimiter: limiter(),
    registry: {},
    securityArchive: {},
    securityTelemetry: { record() {} },
    innerAppFactory: () => innerFactory()
  });
  assert.equal(app.apiSecurity.privilegedAccess.status, 'ready');
  state = 'unavailable';
  assert.equal(app.apiSecurity.privilegedAccess.status, 'unavailable');
  app.close();
});
