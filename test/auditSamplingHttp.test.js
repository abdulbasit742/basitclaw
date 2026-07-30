import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request as httpRequest } from 'node:http';
import { AuthorizationError } from '../src/security/accessControl.js';
import { createAuditSamplingHandler } from '../src/sampling/auditSamplingHandler.js';

const planId = `SMP-${'1'.repeat(32)}`;

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
      host: '127.0.0.1', port, method, path, agent: false,
      headers: { 'x-test-role': role, connection: 'close', ...(bytes ? { 'content-type': 'application/json', 'content-length': bytes.length } : {}) }
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
function gateway() {
  return {
    mode: 'api-key',
    async authenticate(req) {
      const role = String(req.headers['x-test-role'] ?? 'manager');
      const permissions = role === 'auditor'
        ? ['audit:read', 'fieldwork:write']
        : role === 'viewer' ? ['audit:read'] : ['audit:read', 'fieldwork:write', 'engagement:write'];
      return { subject: `${role}.one`, tenantId: 'tenant-http', keyId: `${role}-key`, permissions };
    },
    authorise(principal, permission) {
      if (!principal.permissions.includes(permission)) throw new AuthorizationError(undefined, { reason: 'permission_denied', permission });
    }
  };
}
function registry() {
  return {
    createSamplingPlan(tenantId, input, context) {
      assert.equal(tenantId, 'tenant-http');
      assert.equal(input.method, 'simple_random');
      return { created: true, duplicate: false, plan: { planId, preparedBy: context.actor, status: 'draft' } };
    },
    approveSamplingPlan(tenantId, requestedPlanId, input, context) {
      assert.equal(requestedPlanId, planId);
      assert.equal(input.confirmation, `APPROVE SAMPLE ${planId}`);
      return { approved: true, duplicate: false, plan: { planId, approvedBy: context.actor, status: 'approved', selection: { selectionHash: 'a'.repeat(64), selected: [] } } };
    },
    cancelSamplingPlan() { return { cancelled: true, plan: { planId, status: 'cancelled' } }; },
    samplingPlan() { return { planId, status: 'draft' }; },
    samplingPlans() { return [{ planId, status: 'draft' }]; },
    verifySamplingPlan() { return { valid: true, planId }; },
    auditSamplingStatus() { return { status: 'ready', enabled: true }; }
  };
}

test('auditor can prepare a plan but cannot approve it', async (t) => {
  const handler = createAuditSamplingHandler({ registry: registry(), authenticationGateway: gateway() });
  const { server, port } = await listen(handler);
  t.after(() => closeServer(server));
  const created = await request(port, {
    role: 'auditor', method: 'POST', path: '/api/workforce-audit/sampling-plans',
    body: {
      engagementId: 'ENG-1', objective: 'Test payroll approval and completeness', rationale: 'Use a reproducible population sample.',
      evidenceId: `EVD-${'2'.repeat(32)}`, evidenceVersion: 1, idempotencyKey: 'sample-1', method: 'simple_random', sampleSize: 1,
      population: [{ sourceReference: 'row-1' }]
    }
  });
  assert.equal(created.status, 201);
  const denied = await request(port, {
    role: 'auditor', method: 'POST', path: `/api/workforce-audit/sampling-plans/${planId}/approve`,
    body: { confirmation: `APPROVE SAMPLE ${planId}` }
  });
  assert.equal(denied.status, 403);
});

test('manager can approve and governance viewers can read plans', async (t) => {
  const handler = createAuditSamplingHandler({ registry: registry(), authenticationGateway: gateway() });
  const { server, port } = await listen(handler);
  t.after(() => closeServer(server));
  const approved = await request(port, {
    role: 'manager', method: 'POST', path: `/api/workforce-audit/sampling-plans/${planId}/approve`,
    body: { confirmation: `APPROVE SAMPLE ${planId}` }
  });
  assert.equal(approved.status, 200);
  const viewed = await request(port, { role: 'viewer', path: `/api/workforce-audit/sampling-plans/${planId}` });
  assert.equal(viewed.status, 200);
  assert.equal(viewed.body.data.planId, planId);
});

test('unknown fields and malformed percent encoding return controlled 400 responses', async (t) => {
  const handler = createAuditSamplingHandler({ registry: registry(), authenticationGateway: gateway() });
  const { server, port } = await listen(handler);
  t.after(() => closeServer(server));
  const unknown = await request(port, {
    role: 'auditor', method: 'POST', path: '/api/workforce-audit/sampling-plans',
    body: { unexpected: true }
  });
  assert.equal(unknown.status, 400);
  const malformed = await request(port, { path: '/api/workforce-audit/sampling-plans/%E0%A4%A' });
  assert.equal(malformed.status, 400);
  assert.match(malformed.body.error, /percent-encoded/);
});
