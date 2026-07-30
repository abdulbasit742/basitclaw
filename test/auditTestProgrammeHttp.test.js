import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request as httpRequest } from 'node:http';
import { AuthorizationError } from '../src/security/accessControl.js';
import { createAuditTestProgrammeHandler } from '../src/auditTestProgrammeHandler.js';
import { createWorkforceAuditService } from '../src/services/workforceAuditService.js';

const now = () => new Date('2026-07-30T01:00:00.000Z');

function authenticationGateway() {
  return {
    mode: 'api-key',
    async authenticate(req) {
      return {
        subject: String(req.headers['x-subject'] ?? 'auditor.preparer'),
        tenantId: 'tenant-a',
        keyId: 'test-key',
        permissions: String(req.headers['x-permissions'] ?? 'audit:read,fieldwork:write').split(',')
      };
    },
    authorise(principal, permission) {
      if (!principal.permissions.includes(permission)) throw new AuthorizationError('Denied.', { permission });
    }
  };
}

async function listen(handler) {
  const server = createServer((req, res) => handler.handle(req, res));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { server, port: server.address().port };
}

function request(port, method, path, { body = null, subject = 'auditor.preparer', permissions = 'audit:read,fieldwork:write' } = {}) {
  return new Promise((resolve, reject) => {
    const bytes = body === null ? null : Buffer.from(JSON.stringify(body));
    const req = httpRequest({
      host: '127.0.0.1', port, method, path,
      headers: {
        connection: 'close',
        'x-subject': subject,
        'x-permissions': permissions,
        ...(bytes ? { 'content-type': 'application/json', 'content-length': bytes.length } : {})
      }
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) }));
    });
    req.on('error', reject);
    req.end(bytes);
  });
}

function createBody() {
  return {
    objective: 'Determine whether the payroll approval control operated for the selected population.',
    controlId: 'PAY-CTRL-07',
    assertions: ['authorisation'],
    population: [{ recordId: 'PAY-0001', stratum: 'staff', riskScore: 10 }],
    samplingMethod: 'random',
    sampleSize: 1,
    confidenceLevel: 0.95,
    tolerableDeviationRate: 1,
    expectedDeviationRate: 0,
    reviewer: 'manager.reviewer',
    testSteps: [{ stepId: 'AUTH-01', title: 'Inspect approval', procedure: 'Inspect the approved request and compare it with the processed payroll change.' }]
  };
}

test('HTTP lifecycle enforces manager review and returns reproducible integrity', async (t) => {
  const service = createWorkforceAuditService({ now, tenantId: 'tenant-a' });
  const registry = { forTenant(tenantId) { assert.equal(tenantId, 'tenant-a'); return service; } };
  const handler = createAuditTestProgrammeHandler({ registry, authenticationGateway: authenticationGateway() });
  const { server, port } = await listen(handler);
  t.after(async () => new Promise((resolve) => server.close(resolve)));

  const created = await request(port, 'POST', '/api/workforce-audit/engagements/ENG-2026-004/test-programmes', { body: createBody() });
  assert.equal(created.status, 201);
  const programme = created.body.data;
  const sampleId = programme.samples[0].sampleId;

  const result = await request(port, 'POST', `/api/workforce-audit/test-programmes/${programme.id}/samples/${sampleId}/results`, {
    body: { stepResults: [{ stepId: 'AUTH-01', outcome: 'pass', evidenceRefs: [`EVD-${'a'.repeat(32)}`], notes: 'The approval matched the processed change.' }] },
    subject: 'auditor.tester'
  });
  assert.equal(result.status, 201);

  const submitted = await request(port, 'POST', `/api/workforce-audit/test-programmes/${programme.id}/submit`, {
    body: { rationale: 'The selected item was tested and the evidence package is complete.', exceptionsEscalated: false }
  });
  assert.equal(submitted.status, 200);

  const denied = await request(port, 'POST', `/api/workforce-audit/test-programmes/${programme.id}/review`, {
    body: { conclusion: 'effective', rationale: 'Independent review confirms the programme and evidence.', confirmation: `FINALISE ${programme.id} EFFECTIVE` },
    subject: 'auditor.preparer',
    permissions: 'engagement:write'
  });
  assert.equal(denied.status, 400);

  const reviewed = await request(port, 'POST', `/api/workforce-audit/test-programmes/${programme.id}/review`, {
    body: { conclusion: 'effective', rationale: 'Independent review confirms the approved population, execution and conclusion.', confirmation: `FINALISE ${programme.id} EFFECTIVE` },
    subject: 'manager.reviewer',
    permissions: 'engagement:write'
  });
  assert.equal(reviewed.status, 200);
  assert.equal(reviewed.body.data.review.conclusion, 'effective');

  const verified = await request(port, 'GET', `/api/workforce-audit/test-programmes/${programme.id}/verify`, {
    subject: 'manager.reviewer', permissions: 'governance:read'
  });
  assert.equal(verified.status, 200);
  assert.equal(verified.body.data.valid, true);
});

test('review route requires manager permission', async (t) => {
  const service = createWorkforceAuditService({ now, tenantId: 'tenant-a' });
  const handler = createAuditTestProgrammeHandler({ registry: { forTenant: () => service }, authenticationGateway: authenticationGateway() });
  const { server, port } = await listen(handler);
  t.after(async () => new Promise((resolve) => server.close(resolve)));
  const response = await request(port, 'POST', '/api/workforce-audit/test-programmes/TPG-2026-0001/review', {
    body: {}, permissions: 'fieldwork:write'
  });
  assert.equal(response.status, 403);
});

test('malformed encoded programme IDs return controlled validation responses', async (t) => {
  const service = createWorkforceAuditService({ now, tenantId: 'tenant-a' });
  const handler = createAuditTestProgrammeHandler({ registry: { forTenant: () => service }, authenticationGateway: authenticationGateway() });
  const { server, port } = await listen(handler);
  t.after(async () => new Promise((resolve) => server.close(resolve)));
  const response = await request(port, 'GET', '/api/workforce-audit/test-programmes/%E0%A4%A', { permissions: 'audit:read' });
  assert.equal(response.status, 400);
  assert.match(response.body.error, /invalid percent encoding/);
});
