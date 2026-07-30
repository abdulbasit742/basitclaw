import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request as httpRequest } from 'node:http';
import { AuthenticationError, AuthorizationError } from '../src/security/accessControl.js';
import { createRegulatoryCaseHandler } from '../src/regulatory/regulatoryCaseHandler.js';

async function listen(handler) { const server = createServer((req, res) => handler.handle(req, res)); await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve)); return { server, port: server.address().port }; }
async function close(server) { server.closeAllConnections?.(); await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())); }
function request(port, method, path, body = null) { const bytes = body === null ? null : Buffer.from(JSON.stringify(body)); return new Promise((resolve, reject) => { const req = httpRequest({ host: '127.0.0.1', port, method, path, headers: { connection: 'close', ...(bytes ? { 'content-type': 'application/json', 'content-length': bytes.length } : {}) } }, (res) => { const chunks = []; res.on('data', (chunk) => chunks.push(chunk)); res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) })); }); req.on('error', reject); req.end(bytes); }); }

function store() {
  const caseId = `RGC-${'a'.repeat(32)}`;
  return {
    tenantStatus() { return { status: 'ready', total: 1 }; },
    verifyTenant() { return { valid: true, checkedCases: 1, checkedEvents: 2 }; },
    list() { return [{ caseId, state: 'open' }]; },
    createCase(_tenant, input, context) { return { created: true, duplicate: false, case: { caseId, state: 'open', authority: input.authority, dueAt: input.dueAt, evidence: input.evidence, createdBy: context.actor } }; },
    addEvidence() { return { caseId, state: 'open', deadlineState: 'on_track' }; },
    submitResponse() { return { caseId, state: 'response_pending', deadlineState: 'on_track' }; },
    approveResponse() { return { caseId, state: 'response_approved', deadlineState: 'on_track' }; },
    closeCase() { return { caseId, state: 'closed', deadlineState: 'complete' }; },
    cancelCase() { return { caseId, state: 'cancelled', deadlineState: 'complete' }; },
    events() { return []; },
    get() { return { caseId, state: 'open' }; }
  };
}

function auth({ authenticated = true, allowed = true, seen = [] } = {}) {
  return { mode: 'api-key', async authenticate() { if (!authenticated) throw new AuthenticationError(); return { subject: 'audit.manager', tenantId: 'tenant-a', keyId: 'key-1' }; }, authorise(principal, permission) { seen.push(permission); if (!allowed) throw new AuthorizationError(); return principal; } };
}

test('case creation and approval routes request separate permissions', async (t) => {
  const seen = [];
  const handler = createRegulatoryCaseHandler({ store: store(), authenticationGateway: auth({ seen }) });
  const { server, port } = await listen(handler); t.after(() => close(server));
  const created = await request(port, 'POST', '/api/workforce-audit/regulatory-cases', { authority: 'Regulator', dueAt: '2026-08-01T00:00:00.000Z', evidence: [] });
  assert.equal(created.status, 201);
  const caseId = created.body.data.case.caseId;
  const approved = await request(port, 'POST', `/api/workforce-audit/regulatory-cases/${caseId}/approve-response`, { reason: 'Independent approval completed', confirmation: `APPROVE RESPONSE ${caseId}` });
  assert.equal(approved.status, 200);
  assert.deepEqual(seen, ['regulatory:case', 'regulatory:case:approve']);
});

test('authentication, authorisation and malformed paths fail cleanly', async (t) => {
  const first = await listen(createRegulatoryCaseHandler({ store: store(), authenticationGateway: auth({ authenticated: false }) })); t.after(() => close(first.server));
  assert.equal((await request(first.port, 'GET', '/api/workforce-audit/regulatory-cases')).status, 401);
  const second = await listen(createRegulatoryCaseHandler({ store: store(), authenticationGateway: auth({ allowed: false }) })); t.after(() => close(second.server));
  assert.equal((await request(second.port, 'GET', '/api/workforce-audit/regulatory-cases')).status, 403);
  const third = await listen(createRegulatoryCaseHandler({ store: store(), authenticationGateway: auth() })); t.after(() => close(third.server));
  const malformed = await request(third.port, 'GET', '/api/workforce-audit/regulatory-cases/%E0%A4%A');
  assert.equal(malformed.status, 400);
  assert.match(malformed.body.error, /invalid percent encoding/);
});
