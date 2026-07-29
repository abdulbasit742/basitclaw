import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createEvidenceRegistry } from '../src/evidence/evidenceRegistry.js';
import { createEvidenceAwareApp } from '../src/evidence/evidenceServer.js';

const key = Buffer.alloc(32, 9).toString('base64');
const principal = Object.freeze({
  subject: 'auditor.one', tenantId: 'tenant-a', role: 'compliance_admin', keyId: 'key-1',
  permissions: ['audit:read', 'finding:write', 'governance:read', 'backup:restore']
});
function fixture({ delayedFinding = false } = {}) {
  let current = new Date('2026-07-30T00:00:00.000Z');
  let signalFindingStarted;
  const findingStarted = new Promise((resolve) => { signalFindingStarted = resolve; });
  const evidenceRegistry = createEvidenceRegistry({
    directory: mkdtempSync(join(tmpdir(), 'evidence-http-')),
    keys: { k1: key },
    primaryKeyId: 'k1',
    now: () => new Date(current)
  });
  const auditState = { findings: [] };
  const auditRegistry = { forTenant: () => ({ getFindings: () => structuredClone(auditState.findings) }) };
  const gateway = {
    mode: 'api-key',
    authenticate: async () => principal,
    authorise: (candidate, permission) => {
      if (!candidate.permissions.includes(permission)) {
        const error = new Error('forbidden'); error.code = 'FORBIDDEN'; throw error;
      }
      return candidate;
    }
  };
  const limiter = {
    clientAddress: () => '127.0.0.1',
    consume: (_subject, policy) => ({ allowed: true, policy, remaining: 10, limit: 10, retryAfterSeconds: 0 }),
    headers: () => ({})
  };
  const base = createServer(async (req, res) => {
    if (req.method === 'POST' && req.url === '/api/workforce-audit/findings') {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const body = JSON.parse(Buffer.concat(chunks));
      signalFindingStarted();
      if (delayedFinding) await new Promise((resolve) => setTimeout(resolve, 150));
      auditState.findings.push({ id: 'FND-1', evidenceRefs: body.evidenceRefs });
      res.writeHead(201, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ success: true, data: auditState.findings.at(-1) }));
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ success: true, data: { status: 'ok' } }));
  });
  base.authenticationGateway = gateway;
  base.apiSecurity = { securityTelemetry: { record() {} } };
  base.resilienceScheduler = { start() {}, stop() {} };
  const app = createEvidenceAwareApp({
    evidenceRegistry,
    auditRegistry,
    rateLimiter: limiter,
    baseApp: base,
    authenticationGateway: gateway,
    securityTelemetry: base.apiSecurity.securityTelemetry
  });
  return { app, evidenceRegistry, auditState, findingStarted, setNow: (value) => { current = new Date(value); } };
}
async function listen(app) {
  await new Promise((resolve) => app.listen(0, '127.0.0.1', resolve));
  return `http://127.0.0.1:${app.address().port}`;
}
async function json(response) { return response.json(); }
async function uploadEvidence(base, overrides = {}) {
  const response = await fetch(`${base}/api/workforce-audit/evidence`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-key': 'test' },
    body: JSON.stringify({
      filename: 'sample.txt', mediaType: 'text/plain',
      contentBase64: Buffer.from('sample').toString('base64'), ...overrides
    })
  });
  assert.equal(response.status, 201);
  return (await json(response)).data;
}

test('uploads evidence, forwards registered finding references, and blocks arbitrary references', async (t) => {
  const { app } = fixture();
  t.after(() => app.close());
  const base = await listen(app);
  const item = await uploadEvidence(base);
  const finding = await fetch(`${base}/api/workforce-audit/findings`, {
    method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': 'test' },
    body: JSON.stringify({ evidenceRefs: [item.evidenceId] })
  });
  assert.equal(finding.status, 201);
  const invalid = await fetch(`${base}/api/workforce-audit/findings`, {
    method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': 'test' },
    body: JSON.stringify({ evidenceRefs: ['drive://uncontrolled-file'] })
  });
  assert.equal(invalid.status, 400);
  assert.equal((await json(invalid)).code, 'EVIDENCE_VALIDATION_FAILED');
});

test('serves verified bytes and refuses disposal while referenced', async (t) => {
  const { app } = fixture();
  t.after(() => app.close());
  const base = await listen(app);
  const item = await uploadEvidence(base, { retentionUntil: '2026-07-31T00:00:00.000Z' });
  const content = await fetch(`${base}/api/workforce-audit/evidence/${item.evidenceId}/content`);
  assert.equal(await content.text(), 'sample');
  assert.equal(content.headers.get('x-evidence-sha256').length, 64);
  await fetch(`${base}/api/workforce-audit/findings`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ evidenceRefs: [item.evidenceId] })
  });
  const dispose = await fetch(`${base}/api/workforce-audit/evidence/${item.evidenceId}/dispose`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ confirmation: `DISPOSE ${item.evidenceId}`, reason: 'Approved retention disposition after review' })
  });
  assert.equal(dispose.status, 409);
  assert.equal((await json(dispose)).code, 'EVIDENCE_CONFLICT');
});

test('event history rejects unsupported POST without mutating evidence', async (t) => {
  const { app } = fixture();
  t.after(() => app.close());
  const base = await listen(app);
  const item = await uploadEvidence(base);
  const response = await fetch(`${base}/api/workforce-audit/evidence/${item.evidenceId}/events`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}'
  });
  assert.equal(response.status, 404);
  assert.equal((await json(response)).code, 'NOT_FOUND');
  assert.equal((await fetch(`${base}/api/workforce-audit/evidence/${item.evidenceId}`)).status, 200);
});

test('finding reference guard closes the disposition race', async (t) => {
  const { app, findingStarted, setNow } = fixture({ delayedFinding: true });
  t.after(() => app.close());
  const base = await listen(app);
  const item = await uploadEvidence(base, { retentionUntil: '2026-07-31T00:00:00.000Z' });
  setNow('2026-08-02T00:00:00.000Z');
  const findingPromise = fetch(`${base}/api/workforce-audit/findings`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ evidenceRefs: [item.evidenceId] })
  });
  await findingStarted;
  const firstDispose = await fetch(`${base}/api/workforce-audit/evidence/${item.evidenceId}/dispose`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ confirmation: `DISPOSE ${item.evidenceId}`, reason: 'Approved retention disposition after review' })
  });
  assert.equal(firstDispose.status, 423);
  assert.equal((await json(firstDispose)).code, 'EVIDENCE_STORE_BUSY');
  assert.equal((await findingPromise).status, 201);
  const retry = await fetch(`${base}/api/workforce-audit/evidence/${item.evidenceId}/dispose`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ confirmation: `DISPOSE ${item.evidenceId}`, reason: 'Approved retention disposition after review' })
  });
  assert.equal(retry.status, 409);
  assert.equal((await json(retry)).code, 'EVIDENCE_CONFLICT');
});
