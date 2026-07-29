import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createEvidenceRegistry } from '../src/evidence/evidenceRegistry.js';
import { createEvidenceAwareApp } from '../src/evidence/evidenceServer.js';
import { createEvidenceScreeningEngine } from '../src/evidence/evidenceScreeningEngine.js';
import { createScreenedEvidenceRegistry } from '../src/evidence/evidenceScreeningRegistry.js';

const key = Buffer.alloc(32, 13).toString('base64');
const principal = Object.freeze({
  subject: 'auditor.one', tenantId: 'tenant-a', role: 'compliance_admin', keyId: 'key-1',
  permissions: ['audit:read', 'finding:write', 'governance:read', 'backup:restore']
});

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), 'screening-http-'));
  const baseRegistry = createEvidenceRegistry({ directory, keys: { k1: key }, primaryKeyId: 'k1' });
  const evidenceRegistry = createScreenedEvidenceRegistry({
    registry: baseRegistry,
    engine: createEvidenceScreeningEngine({ mode: 'enforce' }),
    keys: { k1: key },
    primaryKeyId: 'k1',
    eventRetention: 100
  });
  const findings = [];
  const auditRegistry = { forTenant: () => ({ getFindings: () => structuredClone(findings) }) };
  const gateway = {
    mode: 'api-key',
    authenticate: async () => principal,
    authorise: (candidate, permission) => {
      if (!candidate.permissions.includes(permission)) { const error = new Error('forbidden'); error.code = 'FORBIDDEN'; throw error; }
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
      findings.push({ id: 'FND-1', evidenceRefs: body.evidenceRefs });
      res.writeHead(201, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ success: true, data: findings.at(-1) }));
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ success: true, data: { status: 'ok' } }));
  });
  base.authenticationGateway = gateway;
  base.apiSecurity = { securityTelemetry: { record() {} } };
  base.resilienceScheduler = { start() {}, stop() {} };
  const app = createEvidenceAwareApp({
    evidenceRegistry, auditRegistry, rateLimiter: limiter, baseApp: base,
    authenticationGateway: gateway, securityTelemetry: base.apiSecurity.securityTelemetry
  });
  return { app };
}

async function listen(app) {
  await new Promise((resolve) => app.listen(0, '127.0.0.1', resolve));
  return `http://127.0.0.1:${app.address().port}`;
}

async function payload(response) { return response.json(); }

test('quarantined upload blocks download and finding linkage until governed release', async (t) => {
  const { app } = fixture();
  t.after(() => app.close());
  const base = await listen(app);
  const secret = '-----BEGIN PRIVATE KEY-----\nnever-return-this\n-----END PRIVATE KEY-----';
  const upload = await fetch(`${base}/api/workforce-audit/evidence`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-key': 'test' },
    body: JSON.stringify({ filename: 'secret.txt', mediaType: 'text/plain', contentBase64: Buffer.from(secret).toString('base64') })
  });
  assert.equal(upload.status, 201);
  const item = (await payload(upload)).data;
  assert.equal(item.status, 'quarantine');

  const content = await fetch(`${base}/api/workforce-audit/evidence/${item.evidenceId}/content`, { headers: { 'x-api-key': 'test' } });
  assert.equal(content.status, 423);
  assert.equal((await payload(content)).code, 'EVIDENCE_QUARANTINED');

  const finding = await fetch(`${base}/api/workforce-audit/findings`, {
    method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': 'test' },
    body: JSON.stringify({ evidenceRefs: [item.evidenceId] })
  });
  assert.equal(finding.status, 423);

  const reportResponse = await fetch(`${base}/api/workforce-audit/evidence/${item.evidenceId}/screening`, { headers: { 'x-api-key': 'test' } });
  assert.equal(reportResponse.status, 200);
  const reportText = await reportResponse.text();
  assert.equal(reportText.includes('never-return-this'), false);
  assert.ok(JSON.parse(reportText).data.findings.some((entry) => entry.ruleId === 'DLP_PRIVATE_KEY_MATERIAL'));

  const release = await fetch(`${base}/api/workforce-audit/evidence/${item.evidenceId}/screening/release`, {
    method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': 'test' },
    body: JSON.stringify({
      confirmation: `RELEASE QUARANTINE ${item.evidenceId}`,
      reason: 'Independent review confirmed synthetic non-production test material'
    })
  });
  assert.equal(release.status, 200);
  assert.equal((await payload(release)).data.status, 'active');

  const releasedContent = await fetch(`${base}/api/workforce-audit/evidence/${item.evidenceId}/content`, { headers: { 'x-api-key': 'test' } });
  assert.equal(releasedContent.status, 200);
  assert.equal(await releasedContent.text(), secret);
});

test('screening event route is read-only', async (t) => {
  const { app } = fixture();
  t.after(() => app.close());
  const base = await listen(app);
  const upload = await fetch(`${base}/api/workforce-audit/evidence`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ filename: 'a.txt', mediaType: 'text/plain', contentBase64: Buffer.from('clean').toString('base64') })
  });
  const item = (await payload(upload)).data;
  const response = await fetch(`${base}/api/workforce-audit/evidence/${item.evidenceId}/screening/events`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}'
  });
  assert.equal(response.status, 404);
  assert.equal((await payload(response)).code, 'NOT_FOUND');
});
