import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createEvidenceRegistry } from '../src/evidence/evidenceRegistry.js';
import { createEvidenceAwareApp } from '../src/evidence/evidenceServer.js';

const principal = {
  subject: 'auditor.one',
  tenantId: 'tenant-a',
  role: 'compliance_admin',
  keyId: 'key-1',
  permissions: ['audit:read']
};

test('unexpected evidence-handler rejection returns a contained 500 response', async (t) => {
  const evidenceRegistry = createEvidenceRegistry({
    directory: mkdtempSync(join(tmpdir(), 'evidence-failure-')),
    keys: { k1: Buffer.alloc(32, 4).toString('base64') },
    primaryKeyId: 'k1'
  });
  const baseApp = createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ success: true }));
  });
  baseApp.authenticationGateway = {
    mode: 'api-key',
    authenticate: async () => principal,
    authorise: () => principal
  };
  baseApp.apiSecurity = { securityTelemetry: { record() {} } };
  baseApp.resilienceScheduler = { start() {}, stop() {} };
  const app = createEvidenceAwareApp({
    evidenceRegistry,
    auditRegistry: { forTenant: () => ({ getFindings: () => [] }) },
    rateLimiter: {
      clientAddress: () => '127.0.0.1',
      consume: (_subject, policy) => ({ allowed: true, policy, remaining: 1, limit: 1, retryAfterSeconds: 0 }),
      headers: () => ({})
    },
    baseApp,
    authenticationGateway: baseApp.authenticationGateway,
    securityTelemetry: baseApp.apiSecurity.securityTelemetry,
    evidenceHandler: {
      matches: () => true,
      handle: async () => { throw new Error('unexpected evidence failure'); }
    }
  });
  t.after(() => app.close());
  await new Promise((resolve) => app.listen(0, '127.0.0.1', resolve));
  const originalError = console.error;
  console.error = () => {};
  try {
    const response = await fetch(`http://127.0.0.1:${app.address().port}/api/workforce-audit/evidence/failure`);
    const payload = await response.json();
    assert.equal(response.status, 500);
    assert.equal(payload.code, 'INTERNAL_ERROR');
    assert.equal(payload.error, 'Internal server error.');
    assert.equal(response.headers.get('x-request-id'), payload.meta.requestId);
  } finally {
    console.error = originalError;
  }
});
