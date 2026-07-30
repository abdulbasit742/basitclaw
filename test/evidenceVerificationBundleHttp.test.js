import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request as httpRequest } from 'node:http';
import { createEvidenceVerificationBundleHandler } from '../src/evidence/evidenceVerificationBundleHandler.js';

const evidenceId = `EVD-${'a'.repeat(32)}`;
const bundleId = `EVB-${'b'.repeat(32)}`;

function fixture({ permissions = ['governance:read', 'evidence:preserve'] } = {}) {
  const calls = [];
  const service = {
    health() {
      return { status: 'ready', enabled: true, mode: 'signed-stateless-portable-verification-bundles', rawEvidenceContentIncluded: false };
    },
    create(tenantId, id, input, context) {
      calls.push({ tenantId, id, input, context });
      return {
        created: true,
        summary: {
          bundleId,
          evidenceId: id,
          evidenceVersion: 1,
          archiveId: `ARC-${'c'.repeat(32)}`,
          profile: input.profile,
          recipientRef: input.recipientRef,
          generatedAt: '2026-07-30T01:00:00.000Z',
          expiresAt: '2026-08-29T01:00:00.000Z'
        },
        bundle: { format: 'basitclaw-portable-evidence-verification-bundle', bundleId }
      };
    },
    verify(bundle) {
      calls.push({ verify: bundle });
      return { valid: true, bundleId: bundle.bundleId, evidenceId };
    }
  };
  const authenticationGateway = {
    mode: 'api-key',
    async authenticate() {
      return { subject: 'manager.one', tenantId: 'tenant-a', keyId: 'key-1', permissions };
    },
    authorise(principal, permission) {
      if (!principal.permissions.includes(permission)) {
        const error = new Error('forbidden');
        error.name = 'AuthorizationError';
        error.code = 'FORBIDDEN';
        error.details = { reason: 'permission_denied' };
        throw error;
      }
    }
  };
  const handler = createEvidenceVerificationBundleHandler({ service, authenticationGateway });
  return { handler, calls };
}

async function listen(handler) {
  const server = createServer((req, res) => handler.handle(req, res));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { server, port: server.address().port };
}

async function close(server) {
  server.closeAllConnections?.();
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

function request(port, { method = 'GET', path = '/', body = null } = {}) {
  const bytes = body === null ? null : Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const req = httpRequest({
      host: '127.0.0.1', port, method, path,
      headers: bytes ? { 'content-type': 'application/json', 'content-length': bytes.length } : {}
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: JSON.parse(Buffer.concat(chunks).toString('utf8'))
      }));
    });
    req.on('error', reject);
    req.setHeader('connection', 'close');
    req.end(bytes);
  });
}

test('status reports stateless no-content posture', async (t) => {
  const { handler } = fixture();
  const { server, port } = await listen(handler);
  t.after(() => close(server));
  const response = await request(port, { path: '/api/workforce-audit/evidence-verification-bundles/status' });
  assert.equal(response.status, 200);
  assert.equal(response.body.data.rawEvidenceContentIncluded, false);
});

test('governed export returns a signed JSON attachment', async (t) => {
  const { handler, calls } = fixture();
  const { server, port } = await listen(handler);
  t.after(() => close(server));
  const response = await request(port, {
    method: 'POST',
    path: `/api/workforce-audit/evidence/${evidenceId}/verification-bundles`,
    body: {
      version: 1,
      profile: 'audit',
      recipientRef: 'external-auditor',
      purpose: 'Independent assurance evidence review',
      confirmation: `EXPORT PROOF ${evidenceId} V1`
    }
  });
  assert.equal(response.status, 201);
  assert.match(response.headers['content-disposition'], new RegExp(bundleId));
  assert.equal(response.body.data.bundle.bundleId, bundleId);
  assert.equal(calls[0].tenantId, 'tenant-a');
  assert.equal(calls[0].context.actor, 'manager.one');
});

test('authenticated verification endpoint validates supplied bundle', async (t) => {
  const { handler } = fixture();
  const { server, port } = await listen(handler);
  t.after(() => close(server));
  const response = await request(port, {
    method: 'POST',
    path: '/api/workforce-audit/evidence-verification-bundles/verify',
    body: { bundle: { bundleId } }
  });
  assert.equal(response.status, 200);
  assert.equal(response.body.data.valid, true);
});

test('malformed encoded evidence IDs return controlled 400 responses', async (t) => {
  const { handler } = fixture();
  const { server, port } = await listen(handler);
  t.after(() => close(server));
  const response = await request(port, {
    method: 'POST',
    path: '/api/workforce-audit/evidence/%E0%A4%A/verification-bundles',
    body: {}
  });
  assert.equal(response.status, 400);
  assert.match(response.body.error, /invalid percent encoding/);
});
