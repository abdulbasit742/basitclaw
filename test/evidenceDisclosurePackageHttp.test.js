import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request as httpRequest } from 'node:http';
import { AuthenticationError, AuthorizationError } from '../src/security/accessControl.js';
import { EvidenceValidationError } from '../src/evidence/evidenceRegistry.js';
import { createEvidenceDisclosurePackageHandler } from '../src/evidence/evidenceDisclosurePackageHandler.js';

const evidenceId = `EVD-${'a'.repeat(32)}`;
const packageId = `DSP-${'b'.repeat(32)}`;

function fixture({ permissions = ['governance:read', 'evidence:export'] } = {}) {
  let generated = 0;
  const registry = {
    evidenceDisclosureStatus() { return { status: 'ready', enabled: true, receipts: generated }; },
    evidenceDisclosureReceipts() { return generated ? [{ packageId, evidenceId, includeContent: false }] : []; },
    verifyEvidenceDisclosureReceipt() { return { valid: true, receipt: { packageId, packageSha256: 'c'.repeat(64) } }; },
    generateEvidenceDisclosurePackage(_tenant, requestedEvidenceId, input) {
      if (Object.keys(input).some((key) => !['versions', 'purpose', 'confirmation', 'includeContent', 'recipientId'].includes(key))) {
        throw new EvidenceValidationError('Disclosure request contains unsupported field.', { field: 'unsupported' });
      }
      assert.equal(requestedEvidenceId, evidenceId);
      generated += 1;
      return {
        package: { format: 'basitclaw-evidence-disclosure-package', packageId, manifest: {}, signature: 'signature' },
        receipt: { packageId, evidenceId, evidenceVersions: [1], includeContent: false, recipientId: null, recipientKeyFingerprint: null }
      };
    }
  };
  const authenticationGateway = {
    mode: 'api-key',
    async authenticate(req) {
      if (req.headers['x-api-key'] !== 'manager-key') throw new AuthenticationError();
      return { subject: 'manager.one', tenantId: 'tenant-a', keyId: 'manager-key-id', permissions };
    },
    authorise(principal, permission) {
      if (!principal.permissions.includes(permission)) throw new AuthorizationError();
    }
  };
  return createEvidenceDisclosurePackageHandler({ registry, authenticationGateway });
}

async function listen(handler) {
  const server = createServer((req, res) => handler.handle(req, res));
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return { server, port: server.address().port };
}
async function closeServer(server) {
  server.closeIdleConnections?.();
  server.closeAllConnections?.();
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}
function requestJson(port, path, { method = 'GET', body = null, apiKey = null } = {}) {
  const bytes = body === null ? null : Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const headers = { connection: 'close' };
    if (apiKey) headers['x-api-key'] = apiKey;
    if (bytes) { headers['content-type'] = 'application/json'; headers['content-length'] = bytes.length; }
    const req = httpRequest({ host: '127.0.0.1', port, method, path, headers }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        resolve({ status: res.statusCode, body: text ? JSON.parse(text) : null });
      });
    });
    req.on('error', reject);
    req.end(bytes ?? undefined);
  });
}

test('package generation requires authentication and evidence export permission', async (t) => {
  const { server, port } = await listen(fixture());
  t.after(() => closeServer(server));
  const unauthenticated = await requestJson(port, `/api/workforce-audit/evidence/${evidenceId}/disclosure-packages`, {
    method: 'POST', body: { purpose: 'External regulator disclosure', confirmation: `EXPORT ${evidenceId}` }
  });
  assert.equal(unauthenticated.status, 401);

  const created = await requestJson(port, `/api/workforce-audit/evidence/${evidenceId}/disclosure-packages`, {
    method: 'POST', apiKey: 'manager-key', body: { purpose: 'External regulator disclosure', confirmation: `EXPORT ${evidenceId}` }
  });
  assert.equal(created.status, 201);
  assert.equal(created.body.data.receipt.packageId, packageId);
});

test('principals without evidence export permission cannot generate packages', async (t) => {
  const { server, port } = await listen(fixture({ permissions: ['governance:read'] }));
  t.after(() => closeServer(server));
  const response = await requestJson(port, `/api/workforce-audit/evidence/${evidenceId}/disclosure-packages`, {
    method: 'POST', apiKey: 'manager-key', body: { purpose: 'External regulator disclosure', confirmation: `EXPORT ${evidenceId}` }
  });
  assert.equal(response.status, 403);
});

test('receipt listing and verification return metadata without stored package bytes', async (t) => {
  const { server, port } = await listen(fixture());
  t.after(() => closeServer(server));
  await requestJson(port, `/api/workforce-audit/evidence/${evidenceId}/disclosure-packages`, {
    method: 'POST', apiKey: 'manager-key', body: { purpose: 'External regulator disclosure', confirmation: `EXPORT ${evidenceId}` }
  });
  const listed = await requestJson(port, `/api/workforce-audit/evidence/${evidenceId}/disclosure-packages`, { apiKey: 'manager-key' });
  assert.equal(listed.status, 200);
  assert.equal(listed.body.data[0].package, undefined);
  const verified = await requestJson(port, `/api/workforce-audit/evidence-disclosure/${packageId}/verify`, {
    method: 'POST', apiKey: 'manager-key'
  });
  assert.equal(verified.status, 200);
  assert.equal(verified.body.data.valid, true);
});

test('unsupported public-key fields and malformed encoded IDs fail closed', async (t) => {
  const { server, port } = await listen(fixture());
  t.after(() => closeServer(server));
  const unsupported = await requestJson(port, `/api/workforce-audit/evidence/${evidenceId}/disclosure-packages`, {
    method: 'POST', apiKey: 'manager-key', body: {
      purpose: 'External regulator disclosure', confirmation: `EXPORT ${evidenceId}`,
      publicKeyPem: '-----BEGIN PUBLIC KEY-----'
    }
  });
  assert.equal(unsupported.status, 400);
  const malformed = await requestJson(port, '/api/workforce-audit/evidence/%E0%A4%A/disclosure-packages', { apiKey: 'manager-key' });
  assert.equal(malformed.status, 400);
});
