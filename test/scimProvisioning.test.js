import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scryptSync } from 'node:crypto';
import { createIdentityEntitlementRegistry } from '../src/security/identityEntitlementRegistry.js';
import { createScimAccessController } from '../src/security/scimAccessController.js';
import { createScimHandler, WORKFORCE_EXTENSION } from '../src/security/scimHandler.js';

const storeKey = Buffer.alloc(32, 9).toString('base64');
const salt = '0123456789abcdef0123456789abcdef';
const secret = '0123456789abcdef0123456789abcdef';
const secretHash = scryptSync(secret, salt, 32).toString('base64');

function credential(overrides = {}) {
  return {
    keyId: 'scim-1', subject: 'scim-admin', salt, secretHash,
    scopes: ['scim:read', 'scim:write'], status: 'active', ...overrides
  };
}

function fixture({ credentials = [credential()] } = {}) {
  const registry = createIdentityEntitlementRegistry({
    mode: 'enforce', directory: mkdtempSync(join(tmpdir(), 'basitclaw-scim-')),
    keys: { k1: storeKey }, primaryKeyId: 'k1', now: () => new Date('2026-07-29T00:00:00Z')
  });
  const accessController = createScimAccessController({ credentials });
  const telemetry = { events: [], record(value) { this.events.push(value); } };
  const handler = createScimHandler({ registry, accessController, issuer: 'https://id.example.com/tenant', securityTelemetry: telemetry });
  const server = createServer((req, res) => {
    handler.handle(req, res).catch((error) => {
      if (!res.headersSent) res.writeHead(500);
      res.end(JSON.stringify({ error: error.message }));
    });
  });
  return { registry, telemetry, server };
}

async function request(server, path, { method = 'GET', body, headers = {}, token = `scim-1.${secret}` } = {}) {
  if (!server.listening) await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const response = await fetch(`http://127.0.0.1:${server.address().port}${path}`, {
    method,
    headers: { authorization: `Bearer ${token}`, ...(body ? { 'content-type': 'application/scim+json' } : {}), ...headers },
    body: body ? JSON.stringify(body) : undefined
  });
  const text = await response.text();
  return { response, payload: text ? JSON.parse(text) : null };
}

const user = {
  schemas: ['urn:ietf:params:scim:schemas:core:2.0:User', WORKFORCE_EXTENSION],
  externalId: 'idp-user-1', active: true, displayName: 'Audit User',
  [WORKFORCE_EXTENSION]: {
    tenantId: 'tenant-a', role: 'auditor', reviewBy: '2027-01-01T00:00:00Z', reason: 'approved onboarding'
  }
};

function patchBody(operations) {
  return { schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'], Operations: operations };
}

test('SCIM create, read, patch, and deprovision use ETags and governance evidence', async (t) => {
  const { registry, telemetry, server } = fixture();
  t.after(() => server.close());
  const created = await request(server, '/scim/v2/Users', { method: 'POST', body: user });
  assert.equal(created.response.status, 201);
  assert.equal(created.payload.active, true);
  assert.equal(created.payload.externalId, undefined);
  assert.match(created.response.headers.get('etag'), /^W\/"1"$/);
  const id = created.payload.id;

  const fetched = await request(server, `/scim/v2/Users/${id}`);
  assert.equal(fetched.response.status, 200);
  assert.equal(fetched.payload[WORKFORCE_EXTENSION].tenantId, 'tenant-a');

  const patched = await request(server, `/scim/v2/Users/${id}`, {
    method: 'PATCH', headers: { 'if-match': 'W/"1"' }, body: patchBody([
      { op: 'replace', path: 'active', value: false },
      { op: 'replace', path: WORKFORCE_EXTENSION, value: { reason: 'employment ended' } }
    ])
  });
  assert.equal(patched.response.status, 200);
  assert.equal(patched.payload.active, false);
  assert.match(patched.response.headers.get('etag'), /^W\/"2"$/);

  const removed = await request(server, `/scim/v2/Users/${id}`, {
    method: 'DELETE', headers: { 'if-match': 'W/"2"', 'x-basitclaw-change-reason': 'confirmed deprovisioning' }
  });
  assert.equal(removed.response.status, 204);
  assert.equal(registry.get(id).active, false);
  assert.ok(telemetry.events.some((event) => event.type === 'identity.provisioned'));
  assert.ok(telemetry.events.some((event) => event.type === 'identity.deprovisioned'));
});

test('SCIM rejects missing credentials, stale or missing ETags, and unsupported filters', async (t) => {
  const { server } = fixture();
  t.after(() => server.close());
  if (!server.listening) await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const unauthenticated = await fetch(`http://127.0.0.1:${server.address().port}/scim/v2/Users`);
  assert.equal(unauthenticated.status, 401);

  const created = await request(server, '/scim/v2/Users', { method: 'POST', body: user });
  const id = created.payload.id;
  const stale = await request(server, `/scim/v2/Users/${id}`, {
    method: 'PATCH', headers: { 'if-match': 'W/"0"' }, body: patchBody([
      { op: 'replace', path: WORKFORCE_EXTENSION, value: { reason: 'stale update', role: 'audit_manager' } }
    ])
  });
  assert.equal(stale.response.status, 409);

  const missingPatchEtag = await request(server, `/scim/v2/Users/${id}`, {
    method: 'PATCH', body: patchBody([{ op: 'replace', path: WORKFORCE_EXTENSION, value: { reason: 'missing version' } }])
  });
  assert.equal(missingPatchEtag.response.status, 409);
  const missingDeleteEtag = await request(server, `/scim/v2/Users/${id}`, {
    method: 'DELETE', headers: { 'x-basitclaw-change-reason': 'missing version' }
  });
  assert.equal(missingDeleteEtag.response.status, 409);

  const badFilter = await request(server, '/scim/v2/Users?filter=userName%20co%20%22x%22');
  assert.equal(badFilter.response.status, 400);
  const malformedId = await request(server, '/scim/v2/Users/%ZZ');
  assert.equal(malformedId.response.status, 400);
});

test('SCIM rejects read-only writes, identity replacement, and non-boolean active values', async (t) => {
  const readOnly = fixture({ credentials: [credential({ scopes: ['scim:read'] })] });
  t.after(() => readOnly.server.close());
  const denied = await request(readOnly.server, '/scim/v2/Users', { method: 'POST', body: user });
  assert.equal(denied.response.status, 403);

  const { server } = fixture();
  t.after(() => server.close());
  const created = await request(server, '/scim/v2/Users', { method: 'POST', body: user });
  const id = created.payload.id;
  const replacement = await request(server, `/scim/v2/Users/${id}`, {
    method: 'PUT', headers: { 'if-match': 'W/"1"' }, body: { ...user, externalId: 'different-external-id' }
  });
  assert.equal(replacement.response.status, 400);

  const invalidBoolean = await request(server, `/scim/v2/Users/${id}`, {
    method: 'PATCH', headers: { 'if-match': 'W/"1"' }, body: patchBody([
      { op: 'replace', path: 'active', value: 'false' },
      { op: 'replace', path: WORKFORCE_EXTENSION, value: { reason: 'invalid boolean' } }
    ])
  });
  assert.equal(invalidBoolean.response.status, 400);
});
