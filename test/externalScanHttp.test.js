import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { createServer } from 'node:http';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createEvidenceRegistry } from '../src/evidence/evidenceRegistry.js';
import { createEvidenceScreeningEngine } from '../src/evidence/evidenceScreeningEngine.js';
import { createScreenedEvidenceRegistry } from '../src/evidence/evidenceScreeningRegistry.js';
import { createExternalScanAttestationRegistry } from '../src/evidence/externalScanAttestationRegistry.js';
import { createExternalScanEvidenceRegistry } from '../src/evidence/externalScanEvidenceRegistry.js';
import { createExternalScanCallbackHandler } from '../src/evidence/externalScanCallbackHandler.js';
import { createExternalScanManagementHandler } from '../src/evidence/externalScanManagementHandler.js';
import { sha256 } from '../src/evidence/evidenceCrypto.js';

const evidenceKey = Buffer.alloc(32, 31).toString('base64');
const providerSecret = Buffer.alloc(48, 41);
const currentIso = '2026-07-30T00:00:00.000Z';

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), 'external-scan-http-'));
  const base = createEvidenceRegistry({ directory, keys: { k1: evidenceKey }, primaryKeyId: 'k1' });
  const screened = createScreenedEvidenceRegistry({
    registry: base,
    engine: createEvidenceScreeningEngine({ mode: 'enforce', now: () => new Date(currentIso) }),
    keys: { k1: evidenceKey }, primaryKeyId: 'k1', eventRetention: 100, now: () => new Date(currentIso)
  });
  const attestations = createExternalScanAttestationRegistry({
    directory,
    keys: { k1: evidenceKey },
    primaryKeyId: 'k1',
    providers: { 'managed-av': { keys: { '2026-q3': providerSecret.toString('base64') } } },
    mode: 'enforce', requiredForRelease: true, maxAttestationAgeMinutes: 60,
    clockSkewSeconds: 300, eventRetention: 100, maxRecords: 1000,
    now: () => new Date(currentIso)
  });
  const registry = createExternalScanEvidenceRegistry({ registry: screened, attestations });
  const item = registry.ingest('tenant-a', {
    filename: 'script.js', mediaType: 'application/javascript', contentBase64: Buffer.from('alert(1)').toString('base64')
  }, { actor: 'auditor.one' });
  const report = registry.screeningReport('tenant-a', item.evidenceId);
  return { registry, item, report };
}

function signed(body, { valid = true, nonce = 'nonce-0000000000000010' } = {}) {
  const bytes = Buffer.from(JSON.stringify(body));
  const canonical = `managed-av\n2026-q3\n${currentIso}\n${nonce}\n${sha256(bytes)}`;
  const signature = createHmac('sha256', valid ? providerSecret : Buffer.alloc(48, 1)).update(canonical).digest('hex');
  return {
    bytes,
    headers: {
      'content-type': 'application/json',
      'x-basitclaw-scan-provider': 'managed-av',
      'x-basitclaw-scan-key-id': '2026-q3',
      'x-basitclaw-scan-timestamp': currentIso,
      'x-basitclaw-scan-nonce': nonce,
      'x-basitclaw-scan-signature': signature
    }
  };
}

function bodyFor(item, report) {
  return {
    attestationId: 'managed-av:scan:0000000000000010',
    tenantId: 'tenant-a', evidenceId: item.evidenceId, version: item.currentVersion,
    contentSha256: report.contentSha256, verdict: 'clean', scannedAt: currentIso,
    engine: 'Managed AV Gateway', engineVersion: '8.4.2', definitionsVersion: '2026.07.30.1', findings: []
  };
}

async function listen(handler) {
  const server = createServer((req, res) => handler.handle(req, res));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { server, base: `http://127.0.0.1:${server.address().port}` };
}

test('signed callback accepts a clean attestation and exact replay is idempotent', async (t) => {
  const { registry, item, report } = fixture();
  const handler = createExternalScanCallbackHandler({ registry });
  const { server, base } = await listen(handler);
  t.after(() => server.close());
  const request = signed(bodyFor(item, report));

  const accepted = await fetch(`${base}${handler.route}`, { method: 'POST', headers: request.headers, body: request.bytes });
  assert.equal(accepted.status, 202);
  const acceptedPayload = await accepted.json();
  assert.equal(acceptedPayload.data.attestation.verdict, 'clean');
  assert.equal(JSON.stringify(acceptedPayload).includes(providerSecret.toString('base64')), false);

  const duplicate = await fetch(`${base}${handler.route}`, { method: 'POST', headers: request.headers, body: request.bytes });
  assert.equal(duplicate.status, 200);
  assert.equal((await duplicate.json()).data.duplicate, true);
});

test('callback rejects invalid signatures without revealing provider existence', async (t) => {
  const { registry, item, report } = fixture();
  const handler = createExternalScanCallbackHandler({ registry });
  const { server, base } = await listen(handler);
  t.after(() => server.close());
  const request = signed(bodyFor(item, report), { valid: false, nonce: 'nonce-0000000000000011' });
  const response = await fetch(`${base}${handler.route}`, { method: 'POST', headers: request.headers, body: request.bytes });
  assert.equal(response.status, 401);
  const payload = await response.json();
  assert.equal(payload.code, 'EXTERNAL_SCAN_AUTHENTICATION_FAILED');
  assert.equal(JSON.stringify(payload).includes('managed-av'), false);
});

test('governance management routes expose status and privacy-minimised attestations', async (t) => {
  const { registry, item, report } = fixture();
  const request = signed(bodyFor(item, report), { nonce: 'nonce-0000000000000012' });
  registry.recordExternalScanAttestation(request.bytes, request.headers);
  const principal = { subject: 'audit.manager', tenantId: 'tenant-a', keyId: 'key-1', permissions: ['governance:read'] };
  const authenticationGateway = {
    mode: 'api-key',
    authenticate: async () => principal,
    authorise: (candidate, permission) => {
      if (!candidate.permissions.includes(permission)) { const error = new Error('forbidden'); error.code = 'FORBIDDEN'; throw error; }
      return candidate;
    }
  };
  const handler = createExternalScanManagementHandler({ registry, authenticationGateway });
  const { server, base } = await listen(handler);
  t.after(() => server.close());

  const status = await fetch(`${base}/api/workforce-audit/external-scanner/status`);
  assert.equal(status.status, 200);
  assert.equal((await status.json()).data.totalAttestations, 1);

  const history = await fetch(`${base}/api/workforce-audit/evidence/${item.evidenceId}/external-scans`);
  assert.equal(history.status, 200);
  const payload = await history.json();
  assert.equal(payload.data.length, 1);
  assert.equal(payload.data[0].contentSha256, report.contentSha256);
  assert.equal(JSON.stringify(payload).includes(providerSecret.toString('base64')), false);
});
