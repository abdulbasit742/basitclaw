import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { createServer } from 'node:http';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuthenticationError } from '../src/security/accessControl.js';
import { sha256 } from '../src/evidence/evidenceCrypto.js';
import { EvidenceValidationError } from '../src/evidence/evidenceRegistry.js';
import { createExternalScanAttestationRegistry } from '../src/evidence/externalScanAttestationRegistry.js';
import { createExternalScanEvidenceRegistry } from '../src/evidence/externalScanEvidenceRegistry.js';
import { createExternalScanManagementHandler } from '../src/evidence/externalScanManagementHandler.js';

const currentIso = '2026-07-30T00:00:00.000Z';
const evidenceKey = Buffer.alloc(32, 51).toString('base64');
const providerSecret = Buffer.alloc(48, 61);
const evidenceId = 'EVD-0123456789abcdef0123456789abcdef';
const digest = 'c'.repeat(64);

function registryFixture() {
  return createExternalScanAttestationRegistry({
    directory: mkdtempSync(join(tmpdir(), 'external-scan-hardening-')),
    keys: { k1: evidenceKey }, primaryKeyId: 'k1',
    providers: { 'managed-av': { keys: { '2026-q3': providerSecret.toString('base64') } } },
    mode: 'enforce', requiredForRelease: true, maxAttestationAgeMinutes: 1440,
    clockSkewSeconds: 300, eventRetention: 100, maxRecords: 100,
    now: () => new Date(currentIso)
  });
}

function body(overrides = {}) {
  return {
    attestationId: 'managed-av:scan:hardening-0001', tenantId: 'tenant-a', evidenceId,
    version: 1, contentSha256: digest, verdict: 'clean', scannedAt: currentIso,
    engine: 'Managed AV Gateway', engineVersion: '8.4.2', definitionsVersion: '2026.07.30.1',
    findings: [], ...overrides
  };
}

function signed(input, nonce) {
  const bytes = Buffer.from(JSON.stringify(input));
  const canonical = `managed-av\n2026-q3\n${currentIso}\n${nonce}\n${sha256(bytes)}`;
  return {
    bytes,
    headers: {
      'x-basitclaw-scan-provider': 'managed-av',
      'x-basitclaw-scan-key-id': '2026-q3',
      'x-basitclaw-scan-timestamp': currentIso,
      'x-basitclaw-scan-nonce': nonce,
      'x-basitclaw-scan-signature': createHmac('sha256', providerSecret).update(canonical).digest('hex')
    }
  };
}

const target = () => ({ version: 1, contentSha256: digest });

test('rejects unsupported top-level fields instead of silently ignoring scanner payload data', () => {
  const registry = registryFixture();
  const request = signed(body({ rawMatchedValue: 'must-not-be-accepted' }), 'nonce-hardening-00000001');
  assert.throws(() => registry.acceptSigned(request.bytes, request.headers, target), EvidenceValidationError);
  assert.equal(registry.list('tenant-a').length, 0);
});

test('newest scanner timestamp wins when results arrive out of order', () => {
  const registry = registryFixture();
  const malicious = signed(body({
    attestationId: 'managed-av:scan:hardening-0002', verdict: 'malicious', scannedAt: currentIso,
    findings: [{ ruleId: 'MALWARE.TEST', severity: 'critical', category: 'malware' }]
  }), 'nonce-hardening-00000002');
  registry.acceptSigned(malicious.bytes, malicious.headers, target);

  const olderClean = signed(body({
    attestationId: 'managed-av:scan:hardening-0003', verdict: 'clean', scannedAt: '2026-07-29T23:00:00.000Z'
  }), 'nonce-hardening-00000003');
  registry.acceptSigned(olderClean.bytes, olderClean.headers, target);

  assert.equal(registry.latest('tenant-a', evidenceId, 1).verdict, 'malicious');
  const status = registry.tenantStatus('tenant-a');
  assert.equal(status.malicious, 1);
  assert.equal(status.clean, 0);
  assert.equal(status.status, 'attention');
});

test('enforced external scanning makes evidence health required and unavailable when its store is down', () => {
  const base = {
    enabled: true, required: false, directory: '/tmp/external-scan-health',
    screeningReport() { return { version: 1, contentSha256: digest }; },
    health() { return { status: 'ready', enabled: true, required: false }; },
    tenantStatus() { return { status: 'ready' }; },
    verify() { return { valid: true }; },
    get() { return { evidenceId, currentVersion: 1, status: 'quarantine' }; },
    list() { return []; },
    releaseQuarantine() { return { evidenceId, currentVersion: 1, status: 'active' }; }
  };
  const attestations = {
    enabled: true, mode: 'enforce', requiredForRelease: false,
    list() { return []; }, latest() { return null; }, requireCleanForRelease() { return null; },
    verify() { return { valid: true }; },
    tenantStatus() { throw Object.assign(new Error('down'), { code: 'EXTERNAL_SCAN_STORE_UNAVAILABLE' }); },
    health() { return { status: 'unavailable', enabled: true, mode: 'enforce', requiredForRelease: false }; },
    acceptSigned() { throw new Error('not used'); }
  };
  const policyMutex = { withLock(_resource, operation) { return operation(); }, health() { return { status: 'ready' }; } };
  const registry = createExternalScanEvidenceRegistry({ registry: base, attestations, policyMutex });
  const health = registry.health();
  assert.equal(health.required, true);
  assert.equal(health.status, 'unavailable');
  assert.equal(registry.tenantStatus('tenant-a').status, 'unavailable');
});

test('management authentication failures consume the shared auth-failure quota', async (t) => {
  const calls = [];
  const events = [];
  const rateLimiter = {
    clientAddress: () => '127.0.0.1',
    consume(subject, policy) {
      calls.push({ subject, policy });
      if (policy === 'authFailure') return { allowed: false, policy, limit: 1, remaining: 0, retryAfterSeconds: 60 };
      return { allowed: true, policy, limit: 10, remaining: 9, retryAfterSeconds: 0 };
    },
    headers: () => ({})
  };
  const handler = createExternalScanManagementHandler({
    registry: { externalScanStatus() { return { status: 'ready' }; } },
    authenticationGateway: {
      mode: 'api-key',
      authenticate: async () => { throw new AuthenticationError(); },
      authorise() {}
    },
    rateLimiter,
    securityTelemetry: { record(event) { events.push(event); } }
  });
  const server = createServer((req, res) => handler.handle(req, res));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const response = await fetch(`http://127.0.0.1:${server.address().port}/api/workforce-audit/external-scanner/status`);
  assert.equal(response.status, 429);
  assert.equal(response.headers.get('retry-after'), '60');
  assert.ok(calls.some((entry) => entry.policy === 'authFailure' && entry.subject === 'authentication:127.0.0.1'));
  assert.equal(events[0].type, 'authentication.failed');
});
