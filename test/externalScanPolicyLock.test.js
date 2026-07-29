import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { SecurityControlBusyError } from '../src/security/fileMutex.js';
import { createExternalScanEvidenceRegistry } from '../src/evidence/externalScanEvidenceRegistry.js';
import { createExternalScanCallbackHandler } from '../src/evidence/externalScanCallbackHandler.js';

const evidenceId = 'EVD-0123456789abcdef0123456789abcdef';
const digest = 'a'.repeat(64);

function policyFixture() {
  const resources = [];
  let active = false;
  const policyMutex = {
    withLock(resource, operation) {
      assert.equal(active, false, 'policy operations must not overlap');
      active = true;
      resources.push(resource);
      try { return operation(); } finally { active = false; }
    },
    health() { return { status: 'ready', mode: 'test-policy-mutex' }; }
  };
  const item = {
    evidenceId,
    currentVersion: 1,
    status: 'quarantine',
    versions: [{ version: 1, sha256: digest }]
  };
  const registry = {
    enabled: true,
    directory: '/tmp/external-scan-policy-test',
    get: () => ({ ...item }),
    list: () => [{ ...item }],
    screeningReport: () => ({ version: 1, contentSha256: digest, decision: 'quarantine' }),
    releaseQuarantine: () => ({ ...item, status: 'active' }),
    verify: () => ({ valid: true }),
    health: () => ({ status: 'ready', enabled: true }),
    tenantStatus: () => ({ status: 'attention' })
  };
  const clean = {
    attestationId: 'managed-av:scan:policy-lock', providerId: 'managed-av', keyId: '2026-q3',
    evidenceId, version: 1, contentSha256: digest, verdict: 'clean', scannedAt: '2026-07-30T00:00:00.000Z'
  };
  const attestations = {
    enabled: true,
    mode: 'enforce',
    requiredForRelease: true,
    acceptSigned(_body, _headers, validateTarget) {
      assert.deepEqual(validateTarget({ tenantId: 'tenant-a', evidenceId, version: 1 }), { version: 1, contentSha256: digest });
      return { accepted: true, duplicate: false, attestation: clean };
    },
    list: () => [clean],
    latest: () => clean,
    requireCleanForRelease: () => clean,
    verify: () => ({ valid: true, tenantId: 'tenant-a', records: 1 }),
    tenantStatus: () => ({ status: 'ready', mode: 'enforce', requiredForRelease: true, totalAttestations: 1 }),
    health: () => ({ status: 'ready', enabled: true, mode: 'enforce', requiredForRelease: true })
  };
  return { registry: createExternalScanEvidenceRegistry({ registry, attestations, policyMutex }), resources };
}

test('attestation acceptance and quarantine release share one policy lock', () => {
  const { registry, resources } = policyFixture();
  registry.recordExternalScanAttestation(Buffer.from('{}'), {});
  const released = registry.releaseQuarantine('tenant-a', evidenceId, {
    confirmation: `RELEASE QUARANTINE ${evidenceId}`,
    reason: 'Policy lock test release decision'
  }, { actor: 'admin.one' });
  assert.equal(released.status, 'active');
  assert.deepEqual(resources, ['external-scan-release-policy', 'external-scan-release-policy']);
  assert.equal(registry.health().externalScan.policyMutex.status, 'ready');
});

test('scanner callback maps policy contention to retryable 423', async (t) => {
  const registry = {
    recordExternalScanAttestation() {
      throw new SecurityControlBusyError('busy', { retryAfterMs: 1200 });
    }
  };
  const handler = createExternalScanCallbackHandler({ registry });
  const server = createServer((req, res) => handler.handle(req, res));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const response = await fetch(`http://127.0.0.1:${server.address().port}${handler.route}`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}'
  });
  assert.equal(response.status, 423);
  assert.equal(response.headers.get('retry-after'), '2');
  assert.equal((await response.json()).code, 'EXTERNAL_SCAN_POLICY_BUSY');
});
