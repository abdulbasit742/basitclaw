import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request as httpRequest } from 'node:http';
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuthorizationError } from '../src/security/accessControl.js';
import { EvidenceValidationError } from '../src/evidence/evidenceRegistry.js';
import {
  EvidenceTimeAttestationGovernanceIntegrityError,
  EvidenceTimeAttestationGovernanceRequiredError,
  createEvidenceTimeAttestationGovernanceStore,
  createEvidenceTimeAttestationGovernanceStoreFromEnvironment
} from '../src/evidence/evidenceTimeAttestationGovernanceStore.js';
import { createEvidenceTimeAttestationGovernanceRegistry } from '../src/evidence/evidenceTimeAttestationGovernanceRegistry.js';
import { createEvidenceTimeAttestationGovernanceAwareApp } from '../src/evidence/evidenceTimeAttestationGovernanceServer.js';

const encryptionKey = Buffer.alloc(32, 61).toString('base64');
const signingKey = Buffer.alloc(48, 67).toString('base64');
const tenantId = 'tenant-governance';
const archiveId = `ARC-${'c'.repeat(32)}`;
const evidenceId = `EVD-${'d'.repeat(32)}`;
const attestationA = Object.freeze({
  attestationId: `NTA-${'a'.repeat(32)}`,
  archiveId,
  providerId: 'tsa-a',
  keyId: 'key-a',
  timestamp: '2026-07-30T00:30:00.000Z'
});
const attestationB = Object.freeze({
  attestationId: `NTA-${'b'.repeat(32)}`,
  archiveId,
  providerId: 'tsa-b',
  keyId: 'key-b',
  timestamp: '2026-07-30T01:30:00.000Z'
});

function storeFixture(options = {}) {
  const directory = mkdtempSync(join(tmpdir(), 'notary-governance-'));
  const now = options.now ?? (() => new Date('2026-07-30T02:00:00.000Z'));
  return {
    directory,
    store: createEvidenceTimeAttestationGovernanceStore({
      mode: 'shared-file',
      requiredForDisposition: options.requiredForDisposition ?? false,
      directory,
      encryptionKeys: { governance: encryptionKey },
      encryptionPrimaryKeyId: 'governance',
      signingSecrets: { journal: signingKey },
      signingPrimaryKeyId: 'journal',
      maxEvents: 1000,
      now
    })
  };
}

function providerRevocation(overrides = {}) {
  return {
    eventType: 'provider_revoked',
    providerId: 'tsa-a',
    effectiveAt: '2026-07-30T01:00:00.000Z',
    retroactive: false,
    reasonCode: 'provider_termination',
    reason: 'Provider contract and trust approval were withdrawn.',
    confirmation: 'REVOKE NOTARY PROVIDER tsa-a',
    ...overrides
  };
}

function filesUnder(directory) {
  const files = [];
  const walk = (path) => {
    for (const entry of readdirSync(path, { withFileTypes: true })) {
      const child = join(path, entry.name);
      entry.isDirectory() ? walk(child) : files.push(child);
    }
  };
  walk(directory);
  return files;
}

test('prospective provider revocation preserves earlier proof and excludes later attestations', () => {
  const { store } = storeFixture();
  store.record(tenantId, providerRevocation(), { actor: 'manager.one' });
  const evaluation = store.evaluate(tenantId, [attestationA, { ...attestationA, attestationId: `NTA-${'e'.repeat(32)}`, timestamp: '2026-07-30T01:30:00.000Z' }]);
  assert.equal(evaluation.decisions.get(attestationA.attestationId).operationallyAcceptable, true);
  assert.equal(evaluation.decisions.get(`NTA-${'e'.repeat(32)}`).operationallyAcceptable, false);
  assert.equal(evaluation.decisions.get(`NTA-${'e'.repeat(32)}`).cryptographicallyValid, true);
});

test('retroactive key compromise excludes historical attestations without deleting them', () => {
  const { store } = storeFixture();
  store.record(tenantId, {
    eventType: 'key_revoked', providerId: 'tsa-a', keyId: 'key-a',
    effectiveAt: '2026-07-30T01:00:00.000Z', retroactive: true,
    reasonCode: 'key_compromise', reason: 'The authority signing key was reported compromised.',
    confirmation: 'REVOKE NOTARY KEY tsa-a/key-a'
  }, { actor: 'manager.one' });
  const decision = store.evaluate(tenantId, [attestationA]).decisions.get(attestationA.attestationId);
  assert.equal(decision.operationallyAcceptable, false);
  assert.equal(decision.cryptographicallyValid, true);
  assert.equal(store.list(tenantId).length, 1);
});

test('supersession marks only the original attestation as operationally superseded', () => {
  const { store } = storeFixture();
  store.record(tenantId, {
    eventType: 'attestation_superseded', archiveId,
    attestationId: attestationA.attestationId,
    replacementAttestationId: attestationB.attestationId,
    effectiveAt: '2026-07-30T01:45:00.000Z', retroactive: false,
    reasonCode: 'superseded', reason: 'A corrected authority token replaces the original token.',
    confirmation: `SUPERSEDE ATTESTATION ${attestationA.attestationId} WITH ${attestationB.attestationId}`
  }, { actor: 'manager.one' });
  const decisions = store.evaluate(tenantId, [attestationA, attestationB]).decisions;
  assert.equal(decisions.get(attestationA.attestationId).status, 'superseded');
  assert.equal(decisions.get(attestationB.attestationId).status, 'acceptable');
});

test('identical governance events are idempotent and encrypted without plaintext identifiers', () => {
  const { store, directory } = storeFixture();
  const first = store.record(tenantId, providerRevocation(), { actor: 'manager.one' });
  const duplicate = store.record(tenantId, providerRevocation(), { actor: 'manager.two' });
  assert.equal(first.recorded, true);
  assert.equal(duplicate.duplicate, true);
  assert.equal(duplicate.event.recordedBy, 'manager.one');
  const raw = filesUnder(directory).map((path) => readFileSync(path, 'utf8')).join('\n');
  assert.equal(raw.includes(tenantId), false);
  assert.equal(raw.includes('Provider contract and trust approval'), false);
  assert.equal(store.verifyTenant(tenantId).checkedEvents, 1);
});

test('encrypted journal tampering fails closed and tenant data remains isolated', () => {
  const { store, directory } = storeFixture();
  store.record(tenantId, providerRevocation(), { actor: 'manager.one' });
  assert.equal(store.list('tenant-other').length, 0);
  const path = filesUnder(directory).find((candidate) => candidate.endsWith('.enc.json'));
  const envelope = JSON.parse(readFileSync(path, 'utf8'));
  envelope.ciphertext = envelope.ciphertext.replace(/^./, envelope.ciphertext[0] === 'A' ? 'B' : 'A');
  writeFileSync(path, JSON.stringify(envelope));
  assert.throws(() => store.verifyTenant(tenantId), EvidenceTimeAttestationGovernanceIntegrityError);
});

test('enabled environment configuration requires dedicated encryption and signing keys', () => {
  assert.throws(() => createEvidenceTimeAttestationGovernanceStoreFromEnvironment({
    env: { WORKFORCE_AUDIT_EVIDENCE_NOTARY_GOVERNANCE_MODE: 'shared-file' }
  }), (error) => error.details?.reason === 'missing_governance_encryption_keys');
});

function fakeTimeRegistry() {
  const item = {
    evidenceId,
    status: 'active',
    retentionUntil: '2035-07-30T00:00:00.000Z',
    versions: [{ version: 1, sha256: 'f'.repeat(64) }]
  };
  const receipt = { archiveId };
  return {
    recordTimeAttestation(input) { return { accepted: true, duplicate: false, attestation: input }; },
    verifyEvidenceTimeAttestations() {
      return { valid: true, archiveId, attestationCount: 2, distinctProviders: 2, minimumProviders: 2, quorumSatisfied: true, providerIds: ['tsa-a', 'tsa-b'] };
    },
    evidenceTimeAttestations() { return [attestationA, attestationB]; },
    dispose() { return { status: 'disposed' }; },
    get() { return item; },
    list() { return [item]; },
    evidencePreservationStore: { verifiedForVersion() { return receipt; } },
    evidenceTimeAttestationStore: {
      minimumProviders: 2,
      list() { return [attestationA, attestationB]; }
    },
    evidenceTimeAttestationStatus() { return { status: 'ready', dispositionReady: true }; },
    evidencePreservationReceipts() { return [receipt]; },
    verify() { return { valid: true }; },
    health() { return { status: 'ready', required: true }; },
    tenantStatus() { return { status: 'ready' }; },
    evidenceTimeAttestationEnabled: true
  };
}

test('retroactive provider compromise recalculates quorum and blocks disposition', () => {
  const base = fakeTimeRegistry();
  const { store } = storeFixture({ requiredForDisposition: true });
  const registry = createEvidenceTimeAttestationGovernanceRegistry({ registry: base, governance: store });
  assert.equal(registry.effectiveArchiveVerification(tenantId, archiveId).operationalQuorumSatisfied, true);
  registry.recordTimeAttestationGovernanceEvent(tenantId, providerRevocation({
    retroactive: true,
    reasonCode: 'authority_compromise',
    reason: 'The authority trust boundary was reported compromised.'
  }), { actor: 'manager.one' });
  const verification = registry.verifyEvidenceTimeAttestations(tenantId, archiveId);
  assert.equal(verification.cryptographicallyValid, true);
  assert.equal(verification.quorumSatisfied, true);
  assert.equal(verification.operationalQuorumSatisfied, false);
  assert.equal(verification.acceptableDistinctProviders, 1);
  assert.equal(registry.evidenceTimeAttestationGovernanceStatus(tenantId).dispositionReady, false);
  assert.throws(
    () => registry.dispose(tenantId, evidenceId, { confirmation: `DISPOSE ${evidenceId}`, reason: 'Retention completed.' }, { actor: 'admin.one' }),
    EvidenceTimeAttestationGovernanceRequiredError
  );
});

test('registry enforces exact confirmations and validates attestation targets', () => {
  const registry = createEvidenceTimeAttestationGovernanceRegistry({
    registry: fakeTimeRegistry(),
    governance: storeFixture().store
  });
  assert.throws(() => registry.recordTimeAttestationGovernanceEvent(tenantId, {
    ...providerRevocation(), confirmation: 'REVOKE PROVIDER tsa-a'
  }, { actor: 'manager.one' }), EvidenceValidationError);
  assert.throws(() => registry.recordTimeAttestationGovernanceEvent(tenantId, {
    eventType: 'attestation_revoked', archiveId,
    attestationId: `NTA-${'9'.repeat(32)}`,
    effectiveAt: '2026-07-30T01:00:00.000Z', retroactive: false,
    reasonCode: 'administrative_error', reason: 'The authority token was issued in error.',
    confirmation: `REVOKE ATTESTATION NTA-${'9'.repeat(32)}`
  }, { actor: 'manager.one' }), EvidenceValidationError);
});

async function listen(server) {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return server.address().port;
}

function post(port, body) {
  const payload = Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const req = httpRequest({
      host: '127.0.0.1', port, method: 'POST',
      path: '/api/workforce-audit/evidence-notary/governance/events',
      headers: {
        'content-type': 'application/json',
        'content-length': payload.length,
        connection: 'close'
      }
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) }));
    });
    req.on('error', reject);
    req.end(payload);
  });
}

function baseAppForPermissions(permissions) {
  const app = createServer((req, res) => { res.writeHead(404); res.end(); });
  app.authenticationGateway = {
    mode: 'api-key',
    async authenticate() {
      return { subject: 'user.one', tenantId, keyId: 'key-one', permissions };
    },
    authorise(principal, permission) {
      if (!principal.permissions.includes(permission)) throw new AuthorizationError();
      return principal;
    }
  };
  app.apiSecurity = {};
  return app;
}

test('runtime maps governance writes to the existing manager-only preservation permission', async (t) => {
  const evidenceRegistry = {
    recordTimeAttestationGovernanceEvent() {
      return { recorded: true, duplicate: false, event: { eventId: 'NGE-test', eventType: 'provider_revoked', reasonCode: 'provider_termination' } };
    },
    evidenceTimeAttestationGovernanceStatus() { return { status: 'ready' }; },
    evidenceTimeAttestationGovernanceEvents() { return []; },
    verifyEvidenceTimeAttestationGovernance() { return { valid: true, checkedEvents: 0, headSequence: 0 }; }
  };
  const app = createEvidenceTimeAttestationGovernanceAwareApp({
    evidenceRegistry,
    baseApp: baseAppForPermissions(['evidence:preserve', 'governance:read']),
    rateLimiter: null
  });
  const port = await listen(app);
  t.after(() => new Promise((resolve) => app.close(resolve)));
  const response = await post(port, providerRevocation());
  assert.equal(response.status, 201);
});

test('runtime denies governance writes to principals without preservation permission', async (t) => {
  const evidenceRegistry = {
    recordTimeAttestationGovernanceEvent() { throw new Error('must not be called'); },
    evidenceTimeAttestationGovernanceStatus() { return { status: 'ready' }; },
    evidenceTimeAttestationGovernanceEvents() { return []; },
    verifyEvidenceTimeAttestationGovernance() { return { valid: true, checkedEvents: 0, headSequence: 0 }; }
  };
  const app = createEvidenceTimeAttestationGovernanceAwareApp({
    evidenceRegistry,
    baseApp: baseAppForPermissions(['governance:read']),
    rateLimiter: null
  });
  const port = await listen(app);
  t.after(() => new Promise((resolve) => app.close(resolve)));
  const response = await post(port, providerRevocation());
  assert.equal(response.status, 403);
});
