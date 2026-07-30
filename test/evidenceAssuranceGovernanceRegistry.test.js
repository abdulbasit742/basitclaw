import test from 'node:test';
import assert from 'node:assert/strict';
import { createEvidenceAssuranceGovernanceRegistry, EvidenceAssuranceGovernanceRequiredError } from '../src/evidence/evidenceAssuranceGovernanceRegistry.js';

const tenantId = 'tenant-registry';
const evidenceId = `EVD-${'a'.repeat(32)}`;
const requestId = `AGR-${'b'.repeat(32)}`;
const bundleId = `ASB-${'c'.repeat(32)}`;

function fixture() {
  const created = [];
  const base = {
    assuranceBundleEnabled: true,
    createAssuranceBundle(tenant, evidence, input, context) {
      created.push({ tenant, evidence, input, context });
      return { bundle: { bundleId, packageSha256: 'd'.repeat(64), state: 'pending', recipientId: input.recipientId }, duplicate: false, resealed: false };
    },
    claimAssuranceBundles() { return { recipientId: 'regulator-one', bundles: [{ bundleId }, { bundleId: `ASB-${'e'.repeat(32)}` }] }; },
    acknowledgeAssuranceBundle(id) { return { bundleId: id, recipientId: 'regulator-one', state: 'delivered' }; },
    assuranceBundles() { return [{ bundleId, state: 'pending' }]; },
    get() { return { evidenceId, status: 'active', currentVersion: 1, versions: [{ version: 1, sha256: 'f'.repeat(64) }] }; },
    verify() { return { valid: true }; },
    health() { return { status: 'ready', required: true }; },
    tenantStatus() { return { status: 'ready' }; }
  };
  let approvals = 0;
  let state = 'pending';
  const governance = {
    enabled: true,
    required: true,
    request() { return { requestId, evidenceId, evidenceVersion: 1, recipientId: 'regulator-one', state: 'pending' }; },
    approve(_tenant, _request, context) {
      approvals += 1;
      state = approvals >= 2 ? 'approved' : 'pending';
      return { requestId, evidenceId, evidenceVersion: 1, contentSha256: 'f'.repeat(64), recipientId: 'regulator-one', purpose: 'Authorised regulatory review', purposeCode: 'regulatory-exam', legalBasis: 'statutory-notice', residencyZone: 'pk-primary', requestedBy: 'manager.requester', state, readyToSeal: state === 'approved', approvals: [{ actor: context.actor }] };
    },
    get() { return { requestId, evidenceId, evidenceVersion: 1, recipientId: 'regulator-one', purpose: 'Authorised regulatory review', purposeCode: 'regulatory-exam', legalBasis: 'statutory-notice', residencyZone: 'pk-primary', requestedBy: 'manager.requester', state, readyToSeal: state === 'approved', bundleId: state === 'sealed' ? bundleId : null }; },
    attachBundle() { state = 'sealed'; return { requestId, evidenceId, state: 'sealed', bundleId }; },
    reject() { state = 'rejected'; return { requestId, state }; },
    revoke() { state = 'revoked'; return { requestId, state }; },
    deliveryAllowed(id) { return id === bundleId && state === 'sealed'; },
    recordSuppressedDelivery() {},
    markDelivered() { state = 'delivered'; },
    list() { return []; },
    report() { return { total: 0, byState: {} }; },
    verifyTenant() { return { valid: true }; },
    health() { return { status: 'ready', enabled: true, required: true }; }
  };
  return { registry: createEvidenceAssuranceGovernanceRegistry({ registry: base, governance }), created, governance };
}

test('direct bundle creation is blocked and Pass 21 sealing occurs only after quorum', () => {
  const { registry, created } = fixture();
  assert.throws(() => registry.createAssuranceBundle(tenantId, evidenceId, {}), EvidenceAssuranceGovernanceRequiredError);
  const requested = registry.requestAssuranceBundle(tenantId, evidenceId, {
    version: 1,
    recipientId: 'regulator-one',
    purpose: 'Authorised regulatory review',
    purposeCode: 'regulatory-exam',
    legalBasis: 'statutory-notice',
    residencyZone: 'pk-primary',
    confirmation: `REQUEST EXPORT ${evidenceId} V1 TO regulator-one`
  }, { actor: 'manager.requester', role: 'audit_manager' });
  assert.equal(requested.requestId, requestId);
  assert.equal(registry.approveAssuranceRequest(tenantId, requestId, { actor: 'manager.one', role: 'audit_manager' }).bundle, null);
  const sealed = registry.approveAssuranceRequest(tenantId, requestId, { actor: 'admin.two', role: 'compliance_admin' });
  assert.equal(sealed.bundle.bundleId, bundleId);
  assert.equal(created.length, 1);
  assert.equal(created[0].input.governanceRequestId, requestId);
  assert.equal(created[0].input.legalBasis, 'statutory-notice');
  assert.equal(created[0].context.actor, 'manager.requester');
});

test('revoked or unlinked claimed bundles are removed before the recipient response', () => {
  const { registry } = fixture();
  const result = registry.claimAssuranceBundles(Buffer.from('{}'), {});
  assert.equal(result.bundles.length, 0);
  assert.equal(result.jobs.length, 0);
});
