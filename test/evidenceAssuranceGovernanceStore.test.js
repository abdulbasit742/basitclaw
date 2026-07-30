import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createEvidenceAssuranceGovernanceStore } from '../src/evidence/evidenceAssuranceGovernanceStore.js';

const tenantId = 'tenant-assurance-governance';
const evidenceId = `EVD-${'a'.repeat(32)}`;
const bundleId = `ASB-${'b'.repeat(32)}`;
const encryptionKey = Buffer.alloc(32, 91).toString('base64');

function fixture() {
  let current = new Date('2026-07-30T02:00:00.000Z');
  const directory = mkdtempSync(join(tmpdir(), 'assurance-governance-'));
  const store = createEvidenceAssuranceGovernanceStore({
    mode: 'shared-file',
    required: true,
    directory,
    encryptionKeys: { governance: encryptionKey },
    encryptionPrimaryKeyId: 'governance',
    recipientPolicies: {
      'regulator-one': {
        enabled: true,
        allowedTenants: [tenantId],
        allowedResidencyZones: ['pk-primary'],
        allowedPurposeCodes: ['regulatory-exam'],
        allowedLegalBases: ['statutory-notice'],
        validUntil: '2027-07-30T00:00:00.000Z'
      }
    },
    approvalQuorum: 2,
    requestTtlMinutes: 60,
    now: () => new Date(current)
  });
  return { store, directory, advance(ms) { current = new Date(current.getTime() + ms); } };
}

function requestInput(overrides = {}) {
  return {
    tenantId,
    evidenceId,
    evidenceVersion: 1,
    contentSha256: 'c'.repeat(64),
    recipientId: 'regulator-one',
    purpose: 'Respond to an authorised regulatory examination request',
    purposeCode: 'regulatory-exam',
    legalBasis: 'statutory-notice',
    residencyZone: 'pk-primary',
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

test('encrypts governance metadata and enforces recipient purpose, legal-basis and residency policy', () => {
  const { store, directory } = fixture();
  assert.throws(() => store.request(requestInput({ residencyZone: 'eu-external' }), {
    actor: 'manager.requester', role: 'audit_manager'
  }), /residency zone is not approved/);
  const request = store.request(requestInput(), { actor: 'manager.requester', role: 'audit_manager' });
  assert.equal(request.state, 'pending');
  const raw = filesUnder(directory).map((path) => readFileSync(path, 'utf8')).join('\n');
  assert.equal(raw.includes(tenantId), false);
  assert.equal(raw.includes('statutory-notice'), false);
  assert.equal(raw.includes('regulator-one'), false);
});

test('requires requester separation and two distinct approvers before sealing', () => {
  const { store } = fixture();
  const request = store.request(requestInput(), { actor: 'manager.requester', role: 'audit_manager' });
  assert.throws(() => store.approve(tenantId, request.requestId, {
    actor: 'manager.requester', role: 'audit_manager'
  }), /requester cannot approve/);
  const first = store.approve(tenantId, request.requestId, {
    actor: 'manager.approver-one', role: 'audit_manager'
  });
  assert.equal(first.readyToSeal, false);
  const second = store.approve(tenantId, request.requestId, {
    actor: 'admin.approver-two', role: 'compliance_admin'
  });
  assert.equal(second.readyToSeal, true);
  const sealed = store.attachBundle(tenantId, request.requestId, {
    bundleId,
    packageSha256: 'd'.repeat(64)
  });
  assert.equal(sealed.state, 'sealed');
  assert.equal(store.deliveryAllowed(bundleId), true);
  assert.equal(store.verifyTenant(tenantId).checkedBundleLinks, 1);
});

test('revocation suppresses recipient delivery and delivered history cannot be revoked', () => {
  const { store } = fixture();
  const request = store.request(requestInput(), { actor: 'manager.requester', role: 'audit_manager' });
  store.approve(tenantId, request.requestId, { actor: 'manager.one', role: 'audit_manager' });
  store.approve(tenantId, request.requestId, { actor: 'admin.two', role: 'compliance_admin' });
  store.attachBundle(tenantId, request.requestId, { bundleId, packageSha256: 'd'.repeat(64) });
  const revoked = store.revoke(tenantId, request.requestId, {
    actor: 'admin.revoker',
    reason: 'Recipient authority was withdrawn before delivery'
  });
  assert.equal(revoked.state, 'revoked');
  assert.equal(store.deliveryAllowed(bundleId), false);
  assert.equal(store.recordSuppressedDelivery(bundleId, 'regulator-one').state, 'revoked');

  const otherBundleId = `ASB-${'e'.repeat(32)}`;
  const second = store.request(requestInput(), { actor: 'manager.requester', role: 'audit_manager' });
  store.approve(tenantId, second.requestId, { actor: 'manager.one', role: 'audit_manager' });
  store.approve(tenantId, second.requestId, { actor: 'admin.two', role: 'compliance_admin' });
  store.attachBundle(tenantId, second.requestId, { bundleId: otherBundleId, packageSha256: 'f'.repeat(64) });
  store.markDelivered(otherBundleId, 'regulator-one');
  assert.throws(() => store.revoke(tenantId, second.requestId, {
    actor: 'admin.revoker', reason: 'Attempted retroactive revocation'
  }), /cannot be retroactively revoked/);
});

test('expired pending requests are persisted and cannot be approved', () => {
  const { store, advance } = fixture();
  const request = store.request(requestInput(), { actor: 'manager.requester', role: 'audit_manager' });
  advance(61 * 60_000);
  assert.throws(() => store.approve(tenantId, request.requestId, {
    actor: 'manager.approver', role: 'audit_manager'
  }), /has expired/);
  assert.equal(store.get(tenantId, request.requestId).state, 'expired');
  assert.equal(store.report(tenantId).byState.expired, 1);
});
