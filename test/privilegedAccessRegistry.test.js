import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { permissionsForRole } from '../src/security/accessControl.js';
import { createPrivilegedAccessAdapter } from '../src/security/privilegedAccessAdapter.js';
import {
  PrivilegedAccessStoreError,
  createPrivilegedAccessRegistry
} from '../src/security/privilegedAccessRegistry.js';

const key = Buffer.alloc(32, 7).toString('base64');
const principal = (subject, role = 'compliance_admin', tenantId = 'tenant-a', amr = ['mfa']) => ({
  subject,
  role,
  tenantId,
  authMethod: 'oidc',
  permissions: permissionsForRole(role),
  authenticationContext: { amr, acr: 'urn:high' },
  keyId: `k-${subject}`
});

async function setup(options = {}) {
  const directory = await mkdtemp(resolve(tmpdir(), 'basitclaw-pam-'));
  let current = new Date('2026-07-29T00:00:00.000Z');
  const registry = createPrivilegedAccessRegistry({
    mode: 'enforce',
    directory,
    keys: { k1: key },
    primaryKeyId: 'k1',
    requiredAcr: ['urn:high'],
    breakGlassEnabled: true,
    now: () => new Date(current),
    ...options
  });
  return { directory, registry, setTime: (value) => { current = new Date(value); } };
}

test('two distinct approvers activate only a permission already assigned by the standing role', async () => {
  const { registry } = await setup();
  const requester = principal('requester');
  let request = registry.requestAccess(requester, {
    permissions: ['backup:restore'],
    durationMinutes: 30,
    reason: 'Approved restore during a controlled recovery incident.',
    ticketRef: 'INC-101'
  });
  request = registry.approve(request.id, principal('approver-1'), {
    expectedVersion: request.version,
    comment: 'Validated the recovery ticket and requested access scope.'
  });
  assert.equal(request.status, 'pending');
  assert.throws(() => registry.approve(request.id, principal('approver-1'), {
    expectedVersion: request.version,
    comment: 'A duplicate approval must never satisfy dual control.'
  }), /already approved/);
  request = registry.approve(request.id, principal('approver-2'), {
    expectedVersion: request.version,
    comment: 'Independent approval after validating the operational need.'
  });
  assert.equal(request.status, 'active');
  assert.equal(registry.authorise(requester, 'backup:restore').privilegedAccess.requestId, request.id);
  assert.equal(registry.authorise(requester, 'audit:read').privilegedAccess, undefined);
});

test('self approval and privilege expansion beyond the approved role are denied', async () => {
  const { registry } = await setup();
  const manager = principal('manager', 'audit_manager');
  assert.throws(() => registry.requestAccess(manager, {
    permissions: ['backup:restore'],
    durationMinutes: 30,
    reason: 'Need restore permission for this controlled recovery incident.',
    ticketRef: 'INC-102'
  }), (error) => error.code === 'PRIVILEGED_PERMISSION_NOT_ASSIGNED');

  const requester = principal('requester');
  const request = registry.requestAccess(requester, {
    permissions: ['security:read'],
    durationMinutes: 30,
    reason: 'Need temporary security evidence review for an incident.',
    ticketRef: 'INC-103'
  });
  assert.throws(() => registry.approve(request.id, requester, {
    expectedVersion: request.version,
    comment: 'Self approval must never satisfy the dual-control boundary.'
  }), (error) => error.code === 'PRIVILEGED_ACCESS_SELF_APPROVAL_DENIED');
});

test('expired grants stop authorising protected permissions', async () => {
  const { registry, setTime } = await setup();
  const requester = principal('user');
  let request = registry.requestAccess(requester, {
    permissions: ['security:read'],
    durationMinutes: 5,
    reason: 'Temporary security evidence review for an active incident.',
    ticketRef: 'SEC-9'
  });
  request = registry.approve(request.id, principal('a1'), {
    expectedVersion: request.version,
    comment: 'First independent approval for the evidence review.'
  });
  request = registry.approve(request.id, principal('a2'), {
    expectedVersion: request.version,
    comment: 'Second independent approval for the evidence review.'
  });
  setTime('2026-07-29T00:06:00.000Z');
  assert.throws(() => registry.authorise(requester, 'security:read'), (error) => error.code === 'PRIVILEGED_ACCESS_REQUIRED');
});

test('break glass requires exact confirmation, step-up assurance, and independent review', async () => {
  const { registry } = await setup();
  const emergencyUser = principal('emergency');
  assert.throws(() => registry.activateBreakGlass(emergencyUser, {
    permissions: ['resilience:run'],
    durationMinutes: 10,
    reason: 'Critical production recovery requires an immediate resilience cycle.',
    incidentRef: 'SEV-1',
    confirmation: 'yes'
  }), (error) => error.code === 'BREAK_GLASS_CONFIRMATION_REQUIRED');

  let request = registry.activateBreakGlass(emergencyUser, {
    permissions: ['resilience:run'],
    durationMinutes: 10,
    reason: 'Critical production recovery requires an immediate resilience cycle.',
    incidentRef: 'SEV-1',
    confirmation: 'BREAK GLASS'
  });
  assert.equal(request.breakGlass, true);
  request = registry.completePostReview(request.id, principal('reviewer'), {
    expectedVersion: request.version,
    outcome: 'accepted',
    reason: 'Emergency access matched the incident timeline and approved actions.'
  });
  assert.equal(request.postReview.outcome, 'accepted');
});

test('encrypted storage hides request content and tampering fails closed', async () => {
  const { registry, directory } = await setup();
  registry.requestAccess(principal('hidden'), {
    permissions: ['security:read'],
    durationMinutes: 15,
    reason: 'Sensitive investigation details must remain encrypted at rest.',
    ticketRef: 'CASE-44'
  });
  const path = resolve(directory, 'privileged-access.enc.json');
  const raw = await readFile(path, 'utf8');
  assert.equal(raw.includes('Sensitive investigation'), false);
  const envelope = JSON.parse(raw);
  envelope.ciphertext = `A${envelope.ciphertext.slice(1)}`;
  await writeFile(path, JSON.stringify(envelope));
  assert.throws(() => registry.status(), PrivilegedAccessStoreError);
});

test('observe mode reports missing grants without denying the request', async () => {
  const directory = await mkdtemp(resolve(tmpdir(), 'basitclaw-pam-observe-'));
  const registry = createPrivilegedAccessRegistry({
    mode: 'observe',
    directory,
    keys: { k1: key },
    primaryKeyId: 'k1',
    requiredAmr: ['mfa']
  });
  const observed = registry.authorise(principal('observer'), 'security:read');
  assert.equal(observed.privilegedAccess.status, 'observed');
  assert.equal(observed.privilegedAccess.enforced, false);
});

test('observe adapter does not block protected operations when its encrypted store is unavailable', () => {
  const adapter = createPrivilegedAccessAdapter({
    mode: 'observe',
    authorise() { throw new PrivilegedAccessStoreError(); }
  });
  const observed = adapter.authorise(principal('observer'), 'security:read');
  assert.equal(observed.privilegedAccess.status, 'observed');
  assert.equal(observed.privilegedAccess.reason, 'PRIVILEGED_ACCESS_STORE_UNAVAILABLE');
});

test('adapter classifies malformed privileged principals as client input errors', async () => {
  const { registry } = await setup();
  const adapter = createPrivilegedAccessAdapter(registry);
  const malformed = { ...principal('valid'), role: 'unknown-role' };
  assert.throws(() => adapter.requestAccess(malformed, {
    permissions: ['security:read'],
    durationMinutes: 15,
    reason: 'Malformed roles must not be classified as storage outages.',
    ticketRef: 'CASE-45'
  }), (error) => error.code === 'PRIVILEGED_ACCESS_INPUT_INVALID' && error.statusCode === 400);
});
