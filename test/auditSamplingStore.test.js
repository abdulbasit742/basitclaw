import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createAuditSamplingStore, AuditSamplingIntegrityError } from '../src/sampling/auditSamplingStore.js';
import { createAuditSamplingRegistry } from '../src/sampling/auditSamplingRegistry.js';

const tenantId = 'tenant-sampling';
const evidenceId = `EVD-${'a'.repeat(32)}`;
const digest = 'b'.repeat(64);
const key = Buffer.alloc(32, 67).toString('base64');

function storeFixture() {
  const directory = mkdtempSync(join(tmpdir(), 'audit-sampling-'));
  let clock = new Date('2026-07-30T04:00:00.000Z');
  const store = createAuditSamplingStore({
    mode: 'shared-file', directory,
    keys: { sampling: key }, primaryKeyId: 'sampling',
    now: () => new Date(clock)
  });
  return { store, directory, tick() { clock = new Date(clock.getTime() + 60_000); } };
}

function population(count = 12) {
  return Array.from({ length: count }, (_, index) => ({
    sourceReference: `payroll-row-${index + 1}`,
    amountMinorUnits: String((index + 1) * 100),
    stratum: index < 6 ? 'hourly' : 'salaried'
  }));
}

function createInput(overrides = {}) {
  return {
    tenantId,
    engagementId: 'ENG-2026-payroll',
    objective: 'Test payroll completeness and authorised compensation changes',
    rationale: 'Select a reproducible sample across the complete registered payroll population.',
    evidenceId,
    evidenceVersion: 1,
    evidenceContentSha256: digest,
    idempotencyKey: 'payroll-sample-2026-001',
    method: 'simple_random',
    sampleSize: 5,
    population: population(),
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

test('encrypts source references and reveals the seed only after independent approval', () => {
  const { store, directory, tick } = storeFixture();
  const created = store.create(createInput(), { actor: 'auditor.one' });
  assert.equal(created.plan.status, 'draft');
  assert.equal(created.plan.seedReveal, null);
  assert.equal(created.plan.selection, null);
  const raw = filesUnder(directory).map((path) => readFileSync(path, 'utf8')).join('\n');
  assert.equal(raw.includes('payroll-row-1'), false);
  assert.equal(raw.includes(tenantId), false);
  tick();
  assert.throws(() => store.approve(tenantId, created.plan.planId, {
    confirmation: `APPROVE SAMPLE ${created.plan.planId}`
  }, { actor: 'auditor.one' }), /preparer cannot approve/);
  const approved = store.approve(tenantId, created.plan.planId, {
    confirmation: `APPROVE SAMPLE ${created.plan.planId}`
  }, { actor: 'manager.one' });
  assert.equal(approved.plan.status, 'approved');
  assert.match(approved.plan.seedReveal, /^[a-f0-9]{64}$/);
  assert.equal(approved.plan.selection.selected.length, 5);
  assert.equal(approved.plan.events.some((event) => JSON.stringify(event).includes(approved.plan.seedReveal)), false);
  assert.equal(store.verify(tenantId, created.plan.planId).selectionValid, true);
});

test('idempotency is stable and approved plans cannot be cancelled', () => {
  const { store } = storeFixture();
  const first = store.create(createInput(), { actor: 'auditor.one' });
  const duplicate = store.create(createInput(), { actor: 'auditor.two' });
  assert.equal(duplicate.duplicate, true);
  assert.equal(duplicate.plan.planId, first.plan.planId);
  store.approve(tenantId, first.plan.planId, { confirmation: `APPROVE SAMPLE ${first.plan.planId}` }, { actor: 'manager.one' });
  assert.throws(() => store.cancel(tenantId, first.plan.planId, {
    confirmation: `CANCEL SAMPLE ${first.plan.planId}`,
    reason: 'The audit scope has been withdrawn by governance.'
  }, { actor: 'manager.two' }), /immutable/);
});

test('draft cancellation is governed and exact confirmation is required', () => {
  const { store } = storeFixture();
  const created = store.create(createInput(), { actor: 'auditor.one' });
  assert.throws(() => store.cancel(tenantId, created.plan.planId, {
    confirmation: 'wrong', reason: 'The approved audit scope has materially changed.'
  }, { actor: 'manager.one' }), /confirmation/);
  const cancelled = store.cancel(tenantId, created.plan.planId, {
    confirmation: `CANCEL SAMPLE ${created.plan.planId}`,
    reason: 'The approved audit scope has materially changed.'
  }, { actor: 'manager.one' });
  assert.equal(cancelled.plan.status, 'cancelled');
});

test('ciphertext tampering and cross-tenant access fail closed', () => {
  const { store, directory } = storeFixture();
  const created = store.create(createInput(), { actor: 'auditor.one' });
  assert.throws(() => store.get('tenant-other', created.plan.planId), /does not exist/);
  const planPath = filesUnder(directory).find((path) => path.endsWith('.plan'));
  const envelope = JSON.parse(readFileSync(planPath, 'utf8'));
  envelope.ciphertext = envelope.ciphertext.replace(/^./, envelope.ciphertext[0] === 'A' ? 'B' : 'A');
  writeFileSync(planPath, JSON.stringify(envelope));
  assert.throws(() => store.verify(tenantId, created.plan.planId), AuditSamplingIntegrityError);
});

test('registry revalidates immutable evidence binding before approval', () => {
  const { store } = storeFixture();
  let currentDigest = digest;
  const base = {
    enabled: true,
    get(requestTenant, requestedEvidenceId) {
      assert.equal(requestTenant, tenantId);
      assert.equal(requestedEvidenceId, evidenceId);
      return { evidenceId, status: 'active', currentVersion: 1, versions: [{ version: 1, sha256: currentDigest }] };
    },
    screeningReport() { return { status: 'clean', version: 1 }; },
    verify() { return { valid: true }; },
    health() { return { status: 'ready' }; },
    tenantStatus() { return { status: 'ready' }; }
  };
  const registry = createAuditSamplingRegistry({ registry: base, sampling: store });
  const created = registry.createSamplingPlan(tenantId, {
    ...createInput(),
    evidenceContentSha256: undefined
  }, { actor: 'auditor.one' });
  currentDigest = 'c'.repeat(64);
  assert.throws(() => registry.approveSamplingPlan(tenantId, created.plan.planId, {
    confirmation: `APPROVE SAMPLE ${created.plan.planId}`
  }, { actor: 'manager.one' }), /binding is no longer valid/);
});
