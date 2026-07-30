import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  RegulatoryCaseApprovalError,
  RegulatoryCaseIntegrityError,
  createRegulatoryCaseStore
} from '../src/regulatory/regulatoryCaseStore.js';

const tenantId = 'tenant-regulatory';
const evidenceId = `EVD-${'a'.repeat(32)}`;
const content = Buffer.from('verified regulatory response evidence');
const digest = createHash('sha256').update(content).digest('hex');
const key = Buffer.alloc(32, 112).toString('base64');

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), 'regulatory-case-'));
  let current = new Date('2026-07-30T01:00:00.000Z');
  let validEvidence = true;
  const store = createRegulatoryCaseStore({
    mode: 'shared-file',
    directory,
    encryptionKeys: { r1: key },
    encryptionPrimaryKeyId: 'r1',
    dueSoonHours: 72,
    resolveEvidence(_tenant, selection) {
      if (!validEvidence) return { evidenceId: selection.evidenceId, version: selection.version, contentSha256: 'f'.repeat(64), sizeBytes: content.length, filename: 'response.txt', mediaType: 'text/plain' };
      return { evidenceId, version: 1, contentSha256: digest, sizeBytes: content.length, filename: 'response.txt', mediaType: 'text/plain' };
    },
    now: () => new Date(current)
  });
  return { store, directory, setNow: (value) => { current = new Date(value); }, invalidateEvidence: () => { validEvidence = false; } };
}

function createInput(overrides = {}) {
  return {
    type: 'regulator_request',
    priority: 'high',
    authority: 'National Labour Regulator',
    jurisdiction: 'PK-Federal',
    requestReference: 'NLR-2026-0042',
    legalBasis: 'Statutory workforce record inspection',
    summary: 'Provide verified payroll-control records for the stated review period.',
    receivedAt: '2026-07-30T00:00:00.000Z',
    dueAt: '2026-08-01T00:00:00.000Z',
    owner: 'audit.manager',
    evidence: [{ evidenceId, version: 1 }],
    ...overrides
  };
}

function create(store, overrides = {}) {
  return store.createCase(tenantId, createInput(overrides), { actor: 'audit.manager' }).case;
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

test('stores cases encrypted and reports due-soon and overdue posture', () => {
  const { store, directory, setNow } = fixture();
  const record = create(store);
  assert.equal(record.deadlineState, 'due_soon');
  assert.equal(store.tenantStatus(tenantId).dueSoon, 1);
  const raw = filesUnder(directory).map((path) => readFileSync(path, 'utf8')).join('\n');
  for (const value of [tenantId, evidenceId, 'National Labour Regulator', 'NLR-2026-0042']) assert.equal(raw.includes(value), false);
  setNow('2026-08-02T00:00:00.000Z');
  assert.equal(store.get(tenantId, record.caseId).deadlineState, 'overdue');
  assert.equal(store.tenantStatus(tenantId).overdue, 1);
});

test('enforces submitter, approver and closer separation with exact confirmations', () => {
  const { store } = fixture();
  const record = create(store);
  const submitted = store.submitResponse(tenantId, record.caseId, {
    responseReference: 'RESP-2026-0042',
    responseSummary: 'Verified evidence assembled and response prepared for the authority.',
    confirmation: `SUBMIT RESPONSE ${record.caseId}`
  }, { actor: 'audit.manager' });
  assert.equal(submitted.state, 'response_pending');
  assert.throws(() => store.approveResponse(tenantId, record.caseId, {
    reason: 'Response independently reviewed and approved',
    confirmation: `APPROVE RESPONSE ${record.caseId}`
  }, { actor: 'audit.manager' }), RegulatoryCaseApprovalError);
  const approved = store.approveResponse(tenantId, record.caseId, {
    reason: 'Response independently reviewed and approved',
    confirmation: `APPROVE RESPONSE ${record.caseId}`
  }, { actor: 'compliance.admin' });
  assert.equal(approved.state, 'response_approved');
  assert.throws(() => store.closeCase(tenantId, record.caseId, {
    reason: 'Authority confirmed receipt and no further action is pending',
    confirmation: `CLOSE CASE ${record.caseId}`
  }, { actor: 'compliance.admin' }), RegulatoryCaseApprovalError);
  const closed = store.closeCase(tenantId, record.caseId, {
    reason: 'Authority confirmed receipt and no further action is pending',
    confirmation: `CLOSE CASE ${record.caseId}`
  }, { actor: 'case.closer' });
  assert.equal(closed.state, 'closed');
  assert.equal(closed.deadlineState, 'complete');
});

test('revalidates immutable evidence before submission and approval', () => {
  const { store, invalidateEvidence } = fixture();
  const record = create(store);
  invalidateEvidence();
  assert.throws(() => store.submitResponse(tenantId, record.caseId, {
    responseReference: 'RESP-2026-0042',
    responseSummary: 'Response should not submit after evidence identity changes.',
    confirmation: `SUBMIT RESPONSE ${record.caseId}`
  }, { actor: 'audit.manager' }));
  assert.equal(store.get(tenantId, record.caseId).state, 'open');
});

test('duplicate case identity is idempotent and tenant isolation is preserved', () => {
  const { store } = fixture();
  const first = store.createCase(tenantId, createInput(), { actor: 'audit.manager' });
  const second = store.createCase(tenantId, createInput(), { actor: 'other.actor' });
  assert.equal(second.duplicate, true);
  assert.equal(second.case.caseId, first.case.caseId);
  assert.equal(store.list('tenant-other').length, 0);
});

test('tampered encrypted indexes fail closed', () => {
  const { store, directory } = fixture();
  create(store);
  const path = filesUnder(directory).find((entry) => entry.endsWith('.evidence'));
  const envelope = JSON.parse(readFileSync(path, 'utf8'));
  envelope.ciphertext = envelope.ciphertext.replace(/^./, envelope.ciphertext[0] === 'A' ? 'B' : 'A');
  writeFileSync(path, JSON.stringify(envelope));
  assert.throws(() => store.verifyTenant(tenantId), RegulatoryCaseIntegrityError);
});
