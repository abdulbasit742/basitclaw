import test from 'node:test';
import assert from 'node:assert/strict';
import { createGovernanceLedger } from '../src/services/governanceLedger.js';
import { createWorkforceAuditService, ValidationError } from '../src/services/workforceAuditService.js';

const fixedNow = () => new Date('2026-07-30T01:00:00.000Z');
const population = Array.from({ length: 20 }, (_, index) => ({
  recordId: `PAY-${String(index + 1).padStart(4, '0')}`,
  stratum: index < 5 ? 'executive' : 'staff',
  riskScore: index % 5
}));

function programmeInput(overrides = {}) {
  return {
    objective: 'Determine whether payroll changes were authorised and accurately processed.',
    controlId: 'PAY-CTRL-07',
    assertions: ['authorisation', 'accuracy', 'completeness'],
    population,
    samplingMethod: 'random',
    sampleSize: 20,
    confidenceLevel: 0.95,
    tolerableDeviationRate: 0.2,
    expectedDeviationRate: 0.01,
    reviewer: 'manager.reviewer',
    testSteps: [{
      stepId: 'AUTH-01',
      title: 'Inspect approval',
      procedure: 'Inspect the approved change request and compare it with the payroll master-file change.'
    }],
    ...overrides
  };
}

function passResult(reference = `EVD-${'a'.repeat(32)}`) {
  return {
    stepResults: [{ stepId: 'AUTH-01', outcome: 'pass', evidenceRefs: [reference], notes: 'Approval matched the processed payroll change.' }]
  };
}

test('creates reproducible programme state and actor-attributed governance evidence', () => {
  const ledger = createGovernanceLedger({ now: fixedNow });
  const service = createWorkforceAuditService({ now: fixedNow, tenantId: 'tenant-a', ledger });
  const programme = service.createTestProgramme('ENG-2026-004', programmeInput(), { actor: 'auditor.preparer' });
  assert.equal(programme.status, 'fieldwork');
  assert.equal(programme.samples.length, 20);
  assert.equal(programme.sampling.populationSize, 20);
  assert.equal(programme.preparedBy, 'auditor.preparer');
  assert.equal(service.verifyTestProgramme(programme.id).valid, true);
  assert.equal(service.exportState().testProgrammes.length, 1);
  const [event] = ledger.list('tenant-a');
  assert.equal(event.action, 'test_programme.created');
  assert.equal(event.actor, 'auditor.preparer');
  assert.equal(event.metadata.populationDigest, programme.sampling.populationDigest);
});

test('preparer and reviewer must be different identities', () => {
  const service = createWorkforceAuditService({ now: fixedNow, tenantId: 'tenant-a' });
  assert.throws(
    () => service.createTestProgramme('ENG-2026-004', programmeInput({ reviewer: 'auditor.preparer' }), { actor: 'auditor.preparer' }),
    /reviewer must be independent/
  );
});

test('retests append attempts and require an explicit reason', () => {
  const service = createWorkforceAuditService({ now: fixedNow, tenantId: 'tenant-a' });
  const programme = service.createTestProgramme('ENG-2026-004', programmeInput({ sampleSize: 2 }), { actor: 'auditor.preparer' });
  const sampleId = programme.samples[0].sampleId;
  service.recordTestResult(programme.id, sampleId, passResult(), { actor: 'auditor.tester' });
  assert.throws(() => service.recordTestResult(programme.id, sampleId, passResult(), { actor: 'auditor.tester' }), /retestReason/);
  const retested = service.recordTestResult(programme.id, sampleId, { ...passResult(), retestReason: 'Supervisor requested independent reperformance.' }, { actor: 'auditor.second' });
  assert.equal(retested.attempts.length, 2);
  assert.equal(retested.attempts[0].testedBy, 'auditor.tester');
  assert.equal(retested.attempts[1].testedBy, 'auditor.second');
});

test('complete programme reaches only the statistically derived conclusion', () => {
  const ledger = createGovernanceLedger({ now: fixedNow });
  const service = createWorkforceAuditService({ now: fixedNow, tenantId: 'tenant-a', ledger });
  const programme = service.createTestProgramme('ENG-2026-004', programmeInput(), { actor: 'auditor.preparer' });
  for (const sample of programme.samples) service.recordTestResult(programme.id, sample.sampleId, passResult(), { actor: 'auditor.tester' });
  service.submitTestProgramme(programme.id, {
    rationale: 'All selected payroll changes were tested and the evidence package is complete.',
    exceptionsEscalated: false
  }, { actor: 'auditor.preparer' });
  assert.throws(() => service.reviewTestProgramme(programme.id, {
    conclusion: 'effective', rationale: 'Independent review confirms the approved programme and evidence.',
    confirmation: `FINALISE ${programme.id} EFFECTIVE`
  }, { actor: 'different.manager' }), /Only the assigned independent reviewer/);
  const finalised = service.reviewTestProgramme(programme.id, {
    conclusion: 'effective',
    rationale: 'Independent review confirms the sampling population, execution evidence and derived conclusion.',
    confirmation: `FINALISE ${programme.id} EFFECTIVE`
  }, { actor: 'manager.reviewer' });
  assert.equal(finalised.status, 'finalised');
  assert.equal(finalised.review.conclusion, 'effective');
  assert.equal(finalised.review.metrics.deviations, 0);
  assert.equal(service.verifyTestProgramme(programme.id).valid, true);
  assert.equal(ledger.list('tenant-a').at(-1).action, 'test_programme.finalised');
});

test('placeholder evidence blocks submission for review', () => {
  const service = createWorkforceAuditService({ now: fixedNow, tenantId: 'tenant-a' });
  const programme = service.createTestProgramme('ENG-2026-004', programmeInput({ sampleSize: 1 }), { actor: 'auditor.preparer' });
  service.recordTestResult(programme.id, programme.samples[0].sampleId, passResult('PLH-ENG-2026-004-01'), { actor: 'auditor.tester' });
  assert.throws(() => service.submitTestProgramme(programme.id, {
    rationale: 'The selected item was tested but still relies on temporary evidence.',
    exceptionsEscalated: false
  }, { actor: 'auditor.preparer' }), /Placeholder evidence cannot support/);
});

test('review refuses a management-selected conclusion that differs from statistics', () => {
  const service = createWorkforceAuditService({ now: fixedNow, tenantId: 'tenant-a' });
  const programme = service.createTestProgramme('ENG-2026-004', programmeInput({ sampleSize: 10, tolerableDeviationRate: 0.1 }), { actor: 'auditor.preparer' });
  for (const [index, sample] of programme.samples.entries()) {
    const outcome = index < 2 ? 'deviation' : 'pass';
    service.recordTestResult(programme.id, sample.sampleId, {
      stepResults: [{
        stepId: 'AUTH-01', outcome,
        evidenceRefs: [`EVD-${String(index).padStart(32, 'a').slice(-32)}`],
        notes: outcome === 'deviation' ? 'Approval was missing for the processed change.' : 'Approval matched the processed change.'
      }]
    }, { actor: 'auditor.tester' });
  }
  service.submitTestProgramme(programme.id, {
    rationale: 'Testing is complete and identified deviations were escalated for review.',
    exceptionsEscalated: true
  }, { actor: 'auditor.preparer' });
  assert.throws(() => service.reviewTestProgramme(programme.id, {
    conclusion: 'effective',
    rationale: 'Management believes the control should still be described as effective.',
    confirmation: `FINALISE ${programme.id} EFFECTIVE`
  }, { actor: 'manager.reviewer' }), ValidationError);
  const finalised = service.reviewTestProgramme(programme.id, {
    conclusion: 'ineffective',
    rationale: 'The observed deviation rate exceeds the approved tolerable deviation threshold.',
    confirmation: `FINALISE ${programme.id} INEFFECTIVE`
  }, { actor: 'manager.reviewer' });
  assert.equal(finalised.review.conclusion, 'ineffective');
});
