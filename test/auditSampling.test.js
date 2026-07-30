import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createAuditSamplingPlan,
  expectedAuditConclusion,
  verifyAuditSamplingPlan,
  wilsonUpperDeviationBound
} from '../src/services/auditSampling.js';

const population = Array.from({ length: 40 }, (_, index) => ({
  recordId: `PAY-${String(index + 1).padStart(4, '0')}`,
  stratum: index < 10 ? 'executive' : index < 25 ? 'monthly' : 'hourly',
  riskScore: index % 7
}));

function plan(input = {}) {
  return createAuditSamplingPlan({
    tenantId: 'tenant-a',
    engagementId: 'ENG-2026-004',
    programmeId: 'TPG-2026-0001',
    population,
    method: 'random',
    sampleSize: 10,
    ...input
  });
}

test('random sample is reproducible and independent of population input order', () => {
  const first = plan();
  const second = plan({ population: [...population].reverse() });
  assert.deepEqual(first.selected.map((item) => item.recordId), second.selected.map((item) => item.recordId));
  assert.equal(first.populationDigest, second.populationDigest);
  assert.equal(first.seed, second.seed);
  assert.equal(new Set(first.selected.map((item) => item.recordId)).size, 10);
});

test('systematic sampling selects the requested number without duplicates', () => {
  const result = plan({ method: 'systematic', sampleSize: 13 });
  assert.equal(result.selected.length, 13);
  assert.equal(new Set(result.selected.map((item) => item.recordId)).size, 13);
});

test('stratified sampling represents every stratum when sample size permits', () => {
  const result = plan({ method: 'stratified', sampleSize: 9 });
  assert.deepEqual([...new Set(result.selected.map((item) => item.stratum))].sort(), ['executive', 'hourly', 'monthly']);
  assert.equal(result.selected.length, 9);
});

test('sampling verification detects altered selected-record order', () => {
  const created = plan();
  const valid = verifyAuditSamplingPlan({
    tenantId: 'tenant-a', engagementId: 'ENG-2026-004', programmeId: 'TPG-2026-0001',
    population, method: 'random', sampleSize: 10,
    selectedRecordIds: created.selected.map((item) => item.recordId)
  });
  assert.equal(valid.valid, true);
  const tampered = verifyAuditSamplingPlan({
    tenantId: 'tenant-a', engagementId: 'ENG-2026-004', programmeId: 'TPG-2026-0001',
    population, method: 'random', sampleSize: 10,
    selectedRecordIds: created.selected.map((item) => item.recordId).reverse()
  });
  assert.equal(tampered.valid, false);
});

test('Wilson bound and derived conclusion fail conservatively on small samples', () => {
  const upper = wilsonUpperDeviationBound(0, 10, 0.95);
  assert.ok(upper > 0.2);
  const result = expectedAuditConclusion({ deviations: 0, testedItems: 10, tolerableDeviationRate: 0.1, confidenceLevel: 0.95 });
  assert.equal(result.conclusion, 'inconclusive');
  assert.equal(result.observedDeviationRate, 0);
});

test('observed deviations above tolerance produce an ineffective conclusion', () => {
  const result = expectedAuditConclusion({ deviations: 3, testedItems: 20, tolerableDeviationRate: 0.1, confidenceLevel: 0.95 });
  assert.equal(result.conclusion, 'ineffective');
  assert.equal(result.observedDeviationRate, 0.15);
});
