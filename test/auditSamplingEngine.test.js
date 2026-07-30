import test from 'node:test';
import assert from 'node:assert/strict';
import { normalisePopulation, selectAuditSample, verifyAuditSample } from '../src/sampling/auditSamplingEngine.js';

const seed = '11'.repeat(32);

function population(count = 20) {
  return normalisePopulation(Array.from({ length: count }, (_, index) => ({
    sourceReference: `employee-row-${index + 1}`,
    amountMinorUnits: String((index + 1) * 100),
    stratum: index < count / 2 ? 'hourly' : 'salaried'
  }))).population;
}

test('simple random selection is deterministic and without replacement', () => {
  const entries = population();
  const first = selectAuditSample({ population: entries, method: 'simple_random', sampleSize: 7, seed });
  const second = selectAuditSample({ population: entries, method: 'simple_random', sampleSize: 7, seed });
  assert.deepEqual(second, first);
  assert.equal(new Set(first.selected.map((entry) => entry.itemHash)).size, 7);
  assert.equal(verifyAuditSample({
    population: entries,
    method: 'simple_random',
    sampleSize: 7,
    seed,
    expectedSelectionHash: first.selectionHash,
    expectedItemHashes: first.selected.map((entry) => entry.itemHash)
  }).valid, true);
});

test('systematic selection uses a deterministic bounded random start', () => {
  const result = selectAuditSample({ population: population(24), method: 'systematic', sampleSize: 6, seed });
  assert.equal(result.selected.length, 6);
  assert.equal(result.methodDetails.interval, 4);
  assert.equal(result.methodDetails.randomStartFraction >= 0 && result.methodDetails.randomStartFraction < 1, true);
  assert.equal(new Set(result.selected.map((entry) => entry.itemHash)).size, 6);
});

test('monetary-unit selection uses integer minor units and records duplicate selection points', () => {
  const result = selectAuditSample({ population: population(10), method: 'monetary_unit', sampleSize: 5, seed });
  assert.equal(result.methodDetails.populationValueMinorUnits, '5500');
  assert.equal(result.methodDetails.requestedSelectionPoints, 5);
  assert.equal(result.selected.length <= 5, true);
  assert.equal(result.selected.every((entry) => BigInt(entry.amountMinorUnits) > 0n), true);
});

test('stratified selection honours explicit allocations', () => {
  const result = selectAuditSample({
    population: population(20),
    method: 'stratified_random',
    sampleSize: 6,
    seed,
    strata: { hourly: 4, salaried: 2 }
  });
  assert.equal(result.selected.filter((entry) => entry.stratum === 'hourly').length, 4);
  assert.equal(result.selected.filter((entry) => entry.stratum === 'salaried').length, 2);
  assert.deepEqual(result.methodDetails.allocations, { hourly: 4, salaried: 2 });
});

test('population manifest is order-independent and duplicate source references are rejected', () => {
  const left = normalisePopulation([
    { sourceReference: 'row-b', amountMinorUnits: '200' },
    { sourceReference: 'row-a', amountMinorUnits: '100' }
  ]);
  const right = normalisePopulation([
    { sourceReference: 'row-a', amountMinorUnits: '100' },
    { sourceReference: 'row-b', amountMinorUnits: '200' }
  ]);
  assert.equal(left.populationRoot, right.populationRoot);
  assert.throws(() => normalisePopulation([
    { sourceReference: 'same-row' },
    { sourceReference: 'same-row' }
  ]), /unique/);
});
