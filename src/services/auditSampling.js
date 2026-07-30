import { createHash } from 'node:crypto';

const METHODS = new Set(['random', 'systematic', 'stratified']);
const CONFIDENCE_Z = new Map([
  [0.9, 1.2815515655446004],
  [0.95, 1.6448536269514722],
  [0.99, 2.3263478740408408]
]);
const RECORD_ID = /^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{0,190}$/;

export function createAuditSamplingPlan({
  tenantId,
  engagementId,
  programmeId,
  population,
  method = 'random',
  sampleSize
} = {}) {
  const selectedMethod = String(method ?? '');
  if (!METHODS.has(selectedMethod)) throw new TypeError('samplingMethod must be random, systematic, or stratified.');
  const manifest = normalisePopulation(population);
  const size = positiveInteger(sampleSize, 'sampleSize', 1, Math.min(5000, manifest.length));
  if (selectedMethod === 'stratified' && manifest.some((item) => !item.stratum)) {
    throw new TypeError('Every population record must provide a stratum for stratified sampling.');
  }
  const populationDigest = sha256(stableStringify(manifest));
  const seed = sha256([
    'basitclaw-audit-sampling-v1',
    safeIdentifier(tenantId, 'tenantId'),
    safeIdentifier(engagementId, 'engagementId'),
    safeIdentifier(programmeId, 'programmeId'),
    selectedMethod,
    String(size),
    populationDigest
  ].join('\n'));
  const selected = selectedMethod === 'random'
    ? randomSelection(manifest, size, seed)
    : selectedMethod === 'systematic'
      ? systematicSelection(manifest, size, seed)
      : stratifiedSelection(manifest, size, seed);
  return Object.freeze({
    version: 1,
    method: selectedMethod,
    sampleSize: size,
    populationSize: manifest.length,
    populationDigest,
    seed,
    manifest,
    selected: selected.map((item, index) => ({ ...item, selectionOrder: index + 1 }))
  });
}

export function verifyAuditSamplingPlan(input = {}) {
  const rebuilt = createAuditSamplingPlan(input);
  const expectedIds = rebuilt.selected.map((item) => item.recordId);
  const suppliedIds = Array.isArray(input.selectedRecordIds) ? input.selectedRecordIds.map(String) : [];
  return {
    valid: suppliedIds.length === expectedIds.length && suppliedIds.every((value, index) => value === expectedIds[index]),
    populationDigest: rebuilt.populationDigest,
    seed: rebuilt.seed,
    expectedRecordIds: expectedIds,
    suppliedRecordIds: suppliedIds
  };
}

export function wilsonUpperDeviationBound(deviations, testedItems, confidenceLevel = 0.95) {
  const n = positiveInteger(testedItems, 'testedItems', 1, 1_000_000);
  const x = nonNegativeInteger(deviations, 'deviations', n);
  const confidence = Number(confidenceLevel);
  const z = CONFIDENCE_Z.get(confidence);
  if (!z) throw new TypeError('confidenceLevel must be 0.9, 0.95, or 0.99.');
  const proportion = x / n;
  const z2 = z * z;
  const denominator = 1 + z2 / n;
  const centre = proportion + z2 / (2 * n);
  const margin = z * Math.sqrt((proportion * (1 - proportion) + z2 / (4 * n)) / n);
  return clampRate((centre + margin) / denominator);
}

export function expectedAuditConclusion({ deviations, testedItems, tolerableDeviationRate, confidenceLevel = 0.95 } = {}) {
  const n = positiveInteger(testedItems, 'testedItems', 1, 1_000_000);
  const x = nonNegativeInteger(deviations, 'deviations', n);
  const tolerance = rate(tolerableDeviationRate, 'tolerableDeviationRate');
  const observedDeviationRate = x / n;
  const upperDeviationBound = wilsonUpperDeviationBound(x, n, confidenceLevel);
  const conclusion = observedDeviationRate > tolerance
    ? 'ineffective'
    : upperDeviationBound > tolerance
      ? 'inconclusive'
      : x > 0
        ? 'effective_with_exceptions'
        : 'effective';
  return {
    conclusion,
    deviations: x,
    testedItems: n,
    observedDeviationRate: roundRate(observedDeviationRate),
    upperDeviationBound: roundRate(upperDeviationBound),
    tolerableDeviationRate: roundRate(tolerance),
    confidenceLevel: Number(confidenceLevel)
  };
}

function normalisePopulation(population) {
  if (!Array.isArray(population) || population.length === 0) throw new TypeError('population must contain at least one record.');
  if (population.length > 50_000) throw new TypeError('population cannot contain more than 50000 records.');
  const seen = new Set();
  const manifest = population.map((item, index) => {
    if (!item || typeof item !== 'object' || Array.isArray(item)) throw new TypeError(`population record ${index} must be an object.`);
    const recordId = String(item.recordId ?? '').trim();
    if (!RECORD_ID.test(recordId)) throw new TypeError(`population record ${index} has an invalid recordId.`);
    if (seen.has(recordId)) throw new TypeError(`population recordId ${recordId} is duplicated.`);
    seen.add(recordId);
    const riskScore = item.riskScore === undefined || item.riskScore === null ? 0 : Number(item.riskScore);
    if (!Number.isFinite(riskScore) || riskScore < 0 || riskScore > 100) throw new TypeError(`population record ${recordId} has an invalid riskScore.`);
    const stratum = item.stratum === undefined || item.stratum === null || item.stratum === ''
      ? null
      : cleanLabel(item.stratum, `population record ${recordId} stratum`, 1, 100);
    return { recordId, stratum, riskScore: Number(riskScore.toFixed(4)) };
  });
  return manifest.sort((left, right) => left.recordId.localeCompare(right.recordId));
}

function randomSelection(manifest, sampleSize, seed) {
  return [...manifest]
    .sort((left, right) => score(seed, left.recordId).localeCompare(score(seed, right.recordId)) || left.recordId.localeCompare(right.recordId))
    .slice(0, sampleSize);
}

function systematicSelection(manifest, sampleSize, seed) {
  const interval = manifest.length / sampleSize;
  const fraction = Number.parseInt(seed.slice(0, 13), 16) / 0x1fffffffffffff;
  const start = fraction * interval;
  return Array.from({ length: sampleSize }, (_, index) => manifest[Math.floor(start + index * interval)]);
}

function stratifiedSelection(manifest, sampleSize, seed) {
  const groups = new Map();
  for (const item of manifest) {
    const key = item.stratum;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(item);
  }
  const orderedGroups = [...groups.entries()].sort(([left], [right]) => left.localeCompare(right));
  const allocations = new Map(orderedGroups.map(([key]) => [key, 0]));
  if (sampleSize >= orderedGroups.length) {
    for (const [key] of orderedGroups) allocations.set(key, 1);
  }
  let allocated = [...allocations.values()].reduce((sum, value) => sum + value, 0);
  while (allocated < sampleSize) {
    const candidate = orderedGroups
      .filter(([key, records]) => allocations.get(key) < records.length)
      .map(([key, records]) => ({
        key,
        deficit: sampleSize * (records.length / manifest.length) - allocations.get(key),
        tie: score(seed, `stratum:${key}:${allocations.get(key)}`)
      }))
      .sort((left, right) => right.deficit - left.deficit || left.tie.localeCompare(right.tie) || left.key.localeCompare(right.key))[0];
    if (!candidate) throw new TypeError('The stratified sample allocation could not be completed.');
    allocations.set(candidate.key, allocations.get(candidate.key) + 1);
    allocated += 1;
  }
  const selected = [];
  for (const [key, records] of orderedGroups) {
    selected.push(...[...records]
      .sort((left, right) => score(seed, `${key}:${left.recordId}`).localeCompare(score(seed, `${key}:${right.recordId}`)) || left.recordId.localeCompare(right.recordId))
      .slice(0, allocations.get(key)));
  }
  return selected.sort((left, right) => score(seed, `order:${left.recordId}`).localeCompare(score(seed, `order:${right.recordId}`)) || left.recordId.localeCompare(right.recordId));
}

function score(seed, value) {
  return sha256(`${seed}\n${value}`);
}

function safeIdentifier(value, field) {
  const text = String(value ?? '').trim();
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{0,191}$/.test(text)) throw new TypeError(`${field} must be a safe identifier.`);
  return text;
}

function cleanLabel(value, field, minimum, maximum) {
  const text = String(value ?? '').trim();
  if (text.length < minimum || text.length > maximum || /[\u0000-\u001f\u007f]/.test(text)) throw new TypeError(`${field} must contain ${minimum} to ${maximum} printable characters.`);
  return text;
}

function positiveInteger(value, field, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) throw new TypeError(`${field} must be an integer from ${minimum} to ${maximum}.`);
  return parsed;
}

function nonNegativeInteger(value, field, maximum) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > maximum) throw new TypeError(`${field} must be an integer from 0 to ${maximum}.`);
  return parsed;
}

function rate(value, field) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0 || parsed > 1) throw new TypeError(`${field} must be a number from 0 to 1.`);
  return parsed;
}

function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function clampRate(value) {
  return Math.max(0, Math.min(1, value));
}

function roundRate(value) {
  return Number(value.toFixed(6));
}
