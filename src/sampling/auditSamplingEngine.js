import { createHmac, createHash } from 'node:crypto';

const METHODS = new Set(['simple_random', 'systematic', 'monetary_unit', 'stratified_random']);
const HASH = /^[a-f0-9]{64}$/;

export class AuditSamplingValidationError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = 'AuditSamplingValidationError';
    this.code = 'AUDIT_SAMPLING_VALIDATION_FAILED';
    this.statusCode = 400;
    this.details = details;
  }
}

export function normalisePopulation(entries, { maximumItems = 100_000 } = {}) {
  if (!Array.isArray(entries) || entries.length < 1 || entries.length > maximumItems) {
    throw new AuditSamplingValidationError(`population must contain 1 to ${maximumItems} entries.`, { field: 'population' });
  }
  const references = new Set();
  const population = entries.map((entry, index) => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      throw new AuditSamplingValidationError('Each population entry must be an object.', { index });
    }
    const sourceReference = cleanText(entry.sourceReference, 'sourceReference', 1, 500, index);
    if (references.has(sourceReference)) throw new AuditSamplingValidationError('Population source references must be unique.', { index });
    references.add(sourceReference);
    const amountMinorUnits = entry.amountMinorUnits === undefined || entry.amountMinorUnits === null
      ? null
      : nonNegativeIntegerString(entry.amountMinorUnits, 'amountMinorUnits', index);
    const stratum = entry.stratum === undefined || entry.stratum === null
      ? null
      : cleanText(entry.stratum, 'stratum', 1, 100, index);
    return Object.freeze({
      sourceReference,
      itemHash: sha256(sourceReference),
      amountMinorUnits,
      stratum
    });
  });
  population.sort((left, right) => left.itemHash.localeCompare(right.itemHash));
  const populationRoot = sha256(stableStringify(population.map(({ itemHash, amountMinorUnits, stratum }) => ({ itemHash, amountMinorUnits, stratum }))));
  const populationValueMinorUnits = population.reduce((sum, entry) => sum + BigInt(entry.amountMinorUnits ?? 0), 0n).toString();
  return Object.freeze({ population, populationRoot, populationCount: population.length, populationValueMinorUnits });
}

export function selectAuditSample({ population, method, sampleSize, seed, strata = null } = {}) {
  if (!Array.isArray(population) || !population.length) throw new AuditSamplingValidationError('A normalised population is required.');
  const selectedMethod = String(method ?? '');
  if (!METHODS.has(selectedMethod)) throw new AuditSamplingValidationError(`method must be one of ${[...METHODS].join(', ')}.`, { field: 'method' });
  const size = integer(sampleSize, 'sampleSize', 1, population.length);
  const seedBytes = seedBuffer(seed);
  let selected;
  let methodDetails;
  if (selectedMethod === 'simple_random') {
    selected = sampleWithoutReplacement(population, size, seedBytes, 'simple-random');
    methodDetails = { replacement: false };
  } else if (selectedMethod === 'systematic') {
    ({ selected, methodDetails } = systematic(population, size, seedBytes));
  } else if (selectedMethod === 'monetary_unit') {
    ({ selected, methodDetails } = monetaryUnit(population, size, seedBytes));
  } else {
    ({ selected, methodDetails } = stratified(population, size, seedBytes, strata));
  }
  return Object.freeze({
    method: selectedMethod,
    sampleSize: selected.length,
    selected: selected.map((entry, position) => Object.freeze({
      position: position + 1,
      itemHash: entry.itemHash,
      amountMinorUnits: entry.amountMinorUnits,
      stratum: entry.stratum
    })),
    methodDetails,
    selectionHash: sha256(stableStringify(selected.map((entry) => entry.itemHash)))
  });
}

export function verifyAuditSample({ population, method, sampleSize, seed, strata, expectedSelectionHash, expectedItemHashes } = {}) {
  const generated = selectAuditSample({ population, method, sampleSize, seed, strata });
  if (expectedSelectionHash && !HASH.test(String(expectedSelectionHash))) throw new AuditSamplingValidationError('expectedSelectionHash is invalid.');
  const hashMatches = expectedSelectionHash ? generated.selectionHash === expectedSelectionHash : true;
  const itemsMatch = expectedItemHashes
    ? stableStringify(generated.selected.map((entry) => entry.itemHash)) === stableStringify(expectedItemHashes)
    : true;
  return Object.freeze({ valid: hashMatches && itemsMatch, hashMatches, itemsMatch, generated });
}

function sampleWithoutReplacement(population, size, seed, domain) {
  const indexes = population.map((_, index) => index);
  const random = deterministicRandom(seed, domain);
  for (let index = indexes.length - 1; index > 0; index -= 1) {
    const swap = random.integer(index + 1);
    [indexes[index], indexes[swap]] = [indexes[swap], indexes[index]];
  }
  return indexes.slice(0, size).map((index) => population[index]);
}

function systematic(population, size, seed) {
  const interval = population.length / size;
  const random = deterministicRandom(seed, 'systematic');
  const startFraction = random.fraction();
  const indexes = [];
  for (let position = 0; position < size; position += 1) {
    indexes.push(Math.min(population.length - 1, Math.floor((startFraction + position) * interval)));
  }
  return {
    selected: indexes.map((index) => population[index]),
    methodDetails: { interval, randomStartFraction: startFraction, replacement: false }
  };
}

function monetaryUnit(population, size, seed) {
  const amounts = population.map((entry, index) => {
    const amount = BigInt(entry.amountMinorUnits ?? 0);
    if (amount < 0n) throw new AuditSamplingValidationError('Monetary-unit amounts cannot be negative.', { index });
    return amount;
  });
  const total = amounts.reduce((sum, amount) => sum + amount, 0n);
  if (total <= 0n) throw new AuditSamplingValidationError('monetary_unit requires a positive population value.', { field: 'population' });
  if (BigInt(size) > total) throw new AuditSamplingValidationError('sampleSize cannot exceed total minor monetary units.', { sampleSize: size, total: total.toString() });
  const random = deterministicRandom(seed, 'monetary-unit');
  const interval = total / BigInt(size);
  if (interval < 1n) throw new AuditSamplingValidationError('The monetary-unit interval is below one minor unit.');
  const start = BigInt(random.integer(Number(interval > BigInt(Number.MAX_SAFE_INTEGER) ? BigInt(Number.MAX_SAFE_INTEGER) : interval))) + 1n;
  const selected = [];
  const selectedHashes = new Set();
  let cumulative = 0n;
  let populationIndex = 0;
  for (let pointIndex = 0; pointIndex < size; pointIndex += 1) {
    const point = start + BigInt(pointIndex) * interval;
    while (populationIndex < population.length - 1 && cumulative + amounts[populationIndex] < point) {
      cumulative += amounts[populationIndex];
      populationIndex += 1;
    }
    const entry = population[populationIndex];
    if (!selectedHashes.has(entry.itemHash)) {
      selectedHashes.add(entry.itemHash);
      selected.push(entry);
    }
  }
  return {
    selected,
    methodDetails: {
      intervalMinorUnits: interval.toString(),
      randomStartMinorUnits: start.toString(),
      populationValueMinorUnits: total.toString(),
      requestedSelectionPoints: size,
      uniqueItemsSelected: selected.length,
      replacementByMonetaryUnit: true
    }
  };
}

function stratified(population, size, seed, rawStrata) {
  const groups = new Map();
  for (const entry of population) {
    if (!entry.stratum) throw new AuditSamplingValidationError('stratified_random requires every population entry to have a stratum.');
    if (!groups.has(entry.stratum)) groups.set(entry.stratum, []);
    groups.get(entry.stratum).push(entry);
  }
  const allocations = allocateStrata(groups, size, rawStrata);
  const selected = [];
  for (const [stratum, allocation] of [...allocations.entries()].sort(([left], [right]) => left.localeCompare(right))) {
    selected.push(...sampleWithoutReplacement(groups.get(stratum), allocation, seed, `stratum:${stratum}`));
  }
  return {
    selected,
    methodDetails: {
      replacement: false,
      allocations: Object.fromEntries(allocations),
      strataCount: allocations.size
    }
  };
}

function allocateStrata(groups, totalSize, rawStrata) {
  if (rawStrata !== null && rawStrata !== undefined) {
    if (!rawStrata || typeof rawStrata !== 'object' || Array.isArray(rawStrata)) throw new AuditSamplingValidationError('strata must be an allocation object.');
    const allocations = new Map();
    let sum = 0;
    for (const [stratum, entries] of groups) {
      const allocation = integer(rawStrata[stratum], `strata.${stratum}`, 0, entries.length);
      allocations.set(stratum, allocation);
      sum += allocation;
    }
    for (const key of Object.keys(rawStrata)) if (!groups.has(key)) throw new AuditSamplingValidationError('strata contains an unknown stratum.', { stratum: key });
    if (sum !== totalSize) throw new AuditSamplingValidationError('Stratum allocations must equal sampleSize.', { allocated: sum, sampleSize: totalSize });
    return allocations;
  }
  const allocations = new Map();
  const remainders = [];
  let allocated = 0;
  for (const [stratum, entries] of groups) {
    const exact = entries.length * totalSize / [...groups.values()].reduce((sum, values) => sum + values.length, 0);
    const base = Math.min(entries.length, Math.floor(exact));
    allocations.set(stratum, base);
    allocated += base;
    remainders.push({ stratum, remainder: exact - base, capacity: entries.length - base });
  }
  remainders.sort((left, right) => right.remainder - left.remainder || left.stratum.localeCompare(right.stratum));
  while (allocated < totalSize) {
    const candidate = remainders.find((entry) => entry.capacity > 0);
    if (!candidate) throw new AuditSamplingValidationError('The requested sample cannot be allocated across strata.');
    allocations.set(candidate.stratum, allocations.get(candidate.stratum) + 1);
    candidate.capacity -= 1;
    allocated += 1;
  }
  return allocations;
}

function deterministicRandom(seed, domain) {
  let counter = 0;
  let pool = Buffer.alloc(0);
  function bytes(length) {
    while (pool.length < length) {
      const block = createHmac('sha256', seed).update(domain).update(':').update(String(counter)).digest();
      counter += 1;
      pool = Buffer.concat([pool, block]);
    }
    const result = pool.subarray(0, length);
    pool = pool.subarray(length);
    return result;
  }
  function integer(maximumExclusive) {
    if (!Number.isSafeInteger(maximumExclusive) || maximumExclusive < 1) throw new TypeError('maximumExclusive must be a positive safe integer.');
    const range = 2 ** 32;
    const limit = range - (range % maximumExclusive);
    let value;
    do { value = bytes(4).readUInt32BE(0); } while (value >= limit);
    return value % maximumExclusive;
  }
  return {
    integer,
    fraction() { return bytes(6).readUIntBE(0, 6) / 2 ** 48; }
  };
}

function seedBuffer(seed) {
  if (Buffer.isBuffer(seed) && seed.length >= 32) return Buffer.from(seed);
  const text = String(seed ?? '');
  if (/^[a-f0-9]{64,}$/.test(text) && text.length % 2 === 0) return Buffer.from(text, 'hex');
  throw new AuditSamplingValidationError('seed must contain at least 32 cryptographic bytes.', { field: 'seed' });
}
function integer(value, field, minimum, maximum) { const number = Number(value); if (!Number.isInteger(number) || number < minimum || number > maximum) throw new AuditSamplingValidationError(`${field} must be an integer from ${minimum} to ${maximum}.`, { field }); return number; }
function nonNegativeIntegerString(value, field, index) { const text = String(value); if (!/^(0|[1-9][0-9]*)$/.test(text)) throw new AuditSamplingValidationError(`${field} must be a non-negative integer string.`, { field, index }); return BigInt(text).toString(); }
function cleanText(value, field, minimum, maximum, index) { const text = String(value ?? '').trim(); if (text.length < minimum || text.length > maximum) throw new AuditSamplingValidationError(`${field} must contain ${minimum} to ${maximum} characters.`, { field, index }); return text; }
function sha256(value) { return createHash('sha256').update(value).digest('hex'); }
function stableStringify(value) { if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`; if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`; return JSON.stringify(value); }
