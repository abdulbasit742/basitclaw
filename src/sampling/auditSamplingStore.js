import { randomBytes } from 'node:crypto';
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  writeFileSync
} from 'node:fs';
import { dirname, resolve } from 'node:path';
import { createFileMutex } from '../security/fileMutex.js';
import {
  decryptEvidenceJson,
  encryptEvidenceJson,
  parseEvidenceKeyring,
  readEvidenceJson,
  sha256
} from '../evidence/evidenceCrypto.js';
import { EvidenceConflictError, EvidenceIntegrityError, EvidenceStoreError, EvidenceValidationError } from '../evidence/evidenceRegistry.js';
import { AuditSamplingValidationError, normalisePopulation, selectAuditSample } from './auditSamplingEngine.js';

const RECORD_FORMAT = 'basitclaw-audit-sampling-plan-v1';
const PLAN_ID = /^SMP-[a-f0-9]{32}$/;
const EVIDENCE_ID = /^EVD-[a-f0-9]{32}$/;
const HASH = /^[a-f0-9]{64}$/;
const MODES = new Set(['disabled', 'shared-file']);
const STATUSES = new Set(['draft', 'approved', 'cancelled']);

export class AuditSamplingStoreError extends EvidenceStoreError {
  constructor(message = 'The audit sampling store is unavailable.', details = {}, cause = null) {
    super(message, details, cause);
    this.name = 'AuditSamplingStoreError';
    this.code = 'AUDIT_SAMPLING_STORE_UNAVAILABLE';
  }
}

export class AuditSamplingIntegrityError extends EvidenceIntegrityError {
  constructor(message = 'Audit sampling integrity verification failed.', details = {}, cause = null) {
    super(message, details, cause);
    this.name = 'AuditSamplingIntegrityError';
    this.code = 'AUDIT_SAMPLING_INTEGRITY_FAILED';
  }
}

export function createAuditSamplingStore({
  mode = 'disabled',
  directory,
  keys,
  primaryKeyId,
  maximumPopulationItems = 100_000,
  maximumPlansPerTenant = 10_000,
  now = () => new Date(),
  mutex = null
} = {}) {
  const selectedMode = enumValue(mode, MODES, 'mode');
  if (selectedMode === 'disabled') return disabledStore();
  if (!String(directory ?? '').trim()) throw new TypeError('An audit sampling directory is required.');
  const root = resolve(String(directory));
  const keyring = parseEvidenceKeyring(keys, primaryKeyId);
  const populationLimit = integer(maximumPopulationItems, 'maximumPopulationItems', 1, 1_000_000);
  const planLimit = integer(maximumPlansPerTenant, 'maximumPlansPerTenant', 1, 100_000);
  const lock = mutex ?? createFileMutex({ directory: resolve(root, '.locks'), now });
  mkdirSync(root, { recursive: true, mode: 0o700 });

  function create(input, context = {}) {
    const request = validateCreateInput(input, context);
    const normalised = normalisePopulation(request.population, { maximumItems: populationLimit });
    const planId = `SMP-${sha256([
      request.tenantId,
      request.engagementId,
      request.evidenceId,
      String(request.evidenceVersion),
      request.idempotencyKey
    ].join('|')).slice(0, 32)}`;
    const createdAt = validNow(now);
    const path = planPath(request.tenantId, planId);

    return lock.withLock(`audit-sampling:${request.tenantId}`, () => {
      if (existsSync(path)) {
        const existing = readPlan(path, request.tenantId, planId);
        assertIdempotent(existing, request, normalised);
        return { created: false, duplicate: true, plan: publicPlan(existing) };
      }
      const tenantFiles = planNames(tenantDirectory(request.tenantId));
      if (tenantFiles.length >= planLimit) throw new EvidenceConflictError('The tenant audit sampling plan limit has been reached.', { maximumPlansPerTenant: planLimit });
      const seed = randomBytes(32).toString('hex');
      const record = {
        format: RECORD_FORMAT,
        version: 1,
        planId,
        tenantId: request.tenantId,
        engagementId: request.engagementId,
        objective: request.objective,
        rationale: request.rationale,
        evidenceId: request.evidenceId,
        evidenceVersion: request.evidenceVersion,
        evidenceContentSha256: request.evidenceContentSha256,
        idempotencyKey: request.idempotencyKey,
        method: request.method,
        requestedSampleSize: request.sampleSize,
        strata: request.strata,
        population: normalised.population,
        populationRoot: normalised.populationRoot,
        populationCount: normalised.populationCount,
        populationValueMinorUnits: normalised.populationValueMinorUnits,
        seed,
        seedCommitment: sha256(seed),
        status: 'draft',
        preparedBy: request.actor,
        createdAt: createdAt.toISOString(),
        approvedBy: null,
        approvedAt: null,
        cancelledBy: null,
        cancelledAt: null,
        cancellationReason: null,
        selection: null,
        events: []
      };
      record.events.push(eventFor(record, 'plan.created', request.actor, createdAt.toISOString(), {
        populationRoot: record.populationRoot,
        populationCount: record.populationCount,
        method: record.method,
        requestedSampleSize: record.requestedSampleSize,
        seedCommitment: record.seedCommitment
      }));
      writePlan(path, record);
      return { created: true, duplicate: false, plan: publicPlan(record) };
    });
  }

  function approve(tenantId, planId, input = {}, context = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = planIdentifier(planId);
    const actor = identifier(context.actor, 'actor');
    if (input?.confirmation !== `APPROVE SAMPLE ${id}`) {
      throw new EvidenceValidationError(`confirmation must be exactly APPROVE SAMPLE ${id}.`, { field: 'confirmation' });
    }
    return lock.withLock(`audit-sampling:${tenant}`, () => {
      const path = planPath(tenant, id);
      const record = readPlan(path, tenant, id);
      if (record.status === 'approved') return { approved: false, duplicate: true, plan: publicPlan(record) };
      if (record.status !== 'draft') throw new EvidenceConflictError('Only draft sampling plans can be approved.', { planId: id, status: record.status });
      if (record.preparedBy === actor) throw new EvidenceConflictError('The sampling-plan preparer cannot approve the same plan.', { planId: id });
      const selected = selectAuditSample({
        population: record.population,
        method: record.method,
        sampleSize: record.requestedSampleSize,
        seed: record.seed,
        strata: record.strata
      });
      const approvedAt = validNow(now).toISOString();
      record.status = 'approved';
      record.approvedBy = actor;
      record.approvedAt = approvedAt;
      record.selection = selected;
      record.events.push(eventFor(record, 'plan.approved', actor, approvedAt, {
        selectionHash: selected.selectionHash,
        selectedItems: selected.selected.length,
        seedReveal: record.seed
      }));
      writePlanAtomic(path, record);
      return { approved: true, duplicate: false, plan: publicPlan(record) };
    });
  }

  function cancel(tenantId, planId, input = {}, context = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = planIdentifier(planId);
    const actor = identifier(context.actor, 'actor');
    const reason = cleanText(input?.reason, 'reason', 10, 500);
    if (input?.confirmation !== `CANCEL SAMPLE ${id}`) {
      throw new EvidenceValidationError(`confirmation must be exactly CANCEL SAMPLE ${id}.`, { field: 'confirmation' });
    }
    return lock.withLock(`audit-sampling:${tenant}`, () => {
      const path = planPath(tenant, id);
      const record = readPlan(path, tenant, id);
      if (record.status === 'cancelled') return { cancelled: false, duplicate: true, plan: publicPlan(record) };
      if (record.status === 'approved') throw new EvidenceConflictError('Approved sampling plans are immutable and cannot be cancelled.', { planId: id });
      const cancelledAt = validNow(now).toISOString();
      record.status = 'cancelled';
      record.cancelledBy = actor;
      record.cancelledAt = cancelledAt;
      record.cancellationReason = reason;
      record.events.push(eventFor(record, 'plan.cancelled', actor, cancelledAt, { reasonCode: 'governed_cancellation' }));
      writePlanAtomic(path, record);
      return { cancelled: true, duplicate: false, plan: publicPlan(record) };
    });
  }

  function get(tenantId, planId) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = planIdentifier(planId);
    return lock.withLock(`audit-sampling:${tenant}`, () => publicPlan(readPlan(planPath(tenant, id), tenant, id)));
  }

  function list(tenantId, { engagementId = null, status = null, limit = 500 } = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const engagement = engagementId === null ? null : identifier(engagementId, 'engagementId');
    const selectedStatus = status === null ? null : enumValue(status, STATUSES, 'status');
    const requestedLimit = integer(limit, 'limit', 1, 5000);
    return lock.withLock(`audit-sampling:${tenant}`, () => planNames(tenantDirectory(tenant))
      .map((name) => readPlan(resolve(tenantDirectory(tenant), name), tenant, name.slice(0, -5)))
      .filter((plan) => !engagement || plan.engagementId === engagement)
      .filter((plan) => !selectedStatus || plan.status === selectedStatus)
      .sort((left, right) => right.createdAt.localeCompare(left.createdAt))
      .slice(0, requestedLimit)
      .map(publicPlan));
  }

  function verify(tenantId, planId) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = planIdentifier(planId);
    return lock.withLock(`audit-sampling:${tenant}`, () => verifyRecord(readPlan(planPath(tenant, id), tenant, id)));
  }

  function verifyTenant(tenantId) {
    const tenant = identifier(tenantId, 'tenantId');
    return lock.withLock(`audit-sampling:${tenant}`, () => {
      let approvedPlans = 0;
      const names = planNames(tenantDirectory(tenant));
      for (const name of names) {
        const result = verifyRecord(readPlan(resolve(tenantDirectory(tenant), name), tenant, name.slice(0, -5)));
        if (result.status === 'approved') approvedPlans += 1;
      }
      return { valid: true, tenantId: tenant, checkedPlans: names.length, approvedPlans };
    });
  }

  function status(tenantId) {
    const tenant = identifier(tenantId, 'tenantId');
    try {
      const records = planNames(tenantDirectory(tenant)).map((name) => readPlan(resolve(tenantDirectory(tenant), name), tenant, name.slice(0, -5)));
      return {
        status: 'ready',
        enabled: true,
        plans: records.length,
        drafts: records.filter((plan) => plan.status === 'draft').length,
        approved: records.filter((plan) => plan.status === 'approved').length,
        cancelled: records.filter((plan) => plan.status === 'cancelled').length,
        sourceReferencesPublic: false,
        deterministicVerification: true
      };
    } catch (error) {
      return { status: 'unavailable', enabled: true, error: error?.code ?? 'audit_sampling_store_unavailable' };
    }
  }

  function health() {
    try {
      mkdirSync(root, { recursive: true, mode: 0o700 });
      return {
        status: 'ready',
        enabled: true,
        mode: 'encrypted-reproducible-audit-sampling',
        encrypted: true,
        sourceReferencesPublic: false,
        deterministicVerification: true,
        maximumPopulationItems: populationLimit,
        maximumPlansPerTenant: planLimit,
        mutex: lock.health()
      };
    } catch (error) {
      return { status: 'unavailable', enabled: true, mode: 'encrypted-reproducible-audit-sampling', error: error?.code ?? 'audit_sampling_store_unavailable' };
    }
  }

  function verifyRecord(record) {
    validateRecord(record, record.tenantId, record.planId);
    const normalised = normalisePopulation(record.population, { maximumItems: populationLimit });
    if (normalised.populationRoot !== record.populationRoot
        || normalised.populationCount !== record.populationCount
        || normalised.populationValueMinorUnits !== record.populationValueMinorUnits) {
      throw new AuditSamplingIntegrityError('The sampling population manifest is inconsistent.', { planId: record.planId });
    }
    verifyEvents(record);
    let selectionValid = null;
    if (record.status === 'approved') {
      const regenerated = selectAuditSample({
        population: record.population,
        method: record.method,
        sampleSize: record.requestedSampleSize,
        seed: record.seed,
        strata: record.strata
      });
      selectionValid = regenerated.selectionHash === record.selection?.selectionHash
        && stableStringify(regenerated.selected.map((entry) => entry.itemHash)) === stableStringify(record.selection?.selected?.map((entry) => entry.itemHash));
      if (!selectionValid) throw new AuditSamplingIntegrityError('The approved sample cannot be reproduced.', { planId: record.planId });
    }
    return {
      valid: true,
      planId: record.planId,
      status: record.status,
      populationRoot: record.populationRoot,
      populationCount: record.populationCount,
      seedCommitment: record.seedCommitment,
      selectionValid,
      selectionHash: record.selection?.selectionHash ?? null,
      eventCount: record.events.length,
      eventHeadHash: record.events.at(-1)?.hash ?? null
    };
  }

  function tenantDirectory(tenantId) {
    const directoryPath = resolve(root, sha256(tenantId));
    mkdirSync(directoryPath, { recursive: true, mode: 0o700 });
    return directoryPath;
  }
  function planPath(tenantId, planId) { return resolve(tenantDirectory(tenantId), `${planId}.plan`); }
  function readPlan(path, tenantId, planId) {
    if (!existsSync(path)) throw new EvidenceValidationError('The audit sampling plan does not exist.', { planId });
    try {
      const record = decryptEvidenceJson(readEvidenceJson(path), keyring, recordAad(tenantId, planId), AuditSamplingIntegrityError);
      validateRecord(record, tenantId, planId);
      return record;
    } catch (error) {
      if (error instanceof AuditSamplingIntegrityError || error instanceof EvidenceValidationError) throw error;
      throw new AuditSamplingStoreError('The audit sampling plan could not be read.', { planId }, error);
    }
  }
  function writePlan(path, record) { writeJsonExclusive(path, encryptEvidenceJson(record, keyring, recordAad(record.tenantId, record.planId)), record.planId); }
  function writePlanAtomic(path, record) {
    const temporary = `${path}.${process.pid}.${Date.now()}.tmp`;
    let descriptor = null;
    try {
      const envelope = encryptEvidenceJson(record, keyring, recordAad(record.tenantId, record.planId));
      descriptor = openSync(temporary, 'wx', 0o600);
      writeFileSync(descriptor, `${JSON.stringify(envelope)}\n`, 'utf8');
      fsyncSync(descriptor);
      closeSync(descriptor);
      descriptor = null;
      renameSync(temporary, path);
      const directoryDescriptor = openSync(dirname(path), 'r');
      try { fsyncSync(directoryDescriptor); } finally { closeSync(directoryDescriptor); }
    } catch (error) {
      if (descriptor !== null) try { closeSync(descriptor); } catch {}
      throw new AuditSamplingStoreError('The audit sampling plan update could not be committed.', { planId: record.planId }, error);
    }
  }

  return Object.freeze({ mode: selectedMode, enabled: true, directory: root, create, approve, cancel, get, list, verify, verifyTenant, status, health });
}

export function createAuditSamplingStoreFromEnvironment({ env = process.env } = {}) {
  const mode = environmentValue(env.WORKFORCE_AUDIT_SAMPLING_MODE) ?? 'disabled';
  if (mode === 'disabled') return createAuditSamplingStore({ mode });
  const required = ['WORKFORCE_AUDIT_SAMPLING_KEYS', 'WORKFORCE_AUDIT_SAMPLING_PRIMARY_KEY_ID'];
  const missing = required.filter((name) => !environmentValue(env[name]));
  if (missing.length) throw new AuditSamplingStoreError('Audit sampling configuration is incomplete.', { reason: 'missing_configuration', missing });
  try {
    return createAuditSamplingStore({
      mode,
      directory: environmentValue(env.WORKFORCE_AUDIT_SAMPLING_DIR) ?? './var/workforce-audit-sampling',
      keys: JSON.parse(env.WORKFORCE_AUDIT_SAMPLING_KEYS),
      primaryKeyId: env.WORKFORCE_AUDIT_SAMPLING_PRIMARY_KEY_ID,
      maximumPopulationItems: Number(env.WORKFORCE_AUDIT_SAMPLING_MAX_POPULATION_ITEMS ?? 100_000),
      maximumPlansPerTenant: Number(env.WORKFORCE_AUDIT_SAMPLING_MAX_PLANS_PER_TENANT ?? 10_000)
    });
  } catch (error) {
    if (error instanceof AuditSamplingStoreError) throw error;
    throw new AuditSamplingStoreError('Audit sampling configuration is invalid.', { reason: error?.code ?? 'invalid_configuration' }, error);
  }
}

function validateCreateInput(input, context) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new EvidenceValidationError('An audit sampling plan request is required.');
  return {
    tenantId: identifier(input.tenantId, 'tenantId'),
    engagementId: identifier(input.engagementId, 'engagementId'),
    objective: cleanText(input.objective, 'objective', 10, 500),
    rationale: cleanText(input.rationale, 'rationale', 10, 2000),
    evidenceId: evidenceIdentifier(input.evidenceId),
    evidenceVersion: integer(input.evidenceVersion, 'evidenceVersion', 1, 1_000_000),
    evidenceContentSha256: hashValue(input.evidenceContentSha256, 'evidenceContentSha256'),
    idempotencyKey: identifier(input.idempotencyKey, 'idempotencyKey'),
    method: String(input.method ?? ''),
    sampleSize: integer(input.sampleSize, 'sampleSize', 1, 1_000_000),
    strata: input.strata ?? null,
    population: input.population,
    actor: identifier(context.actor, 'actor')
  };
}
function validateRecord(record, tenantId, planId) {
  if (!record || record.format !== RECORD_FORMAT || record.version !== 1 || record.tenantId !== tenantId || record.planId !== planId
      || !PLAN_ID.test(record.planId) || !EVIDENCE_ID.test(record.evidenceId) || !HASH.test(record.evidenceContentSha256)
      || !HASH.test(record.populationRoot) || !HASH.test(record.seedCommitment) || !STATUSES.has(record.status)
      || !Array.isArray(record.population) || !Array.isArray(record.events)) {
    throw new AuditSamplingIntegrityError('The audit sampling plan identity is invalid.', { planId });
  }
}
function assertIdempotent(record, request, normalised) {
  if (record.engagementId !== request.engagementId || record.evidenceId !== request.evidenceId
      || record.evidenceVersion !== request.evidenceVersion || record.evidenceContentSha256 !== request.evidenceContentSha256
      || record.idempotencyKey !== request.idempotencyKey || record.populationRoot !== normalised.populationRoot
      || record.method !== request.method || record.requestedSampleSize !== request.sampleSize) {
    throw new AuditSamplingIntegrityError('The idempotency key conflicts with an existing sampling plan.', { planId: record.planId });
  }
}
function publicPlan(record) {
  return {
    planId: record.planId,
    engagementId: record.engagementId,
    objective: record.objective,
    rationale: record.rationale,
    evidenceId: record.evidenceId,
    evidenceVersion: record.evidenceVersion,
    evidenceContentSha256: record.evidenceContentSha256,
    method: record.method,
    requestedSampleSize: record.requestedSampleSize,
    populationRoot: record.populationRoot,
    populationCount: record.populationCount,
    populationValueMinorUnits: record.populationValueMinorUnits,
    seedCommitment: record.seedCommitment,
    seedReveal: record.status === 'approved' ? record.seed : null,
    status: record.status,
    preparedBy: record.preparedBy,
    createdAt: record.createdAt,
    approvedBy: record.approvedBy,
    approvedAt: record.approvedAt,
    cancelledBy: record.cancelledBy,
    cancelledAt: record.cancelledAt,
    selection: record.selection,
    sourceReferencesPublic: false,
    events: record.events.map(({ details, ...event }) => ({ ...event, details: sanitiseEventDetails(details) }))
  };
}
function eventFor(record, type, actor, timestamp, details) {
  const previousHash = record.events.at(-1)?.hash ?? null;
  const body = { sequence: record.events.length + 1, type, actor, timestamp, previousHash, details };
  return { ...body, hash: sha256(stableStringify(body)) };
}
function verifyEvents(record) {
  let previousHash = null;
  for (let index = 0; index < record.events.length; index += 1) {
    const event = record.events[index];
    const { hash, ...body } = event;
    if (event.sequence !== index + 1 || event.previousHash !== previousHash || sha256(stableStringify(body)) !== hash) {
      throw new AuditSamplingIntegrityError('The sampling plan event chain is invalid.', { planId: record.planId, sequence: event.sequence });
    }
    previousHash = hash;
  }
}
function sanitiseEventDetails(details) { if (!details || typeof details !== 'object') return {}; const { seedReveal, ...safe } = details; return safe; }
function writeJsonExclusive(path, value, planId) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  let descriptor = null;
  try {
    descriptor = openSync(path, 'wx', 0o600);
    writeFileSync(descriptor, `${JSON.stringify(value)}\n`, 'utf8');
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = null;
    const directoryDescriptor = openSync(dirname(path), 'r');
    try { fsyncSync(directoryDescriptor); } finally { closeSync(directoryDescriptor); }
  } catch (error) {
    if (descriptor !== null) try { closeSync(descriptor); } catch {}
    if (error?.code === 'EEXIST') throw new AuditSamplingIntegrityError('A conflicting audit sampling plan exists.', { planId });
    throw new AuditSamplingStoreError('The audit sampling plan could not be committed.', { planId }, error);
  }
}
function planNames(directory) { return readdirSync(directory).filter((name) => name.endsWith('.plan') && PLAN_ID.test(name.slice(0, -5))).sort(); }
function recordAad(tenantId, planId) { return `basitclaw:audit-sampling:${tenantId}:${planId}`; }
function planIdentifier(value) { const id = String(value ?? ''); if (!PLAN_ID.test(id)) throw new EvidenceValidationError('planId is invalid.', { field: 'planId' }); return id; }
function evidenceIdentifier(value) { const id = String(value ?? ''); if (!EVIDENCE_ID.test(id)) throw new EvidenceValidationError('evidenceId is invalid.', { field: 'evidenceId' }); return id; }
function identifier(value, field) { const text = String(value ?? '').trim(); if (!/^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{1,191}$/.test(text)) throw new EvidenceValidationError(`${field} is invalid.`, { field }); return text; }
function cleanText(value, field, minimum, maximum) { const text = String(value ?? '').trim(); if (text.length < minimum || text.length > maximum) throw new EvidenceValidationError(`${field} must contain ${minimum} to ${maximum} characters.`, { field }); return text; }
function hashValue(value, field) { const text = String(value ?? '').toLowerCase(); if (!HASH.test(text)) throw new EvidenceValidationError(`${field} must be a SHA-256 digest.`, { field }); return text; }
function integer(value, field, minimum, maximum) { const number = Number(value); if (!Number.isInteger(number) || number < minimum || number > maximum) throw new EvidenceValidationError(`${field} must be an integer from ${minimum} to ${maximum}.`, { field }); return number; }
function enumValue(value, allowed, field) { const text = String(value ?? ''); if (!allowed.has(text)) throw new EvidenceValidationError(`${field} must be one of ${[...allowed].join(', ')}.`, { field }); return text; }
function validNow(now) { const value = now(); if (!(value instanceof Date) || Number.isNaN(value.getTime())) throw new TypeError('now must return a valid Date.'); return value; }
function environmentValue(value) { const text = typeof value === 'string' ? value.trim() : value; return text === '' || text === null || text === undefined ? undefined : text; }
function stableStringify(value) { if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`; if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`; return JSON.stringify(value); }
function disabledStore() {
  const status = Object.freeze({ status: 'disabled', enabled: false, sourceReferencesPublic: false });
  return Object.freeze({ mode: 'disabled', enabled: false, create() { throw new EvidenceConflictError('Audit sampling is disabled.'); }, approve() { throw new EvidenceConflictError('Audit sampling is disabled.'); }, cancel() { throw new EvidenceConflictError('Audit sampling is disabled.'); }, get() { throw new EvidenceConflictError('Audit sampling is disabled.'); }, list() { return []; }, verify() { throw new EvidenceConflictError('Audit sampling is disabled.'); }, verifyTenant(tenantId) { return { valid: true, tenantId, checkedPlans: 0, approvedPlans: 0 }; }, status() { return status; }, health() { return status; } });
}
