import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { createFileMutex } from '../security/fileMutex.js';
import {
  atomicWriteEvidenceJson,
  decryptEvidenceJson,
  encryptEvidenceJson,
  parseEvidenceKeyring,
  readEvidenceJson,
  sha256,
  tenantEvidenceDirectory
} from './evidenceCrypto.js';
import {
  EvidenceConflictError,
  EvidenceIntegrityError,
  EvidenceStoreError,
  EvidenceValidationError,
  createEvidenceRegistryFromEnvironment
} from './evidenceRegistry.js';
import { createEvidenceScreeningEngineFromEnvironment } from './evidenceScreeningEngine.js';

const FORMAT = 'basitclaw-workforce-audit-evidence-screening';
const EVIDENCE_ID = /^EVD-[a-f0-9]{32}$/;
const DECISIONS = new Set(['clean', 'quarantine', 'rejected']);

export class EvidenceQuarantinedError extends EvidenceConflictError {
  constructor(evidenceId, details = {}) {
    super('Evidence is quarantined and cannot be downloaded or referenced.', { evidenceId, ...details });
    this.name = 'EvidenceQuarantinedError';
    this.code = 'EVIDENCE_QUARANTINED';
    this.statusCode = 423;
  }
}

export class EvidenceScreeningStoreError extends EvidenceStoreError {
  constructor(message = 'The evidence screening registry is unavailable.', details = {}, cause = null) {
    super(message, details, cause);
    this.name = 'EvidenceScreeningStoreError';
    this.code = 'EVIDENCE_SCREENING_STORE_UNAVAILABLE';
  }
}

export function createScreenedEvidenceRegistry({
  registry,
  engine,
  keys,
  primaryKeyId,
  eventRetention = 10_000,
  now = () => new Date(),
  mutex = null
} = {}) {
  if (!registry || typeof registry.ingest !== 'function') throw new TypeError('A base evidence registry is required.');
  if (!engine || typeof engine.screen !== 'function') throw new TypeError('An evidence screening engine is required.');
  if (!registry.enabled || engine.mode === 'disabled') return disabledScreeningWrapper(registry, engine);
  const keyring = parseEvidenceKeyring(keys, primaryKeyId);
  const root = resolve(registry.directory, '.screening');
  const retainedEvents = integer(eventRetention, 'eventRetention', 100, 100_000);
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const lock = mutex ?? createFileMutex({ directory: resolve(root, '.locks') });

  function ingest(tenantId, input, context = {}) {
    const report = engine.screen(input);
    const item = registry.ingest(tenantId, input, context);
    try {
      recordVersion(tenantId, item.evidenceId, item.currentVersion, report, context.actor, 'screening.completed');
      return overlay(tenantId, item);
    } catch (error) {
      throw screeningFailure(error, 'ingest', item.evidenceId);
    }
  }

  function addVersion(tenantId, evidenceId, input, context = {}) {
    const report = engine.screen(input);
    const item = registry.addVersion(tenantId, evidenceId, input, context);
    try {
      recordVersion(tenantId, item.evidenceId, item.currentVersion, report, context.actor, 'screening.version_completed');
      return overlay(tenantId, item);
    } catch (error) {
      throw screeningFailure(error, 'add_version', item.evidenceId);
    }
  }

  function list(tenantId, options = {}) {
    const status = options.status ?? null;
    const baseOptions = { ...options, status: status === 'active' || status === 'disposed' ? status : null };
    let items = registry.list(tenantId, baseOptions).map((item) => overlay(tenantId, item));
    if (status) items = items.filter((item) => item.status === status);
    return items;
  }

  function get(tenantId, evidenceId) { return overlay(tenantId, registry.get(tenantId, evidenceId)); }

  function readContent(tenantId, evidenceId, options = {}) {
    const item = registry.get(tenantId, evidenceId);
    const version = options.version ?? item.currentVersion;
    assertVersionAccessible(tenantId, item.evidenceId, version);
    return registry.readContent(tenantId, evidenceId, options);
  }

  function assertUsableReferences(tenantId, references) {
    const items = registry.assertUsableReferences(tenantId, references);
    for (const item of items) assertVersionAccessible(tenantId, item.evidenceId, item.currentVersion);
    return items.map((item) => overlay(tenantId, item));
  }

  function releaseQuarantine(tenantId, evidenceId, input, { actor } = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = evidenceIdentifier(evidenceId);
    const by = identifier(actor, 'actor');
    if (input?.confirmation !== `RELEASE QUARANTINE ${id}`) {
      throw new EvidenceValidationError(`confirmation must be exactly RELEASE QUARANTINE ${id}.`, { field: 'confirmation' });
    }
    const reason = text(input?.reason, 'reason', 10, 1000);
    return lock.withLock(`screening:${tenant}`, () => {
      const index = loadIndex(tenant);
      const record = findRecord(index, id);
      const version = currentScreening(record);
      if (version.decision !== 'quarantine') throw new EvidenceConflictError('The current evidence version is not quarantined.', { evidenceId: id });
      version.decision = 'clean';
      version.review = { action: 'released', reviewedAt: now().toISOString(), reviewedBy: by, reason };
      appendEvent(index, by, 'screening.quarantine_released', id, { version: version.version, reportId: version.reportId });
      saveIndex(tenant, index);
      return overlay(tenant, registry.get(tenant, id));
    });
  }

  function rejectQuarantine(tenantId, evidenceId, input, { actor } = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = evidenceIdentifier(evidenceId);
    const by = identifier(actor, 'actor');
    if (input?.confirmation !== `REJECT EVIDENCE ${id}`) {
      throw new EvidenceValidationError(`confirmation must be exactly REJECT EVIDENCE ${id}.`, { field: 'confirmation' });
    }
    const reason = text(input?.reason, 'reason', 10, 1000);
    return lock.withLock(`screening:${tenant}`, () => {
      const index = loadIndex(tenant);
      const record = findRecord(index, id);
      const version = currentScreening(record);
      if (version.decision !== 'quarantine') throw new EvidenceConflictError('The current evidence version is not quarantined.', { evidenceId: id });
      version.decision = 'rejected';
      version.review = { action: 'rejected', reviewedAt: now().toISOString(), reviewedBy: by, reason };
      appendEvent(index, by, 'screening.quarantine_rejected', id, { version: version.version, reportId: version.reportId });
      saveIndex(tenant, index);
      return overlay(tenant, registry.get(tenant, id));
    });
  }

  function screeningReport(tenantId, evidenceId, { version = null } = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = evidenceIdentifier(evidenceId);
    const record = findRecord(loadSafe(tenant), id);
    const selected = version === null
      ? currentScreening(record)
      : record.versions.find((entry) => entry.version === integer(version, 'version', 1, 1_000_000));
    if (!selected) throw new EvidenceIntegrityError('Screening metadata for the requested evidence version is missing.', { evidenceId: id, version });
    return publicScreening(selected);
  }

  function screeningEvents(tenantId, { evidenceId = null, limit = 500 } = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const index = loadSafe(tenant);
    const rows = evidenceId ? index.events.filter((event) => event.evidenceId === evidenceIdentifier(evidenceId)) : index.events;
    return rows.slice(-integer(limit, 'limit', 1, 5000)).reverse().map(publicEvent);
  }

  function verify(tenantId, evidenceId = null) {
    const custody = registry.verify(tenantId, evidenceId);
    const tenant = identifier(tenantId, 'tenantId');
    const index = loadSafe(tenant);
    verifyChain(index);
    const records = evidenceId ? [findRecord(index, evidenceIdentifier(evidenceId))] : index.records;
    for (const record of records) for (const version of record.versions) validateVersion(version, record.evidenceId);
    return { ...custody, screening: { valid: true, checkedRecords: records.length, checkedVersions: records.reduce((sum, record) => sum + record.versions.length, 0), headSequence: index.sequence, headHash: index.headHash, anchorSequence: index.anchor?.sequence ?? 0 } };
  }

  function health() {
    const base = registry.health();
    const screening = screeningHealth();
    const unavailable = base.status !== 'ready' || (engine.required && screening.status !== 'ready');
    return { ...base, status: unavailable ? 'unavailable' : base.status, screening };
  }

  function tenantStatus(tenantId) {
    const base = registry.tenantStatus(tenantId);
    try {
      const index = loadSafe(identifier(tenantId, 'tenantId'));
      const latest = index.records.map(currentScreening);
      const quarantined = latest.filter((entry) => entry.decision === 'quarantine').length;
      const rejected = latest.filter((entry) => entry.decision === 'rejected').length;
      return {
        ...base,
        status: base.status === 'unavailable' ? 'unavailable' : quarantined || rejected ? 'attention' : base.status,
        screening: { status: 'ready', mode: engine.mode, quarantined, rejected, clean: latest.length - quarantined - rejected, totalReports: index.records.reduce((sum, record) => sum + record.versions.length, 0), headSequence: index.sequence, headHash: index.headHash, anchorSequence: index.anchor?.sequence ?? 0 }
      };
    } catch (error) {
      return { ...base, status: engine.required ? 'unavailable' : base.status, screening: { status: 'unavailable', mode: engine.mode, error: error?.code ?? 'screening_store_unavailable' } };
    }
  }

  function overlay(tenantId, item) {
    if (item.status === 'disposed') return { ...item, screening: { status: 'not-applicable' } };
    const tenant = identifier(tenantId, 'tenantId');
    const index = loadSafe(tenant);
    const record = index.records.find((entry) => entry.evidenceId === item.evidenceId);
    if (!record) throw new EvidenceScreeningStoreError('Screening metadata is missing for an evidence item.', { evidenceId: item.evidenceId });
    const version = record.versions.find((entry) => entry.version === item.currentVersion);
    if (!version) throw new EvidenceScreeningStoreError('Screening metadata is missing for the current evidence version.', { evidenceId: item.evidenceId, version: item.currentVersion });
    return { ...item, status: version.decision === 'clean' ? item.status : version.decision, screening: publicScreening(version) };
  }

  function assertVersionAccessible(tenantId, evidenceId, versionNumber) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = evidenceIdentifier(evidenceId);
    const record = findRecord(loadSafe(tenant), id);
    const version = record.versions.find((entry) => entry.version === Number(versionNumber));
    if (!version) throw new EvidenceScreeningStoreError('Screening metadata is missing for the requested evidence version.', { evidenceId: id, version: versionNumber });
    if (version.decision !== 'clean') throw new EvidenceQuarantinedError(id, { version: version.version, decision: version.decision });
  }

  function recordVersion(tenantId, evidenceId, versionNumber, report, actor, action) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = evidenceIdentifier(evidenceId);
    const by = identifier(actor, 'actor');
    validateReport(report);
    lock.withLock(`screening:${tenant}`, () => {
      const index = loadIndex(tenant);
      let record = index.records.find((entry) => entry.evidenceId === id);
      if (!record) { record = { evidenceId: id, currentVersion: 0, versions: [] }; index.records.push(record); }
      if (record.versions.some((entry) => entry.version === versionNumber)) throw new EvidenceIntegrityError('Screening metadata already exists for this immutable version.', { evidenceId: id, version: versionNumber });
      const stored = { version: versionNumber, reportId: report.reportId, engineVersion: report.engineVersion, mode: report.mode, decision: report.decision, wouldQuarantine: report.wouldQuarantine, scannedAt: report.scannedAt, contentSha256: report.contentSha256, sizeBytes: report.sizeBytes, findings: report.findings.map((finding) => ({ ...finding })), review: null };
      record.versions.push(stored);
      record.currentVersion = versionNumber;
      appendEvent(index, by, action, id, { version: versionNumber, reportId: report.reportId, decision: report.decision, findingRuleIds: report.findings.map((finding) => finding.ruleId) });
      saveIndex(tenant, index);
    });
  }

  function screeningHealth() {
    try {
      mkdirSync(root, { recursive: true, mode: 0o700 });
      return { ...engine.health(), status: 'ready', durable: true, distributed: true, encrypted: true, eventRetention: retainedEvents, mutex: lock.health() };
    } catch (error) {
      return { status: 'unavailable', enabled: true, required: Boolean(engine.required), mode: engine.mode, error: error?.code ?? 'screening_store_unavailable' };
    }
  }

  function loadSafe(tenant) {
    try { return loadIndex(tenant); }
    catch (error) { if (error instanceof EvidenceIntegrityError || error instanceof EvidenceScreeningStoreError) throw error; throw screeningFailure(error, 'load_index'); }
  }
  function loadIndex(tenant) {
    const path = indexPath(tenant);
    if (!existsSync(path)) return emptyIndex(tenant);
    let envelope;
    try { envelope = readEvidenceJson(path); } catch (error) { throw new EvidenceIntegrityError('The evidence screening index is unreadable.', { tenantId: tenant }, error); }
    const index = decryptEvidenceJson(envelope, keyring, screeningAad(tenant), EvidenceIntegrityError);
    if (index.format !== FORMAT || index.version !== 1 || index.tenantId !== tenant) throw new EvidenceIntegrityError('The evidence screening index identity is invalid.', { tenantId: tenant });
    verifyChain(index);
    return index;
  }
  function saveIndex(tenant, index) { atomicWriteEvidenceJson(indexPath(tenant), encryptEvidenceJson(index, keyring, screeningAad(tenant))); }
  function indexPath(tenant) { return resolve(tenantEvidenceDirectory(root, tenant), 'screening.evidence'); }

  return Object.freeze({
    ...registry,
    ingest, addVersion, list, get, readContent, assertUsableReferences,
    releaseQuarantine, rejectQuarantine, screeningReport, screeningEvents,
    verify, health, tenantStatus,
    screeningEnabled: true,
    screeningEngine: engine
  });
}

export function createScreenedEvidenceRegistryFromEnvironment(env = process.env) {
  const registry = createEvidenceRegistryFromEnvironment(env);
  const engine = createEvidenceScreeningEngineFromEnvironment(env);
  if (!registry.enabled || engine.mode === 'disabled') return disabledScreeningWrapper(registry, engine);
  let keys;
  try { keys = JSON.parse(environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_KEYS)); }
  catch (error) { throw new EvidenceScreeningStoreError('Evidence screening encryption keys are invalid.', { field: 'WORKFORCE_AUDIT_EVIDENCE_KEYS' }, error); }
  try {
    return createScreenedEvidenceRegistry({
      registry,
      engine,
      keys,
      primaryKeyId: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_PRIMARY_KEY_ID),
      eventRetention: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_SCREENING_EVENT_RETENTION) ?? 10_000
    });
  } catch (error) {
    if (error instanceof EvidenceScreeningStoreError) throw error;
    throw new EvidenceScreeningStoreError('Evidence screening configuration is invalid.', { reason: error?.code ?? 'invalid_configuration' }, error);
  }
}

function disabledScreeningWrapper(registry, engine) {
  if (engine.required) throw new EvidenceScreeningStoreError('Required evidence screening cannot be disabled.', { reason: 'required_disabled' });
  return Object.freeze({
    ...registry,
    screeningEnabled: false,
    screeningEngine: engine,
    releaseQuarantine() { throw new EvidenceConflictError('Evidence screening is disabled.'); },
    rejectQuarantine() { throw new EvidenceConflictError('Evidence screening is disabled.'); },
    screeningReport() { return { status: 'disabled', decision: 'clean', findings: [] }; },
    screeningEvents() { return []; },
    health() { return { ...registry.health(), screening: engine.health() }; },
    tenantStatus(tenantId) { return { ...registry.tenantStatus(tenantId), screening: engine.health() }; }
  });
}

function emptyIndex(tenantId) { return { format: FORMAT, version: 1, tenantId, createdAt: null, updatedAt: null, sequence: 0, headHash: null, anchor: null, records: [], events: [] }; }
function findRecord(index, evidenceId) { const record = index.records.find((entry) => entry.evidenceId === evidenceId); if (!record) throw new EvidenceScreeningStoreError('Screening metadata is missing for the evidence item.', { evidenceId }); return record; }
function currentScreening(record) { const selected = record.versions.find((entry) => entry.version === record.currentVersion); if (!selected) throw new EvidenceIntegrityError('The current evidence screening version is missing.', { evidenceId: record.evidenceId }); return selected; }
function publicScreening(version) { return { reportId: version.reportId, engineVersion: version.engineVersion, mode: version.mode, decision: version.decision, wouldQuarantine: version.wouldQuarantine, scannedAt: version.scannedAt, version: version.version, findings: version.findings.map((finding) => ({ ...finding })), reviewedAt: version.review?.reviewedAt ?? null, reviewAction: version.review?.action ?? null }; }
function publicEvent(event) { return { eventId: event.eventId, sequence: event.sequence, occurredAt: event.occurredAt, action: event.action, evidenceId: event.evidenceId, metadata: structuredClone(event.metadata), previousHash: event.previousHash, hash: event.hash }; }
function validateReport(report) { if (!report || !/^SCR-[a-f0-9]{32}$/.test(report.reportId) || !DECISIONS.has(report.decision) || !Array.isArray(report.findings)) throw new EvidenceIntegrityError('The evidence screening report is invalid.'); }
function validateVersion(version, evidenceId) { if (!Number.isInteger(version.version) || version.version < 1 || !DECISIONS.has(version.decision) || !/^SCR-[a-f0-9]{32}$/.test(version.reportId) || !Array.isArray(version.findings)) throw new EvidenceIntegrityError('Stored evidence screening metadata is invalid.', { evidenceId, version: version.version }); }
function appendEvent(index, actor, action, evidenceId, metadata) { const event = { eventId: `SEV-${randomUUID()}`, sequence: index.sequence + 1, occurredAt: new Date().toISOString(), actor, action, evidenceId, metadata, previousHash: index.headHash }; event.hash = eventHash(event); if (!index.sequence) index.createdAt = event.occurredAt; index.events.push(event); index.sequence = event.sequence; index.headHash = event.hash; index.updatedAt = event.occurredAt; if (index.events.length > 10_000) { const removed = index.events.splice(0, index.events.length - 10_000); const tail = removed.at(-1); index.anchor = { sequence: tail.sequence, hash: tail.hash, createdAt: event.occurredAt }; } }
function verifyChain(index) { let previous = index.anchor?.hash ?? null; let sequence = (index.anchor?.sequence ?? 0) + 1; for (const event of index.events) { if (event.sequence !== sequence || event.previousHash !== previous || event.hash !== eventHash(event)) throw new EvidenceIntegrityError('The evidence screening event chain is invalid.', { failedEventId: event.eventId, expectedSequence: sequence }); previous = event.hash; sequence += 1; } if (index.sequence !== sequence - 1 || index.headHash !== previous) throw new EvidenceIntegrityError('The evidence screening chain head is inconsistent.', { sequence: index.sequence }); }
function eventHash(event) { return sha256(Buffer.from(JSON.stringify({ eventId: event.eventId, sequence: event.sequence, occurredAt: event.occurredAt, actor: event.actor, action: event.action, evidenceId: event.evidenceId, metadata: event.metadata, previousHash: event.previousHash }))); }
function screeningAad(tenant) { return `basitclaw:evidence-screening:${tenant}`; }
function screeningFailure(error, operation, evidenceId = null) { if (error instanceof EvidenceIntegrityError || error instanceof EvidenceValidationError || error instanceof EvidenceConflictError || error instanceof EvidenceScreeningStoreError) return error; return new EvidenceScreeningStoreError('The evidence screening change could not be committed.', { operation, evidenceId, cause: error?.code ?? 'filesystem_error' }, error); }
function identifier(value, field) { const clean = String(value ?? '').trim(); if (!/^[a-zA-Z0-9][a-zA-Z0-9._:@-]{1,191}$/.test(clean)) throw new EvidenceValidationError(`${field} must be a safe identifier.`, { field }); return clean; }
function evidenceIdentifier(value) { const clean = String(value ?? '').trim(); if (!EVIDENCE_ID.test(clean)) throw new EvidenceValidationError('evidenceId must be a valid EVD identifier.', { field: 'evidenceId' }); return clean; }
function text(value, field, minimum, maximum) { const clean = String(value ?? '').trim(); if (clean.length < minimum || clean.length > maximum) throw new EvidenceValidationError(`${field} must contain ${minimum} to ${maximum} characters.`, { field }); return clean; }
function integer(value, field, minimum, maximum) { const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) throw new EvidenceValidationError(`${field} must be an integer from ${minimum} to ${maximum}.`, { field }); return parsed; }
function environmentValue(value) { const clean = typeof value === 'string' ? value.trim() : value; return clean === '' || clean === undefined || clean === null ? undefined : clean; }
