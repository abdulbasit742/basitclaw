import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync } from 'node:fs';
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
} from '../evidence/evidenceCrypto.js';
import {
  EvidenceConflictError,
  EvidenceIntegrityError,
  EvidenceStoreError,
  EvidenceValidationError
} from '../evidence/evidenceRegistry.js';

const FORMAT = 'basitclaw-regulatory-case-register';
const CASE_ID = /^RGC-[a-f0-9]{32}$/;
const EVIDENCE_ID = /^EVD-[a-f0-9]{32}$/;
const HASH = /^[a-f0-9]{64}$/;
const MODES = new Set(['disabled', 'shared-file']);
const CASE_TYPES = new Set(['regulator_request', 'external_audit', 'legal_request', 'certification_review']);
const STATES = new Set(['open', 'response_pending', 'response_approved', 'closed', 'cancelled']);
const PRIORITIES = new Set(['normal', 'high', 'critical']);

export class RegulatoryCaseStoreError extends EvidenceStoreError {
  constructor(message = 'The regulatory case register is unavailable.', details = {}, cause = null) {
    super(message, details, cause);
    this.name = 'RegulatoryCaseStoreError';
    this.code = 'REGULATORY_CASE_STORE_UNAVAILABLE';
  }
}

export class RegulatoryCaseIntegrityError extends EvidenceIntegrityError {
  constructor(message = 'Regulatory case integrity verification failed.', details = {}, cause = null) {
    super(message, details, cause);
    this.name = 'RegulatoryCaseIntegrityError';
    this.code = 'REGULATORY_CASE_INTEGRITY_FAILED';
  }
}

export class RegulatoryCaseApprovalError extends EvidenceConflictError {
  constructor(message = 'The regulatory case approval policy is not satisfied.', details = {}) {
    super(message, details);
    this.name = 'RegulatoryCaseApprovalError';
    this.code = 'REGULATORY_CASE_APPROVAL_REQUIRED';
  }
}

export function createRegulatoryCaseStore({
  mode = 'disabled',
  directory,
  encryptionKeys,
  encryptionPrimaryKeyId,
  resolveEvidence,
  dueSoonHours = 72,
  maximumCases = 10000,
  maximumEvidencePerCase = 500,
  now = () => new Date(),
  mutex = null
} = {}) {
  const selectedMode = enumValue(mode, MODES, 'mode');
  if (selectedMode === 'disabled') return disabledStore();
  if (!String(directory ?? '').trim()) throw new TypeError('A regulatory case directory is required.');
  if (typeof resolveEvidence !== 'function') throw new TypeError('A regulatory case evidence resolver is required.');
  const root = resolve(String(directory));
  const encryption = parseEvidenceKeyring(encryptionKeys, encryptionPrimaryKeyId);
  const dueSoonMs = integer(dueSoonHours, 'dueSoonHours', 1, 2160) * 3_600_000;
  const caseLimit = integer(maximumCases, 'maximumCases', 1, 100000);
  const evidenceLimit = integer(maximumEvidencePerCase, 'maximumEvidencePerCase', 1, 5000);
  const lock = mutex ?? createFileMutex({ directory: resolve(root, '.locks'), now });
  mkdirSync(root, { recursive: true, mode: 0o700 });

  function createCase(tenantId, input, context = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const actor = identifier(context.actor, 'actor');
    const request = normaliseCreate(input, now());
    const evidence = normaliseEvidenceSelections(tenant, request.evidence);
    const caseId = `RGC-${sha256(stableStringify({
      tenant,
      requestReference: request.requestReference,
      authority: request.authority,
      receivedAt: request.receivedAt
    })).slice(0, 32)}`;
    return lock.withLock(`regulatory-cases:${tenant}`, () => {
      const index = loadIndex(tenant);
      const duplicate = index.cases.find((entry) => entry.caseId === caseId);
      if (duplicate) return { created: false, duplicate: true, case: publicCase(duplicate, now(), dueSoonMs) };
      if (index.cases.length >= caseLimit) {
        throw new EvidenceConflictError('The regulatory case capacity has been reached.', { maximumCases: caseLimit });
      }
      const record = {
        caseId,
        tenantId: tenant,
        type: request.type,
        priority: request.priority,
        state: 'open',
        authority: request.authority,
        jurisdiction: request.jurisdiction,
        requestReference: request.requestReference,
        legalBasis: request.legalBasis,
        summary: request.summary,
        receivedAt: request.receivedAt,
        dueAt: request.dueAt,
        owner: request.owner,
        evidence,
        createdAt: now().toISOString(),
        createdBy: actor,
        response: null,
        closure: null,
        cancellation: null
      };
      index.cases.push(record);
      appendEvent(index, record, 'case.created', actor, {
        type: record.type,
        priority: record.priority,
        authority: record.authority,
        requestReference: record.requestReference,
        evidenceCount: evidence.length,
        dueAt: record.dueAt
      });
      saveIndex(tenant, index);
      return { created: true, duplicate: false, case: publicCase(record, now(), dueSoonMs) };
    });
  }

  function addEvidence(tenantId, caseId, input, context = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = caseIdentifier(caseId);
    const actor = identifier(context.actor, 'actor');
    const selections = Array.isArray(input?.evidence) ? input.evidence : [];
    if (!selections.length) throw new EvidenceValidationError('At least one evidence selection is required.', { field: 'evidence' });
    const evidence = normaliseEvidenceSelections(tenant, selections);
    return lock.withLock(`regulatory-cases:${tenant}`, () => {
      const index = loadIndex(tenant);
      const record = findCase(index, id);
      assertEditable(record);
      const existing = new Set(record.evidence.map((entry) => `${entry.evidenceId}:${entry.version}`));
      for (const entry of evidence) {
        if (!existing.has(`${entry.evidenceId}:${entry.version}`)) record.evidence.push(entry);
      }
      if (record.evidence.length > evidenceLimit) {
        throw new EvidenceValidationError(`A regulatory case may reference at most ${evidenceLimit} evidence versions.`, { field: 'evidence' });
      }
      appendEvent(index, record, 'case.evidence_added', actor, { added: evidence.length, total: record.evidence.length });
      saveIndex(tenant, index);
      return publicCase(record, now(), dueSoonMs);
    });
  }

  function submitResponse(tenantId, caseId, input, context = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = caseIdentifier(caseId);
    const actor = identifier(context.actor, 'actor');
    requireConfirmation(input?.confirmation, `SUBMIT RESPONSE ${id}`);
    const responseReference = cleanText(input?.responseReference, 'responseReference', 3, 191);
    const responseSummary = cleanText(input?.responseSummary, 'responseSummary', 20, 2000);
    return lock.withLock(`regulatory-cases:${tenant}`, () => {
      const index = loadIndex(tenant);
      const record = findCase(index, id);
      if (record.state !== 'open') throw new EvidenceConflictError('Only an open regulatory case can submit a response.', { caseId: id, state: record.state });
      if (!record.evidence.length) throw new EvidenceConflictError('A response cannot be submitted without verified evidence references.', { caseId: id });
      revalidateEvidence(tenant, record.evidence);
      record.state = 'response_pending';
      record.response = {
        responseReference,
        responseSummary,
        submittedAt: now().toISOString(),
        submittedBy: actor,
        approvedAt: null,
        approvedBy: null,
        approvalReason: null
      };
      appendEvent(index, record, 'case.response_submitted', actor, { responseReference, evidenceCount: record.evidence.length });
      saveIndex(tenant, index);
      return publicCase(record, now(), dueSoonMs);
    });
  }

  function approveResponse(tenantId, caseId, input, context = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = caseIdentifier(caseId);
    const actor = identifier(context.actor, 'actor');
    requireConfirmation(input?.confirmation, `APPROVE RESPONSE ${id}`);
    const reason = cleanText(input?.reason, 'reason', 10, 500);
    return lock.withLock(`regulatory-cases:${tenant}`, () => {
      const index = loadIndex(tenant);
      const record = findCase(index, id);
      if (record.state !== 'response_pending' || !record.response) {
        throw new RegulatoryCaseApprovalError('The regulatory response is not pending approval.', { caseId: id, state: record.state });
      }
      if (record.response.submittedBy === actor) {
        throw new RegulatoryCaseApprovalError('The response submitter cannot approve their own response.', { caseId: id, reason: 'self_approval' });
      }
      revalidateEvidence(tenant, record.evidence);
      record.state = 'response_approved';
      record.response.approvedAt = now().toISOString();
      record.response.approvedBy = actor;
      record.response.approvalReason = reason;
      appendEvent(index, record, 'case.response_approved', actor, { responseReference: record.response.responseReference });
      saveIndex(tenant, index);
      return publicCase(record, now(), dueSoonMs);
    });
  }

  function closeCase(tenantId, caseId, input, context = {}) {
    return terminalAction('closed', tenantId, caseId, input, context);
  }

  function cancelCase(tenantId, caseId, input, context = {}) {
    return terminalAction('cancelled', tenantId, caseId, input, context);
  }

  function terminalAction(target, tenantId, caseId, input, context) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = caseIdentifier(caseId);
    const actor = identifier(context.actor, 'actor');
    const verb = target === 'closed' ? 'CLOSE' : 'CANCEL';
    requireConfirmation(input?.confirmation, `${verb} CASE ${id}`);
    const reason = cleanText(input?.reason, 'reason', 10, 1000);
    return lock.withLock(`regulatory-cases:${tenant}`, () => {
      const index = loadIndex(tenant);
      const record = findCase(index, id);
      if (target === 'closed') {
        if (record.state !== 'response_approved') throw new RegulatoryCaseApprovalError('Only an approved response can close the regulatory case.', { caseId: id, state: record.state });
        if (record.response.approvedBy === actor) throw new RegulatoryCaseApprovalError('The response approver cannot perform final case closure.', { caseId: id, reason: 'closure_separation' });
        record.state = 'closed';
        record.closure = { closedAt: now().toISOString(), closedBy: actor, reason };
      } else {
        if (['closed', 'cancelled'].includes(record.state)) throw new EvidenceConflictError('The regulatory case is already terminal.', { caseId: id, state: record.state });
        record.state = 'cancelled';
        record.cancellation = { cancelledAt: now().toISOString(), cancelledBy: actor, reason };
      }
      appendEvent(index, record, `case.${target}`, actor, { reason });
      saveIndex(tenant, index);
      return publicCase(record, now(), dueSoonMs);
    });
  }

  function list(tenantId, { state = null, priority = null, limit = 200 } = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const selectedState = state === null ? null : enumValue(state, STATES, 'state');
    const selectedPriority = priority === null ? null : enumValue(priority, PRIORITIES, 'priority');
    return loadSafe(tenant).cases
      .filter((record) => (!selectedState || record.state === selectedState) && (!selectedPriority || record.priority === selectedPriority))
      .sort((left, right) => left.dueAt.localeCompare(right.dueAt))
      .slice(0, integer(limit, 'limit', 1, 2000))
      .map((record) => publicCase(record, now(), dueSoonMs));
  }

  function get(tenantId, caseId) {
    const tenant = identifier(tenantId, 'tenantId');
    return publicCase(findCase(loadSafe(tenant), caseIdentifier(caseId)), now(), dueSoonMs);
  }

  function events(tenantId, caseId = null, { limit = 500 } = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = caseId === null ? null : caseIdentifier(caseId);
    return loadSafe(tenant).events
      .filter((event) => !id || event.caseId === id)
      .slice(-integer(limit, 'limit', 1, 5000))
      .reverse()
      .map((event) => ({ ...event }));
  }

  function verifyTenant(tenantId) {
    const tenant = identifier(tenantId, 'tenantId');
    const index = loadSafe(tenant);
    for (const record of index.cases) {
      if (!CASE_ID.test(record.caseId) || record.tenantId !== tenant || !STATES.has(record.state)) {
        throw new RegulatoryCaseIntegrityError('A regulatory case has an invalid identity.', { caseId: record.caseId });
      }
    }
    return { valid: true, tenantId: tenant, checkedCases: index.cases.length, checkedEvents: index.events.length, headSequence: index.sequence, headHash: index.headHash };
  }

  function tenantStatus(tenantId) {
    const tenant = identifier(tenantId, 'tenantId');
    try {
      const index = loadSafe(tenant);
      const counts = { open: 0, responsePending: 0, responseApproved: 0, closed: 0, cancelled: 0, overdue: 0, dueSoon: 0 };
      for (const record of index.cases) {
        if (record.state === 'open') counts.open += 1;
        if (record.state === 'response_pending') counts.responsePending += 1;
        if (record.state === 'response_approved') counts.responseApproved += 1;
        if (record.state === 'closed') counts.closed += 1;
        if (record.state === 'cancelled') counts.cancelled += 1;
        const deadline = deadlineState(record, now(), dueSoonMs);
        if (deadline === 'overdue') counts.overdue += 1;
        if (deadline === 'due_soon') counts.dueSoon += 1;
      }
      return { status: 'ready', enabled: true, total: index.cases.length, ...counts, headSequence: index.sequence, headHash: index.headHash };
    } catch (error) {
      return { status: 'unavailable', enabled: true, error: error?.code ?? 'regulatory_case_store_unavailable' };
    }
  }

  function health() {
    try {
      mkdirSync(root, { recursive: true, mode: 0o700 });
      const tenantDirectoryCount = readdirSync(root, { withFileTypes: true }).filter((entry) => entry.isDirectory() && entry.name !== '.locks').length;
      return { status: 'ready', enabled: true, mode: 'shared-file-regulatory-case-register', encrypted: true, hashLinkedEvents: true, makerChecker: true, dueSoonHours: dueSoonMs / 3_600_000, tenantDirectoryCount, mutex: lock.health() };
    } catch (error) {
      return { status: 'unavailable', enabled: true, mode: 'shared-file-regulatory-case-register', error: error?.code ?? 'regulatory_case_store_unavailable' };
    }
  }

  function normaliseEvidenceSelections(tenant, selections) {
    if (!Array.isArray(selections) || selections.length > evidenceLimit) throw new EvidenceValidationError(`evidence must contain at most ${evidenceLimit} selections.`, { field: 'evidence' });
    const seen = new Set();
    return selections.map((selection) => {
      if (!selection || typeof selection !== 'object' || Array.isArray(selection)) throw new EvidenceValidationError('Each evidence selection must be an object.', { field: 'evidence' });
      const evidenceId = evidenceIdentifier(selection.evidenceId);
      const version = integer(selection.version, 'version', 1, 1000000);
      const key = `${evidenceId}:${version}`;
      if (seen.has(key)) throw new EvidenceValidationError('Duplicate evidence selections are not allowed.', { field: 'evidence' });
      seen.add(key);
      return normaliseResolved(resolveEvidence(tenant, { evidenceId, version }), { evidenceId, version });
    });
  }

  function revalidateEvidence(tenant, references) {
    for (const reference of references) normaliseResolved(resolveEvidence(tenant, reference), reference);
  }

  function loadIndex(tenant) {
    const path = indexPath(tenant);
    if (!existsSync(path)) return emptyIndex(tenant, now());
    let envelope;
    try { envelope = readEvidenceJson(path); }
    catch (error) { throw new RegulatoryCaseStoreError('The regulatory case index is unreadable.', {}, error); }
    const index = decryptEvidenceJson(envelope, encryption, indexAad(tenant), RegulatoryCaseIntegrityError);
    if (!index || index.format !== FORMAT || index.version !== 1 || index.tenantId !== tenant || !Array.isArray(index.cases) || !Array.isArray(index.events)) throw new RegulatoryCaseIntegrityError('The regulatory case index identity is invalid.');
    verifyEventChain(index);
    return index;
  }

  function loadSafe(tenant) {
    try { return loadIndex(tenant); }
    catch (error) { if (error instanceof RegulatoryCaseStoreError || error instanceof RegulatoryCaseIntegrityError) throw error; throw new RegulatoryCaseStoreError('The regulatory case index could not be loaded.', {}, error); }
  }

  function saveIndex(tenant, index) {
    index.updatedAt = now().toISOString();
    atomicWriteEvidenceJson(indexPath(tenant), encryptEvidenceJson(index, encryption, indexAad(tenant)));
  }

  function indexPath(tenant) { return resolve(tenantEvidenceDirectory(root, tenant), 'regulatory-cases.evidence'); }

  return Object.freeze({ mode: selectedMode, enabled: true, directory: root, createCase, addEvidence, submitResponse, approveResponse, closeCase, cancelCase, list, get, events, verifyTenant, tenantStatus, health });
}

export function createRegulatoryCaseStoreFromEnvironment({ env = process.env, evidenceRegistry } = {}) {
  try {
    const mode = environmentValue(env.WORKFORCE_AUDIT_REGULATORY_CASE_MODE) ?? 'disabled';
    if (mode === 'disabled') return createRegulatoryCaseStore({ mode });
    if (!evidenceRegistry || typeof evidenceRegistry.readContent !== 'function') throw new RegulatoryCaseStoreError('Regulatory cases require enabled evidence custody.', { reason: 'evidence_custody_required' });
    const rawKeys = environmentValue(env.WORKFORCE_AUDIT_REGULATORY_CASE_KEYS);
    const primaryKeyId = environmentValue(env.WORKFORCE_AUDIT_REGULATORY_CASE_PRIMARY_KEY_ID);
    if (!rawKeys || !primaryKeyId) throw new RegulatoryCaseStoreError('Dedicated regulatory case keys and primary key ID are required.', { reason: 'missing_regulatory_case_keys' });
    const resolveEvidence = (tenantId, selection) => {
      const item = evidenceRegistry.get(tenantId, selection.evidenceId);
      if (item.status === 'disposed') throw new EvidenceConflictError('Disposed evidence cannot be linked to a regulatory case.', { evidenceId: selection.evidenceId });
      const version = item.versions?.find((entry) => entry.version === selection.version);
      if (!version) throw new EvidenceValidationError('The regulatory case evidence version does not exist.', { evidenceId: selection.evidenceId, version: selection.version });
      const content = evidenceRegistry.readContent(tenantId, item.evidenceId, { version: version.version });
      return { evidenceId: item.evidenceId, version: version.version, contentSha256: content.sha256, sizeBytes: content.sizeBytes, filename: version.filename ?? item.filename, mediaType: version.mediaType ?? item.mediaType };
    };
    return createRegulatoryCaseStore({ mode, directory: environmentValue(env.WORKFORCE_AUDIT_REGULATORY_CASE_DIR) ?? '.runtime-data/workforce-audit-regulatory-cases', encryptionKeys: JSON.parse(rawKeys), encryptionPrimaryKeyId: primaryKeyId, resolveEvidence, dueSoonHours: environmentValue(env.WORKFORCE_AUDIT_REGULATORY_CASE_DUE_SOON_HOURS) ?? 72, maximumCases: environmentValue(env.WORKFORCE_AUDIT_REGULATORY_CASE_MAX_CASES) ?? 10000, maximumEvidencePerCase: environmentValue(env.WORKFORCE_AUDIT_REGULATORY_CASE_MAX_EVIDENCE) ?? 500 });
  } catch (error) {
    if (error instanceof RegulatoryCaseStoreError) throw error;
    throw new RegulatoryCaseStoreError('Regulatory case configuration is invalid.', { reason: error?.code ?? 'invalid_configuration' }, error);
  }
}

function normaliseCreate(input, date) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new EvidenceValidationError('A valid regulatory case request is required.');
  const receivedAt = isoDate(input.receivedAt, 'receivedAt');
  const dueAt = isoDate(input.dueAt, 'dueAt');
  if (new Date(dueAt) <= new Date(receivedAt)) throw new EvidenceValidationError('dueAt must be after receivedAt.', { field: 'dueAt' });
  if (new Date(receivedAt) > date.getTime() + 300000) throw new EvidenceValidationError('receivedAt cannot be materially in the future.', { field: 'receivedAt' });
  return { type: enumValue(input.type, CASE_TYPES, 'type'), priority: enumValue(input.priority ?? 'normal', PRIORITIES, 'priority'), authority: cleanText(input.authority, 'authority', 2, 191), jurisdiction: cleanText(input.jurisdiction, 'jurisdiction', 2, 191), requestReference: cleanText(input.requestReference, 'requestReference', 3, 191), legalBasis: cleanText(input.legalBasis, 'legalBasis', 3, 500), summary: cleanText(input.summary, 'summary', 20, 2000), receivedAt, dueAt, owner: identifier(input.owner, 'owner'), evidence: input.evidence ?? [] };
}

function normaliseResolved(input, selection) {
  if (!input || typeof input !== 'object') throw new RegulatoryCaseStoreError('The selected regulatory evidence could not be resolved.', { selection });
  const evidenceId = evidenceIdentifier(input.evidenceId);
  const version = integer(input.version, 'version', 1, 1000000);
  const contentSha256 = hashValue(input.contentSha256, 'contentSha256');
  const sizeBytes = integer(input.sizeBytes, 'sizeBytes', 0, 500000000);
  if (evidenceId !== selection.evidenceId || version !== selection.version) throw new RegulatoryCaseIntegrityError('Resolved evidence does not match the regulatory case selection.', { selection });
  return { evidenceId, version, contentSha256, sizeBytes, filename: cleanText(input.filename, 'filename', 1, 255), mediaType: cleanText(input.mediaType, 'mediaType', 1, 255) };
}

function emptyIndex(tenantId, date) { const time = date.toISOString(); return { format: FORMAT, version: 1, tenantId, createdAt: time, updatedAt: time, sequence: 0, headHash: null, cases: [], events: [] }; }
function appendEvent(index, record, type, actor, details) { const occurredAt = new Date().toISOString(); const event = { eventId: `RGE-${sha256(`${record.caseId}|${type}|${index.sequence + 1}|${occurredAt}|${randomUUID()}`).slice(0, 32)}`, sequence: index.sequence + 1, previousHash: index.headHash, type, caseId: record.caseId, actor, occurredAt, details }; event.hash = eventHash(event); index.events.push(event); index.sequence = event.sequence; index.headHash = event.hash; }
function verifyEventChain(index) { let sequence = 1; let previousHash = null; for (const event of index.events) { if (event.sequence !== sequence || event.previousHash !== previousHash || event.hash !== eventHash(event)) throw new RegulatoryCaseIntegrityError('The regulatory case event chain is invalid.', { eventId: event.eventId, expectedSequence: sequence }); sequence += 1; previousHash = event.hash; } if (index.sequence !== sequence - 1 || index.headHash !== previousHash) throw new RegulatoryCaseIntegrityError('The regulatory case chain head is inconsistent.'); }
function eventHash(event) { const { hash, ...body } = event; return sha256(stableStringify(body)); }
function findCase(index, caseId) { const record = index.cases.find((entry) => entry.caseId === caseId); if (!record) throw new EvidenceValidationError('The regulatory case was not found.', { caseId }); return record; }
function assertEditable(record) { if (!['open', 'response_pending'].includes(record.state)) throw new EvidenceConflictError('The regulatory case cannot be edited in its current state.', { caseId: record.caseId, state: record.state }); }
function deadlineState(record, date, dueSoonMs) { if (['closed', 'cancelled'].includes(record.state)) return 'complete'; const remaining = new Date(record.dueAt).getTime() - date.getTime(); if (remaining < 0) return 'overdue'; if (remaining <= dueSoonMs) return 'due_soon'; return 'on_track'; }
function publicCase(record, date, dueSoonMs) { return { caseId: record.caseId, type: record.type, priority: record.priority, state: record.state, authority: record.authority, jurisdiction: record.jurisdiction, requestReference: record.requestReference, legalBasis: record.legalBasis, summary: record.summary, receivedAt: record.receivedAt, dueAt: record.dueAt, deadlineState: deadlineState(record, date, dueSoonMs), owner: record.owner, evidence: record.evidence.map((entry) => ({ ...entry })), createdAt: record.createdAt, createdBy: record.createdBy, response: record.response ? { ...record.response } : null, closure: record.closure ? { ...record.closure } : null, cancellation: record.cancellation ? { ...record.cancellation } : null }; }
function requireConfirmation(actual, expected) { if (actual !== expected) throw new EvidenceValidationError(`confirmation must be exactly ${expected}.`, { field: 'confirmation' }); }
function indexAad(tenantId) { return `basitclaw:regulatory-cases:${tenantId}`; }
function caseIdentifier(value) { const id = String(value ?? ''); if (!CASE_ID.test(id)) throw new EvidenceValidationError('caseId is invalid.', { field: 'caseId' }); return id; }
function evidenceIdentifier(value) { const id = String(value ?? ''); if (!EVIDENCE_ID.test(id)) throw new EvidenceValidationError('evidenceId is invalid.', { field: 'evidenceId' }); return id; }
function hashValue(value, field) { const text = String(value ?? '').toLowerCase(); if (!HASH.test(text)) throw new EvidenceValidationError(`${field} must be a SHA-256 digest.`, { field }); return text; }
function identifier(value, field) { const text = String(value ?? '').trim(); if (!/^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{1,191}$/.test(text)) throw new EvidenceValidationError(`${field} is invalid.`, { field }); return text; }
function cleanText(value, field, minimum, maximum) { const text = String(value ?? '').trim(); if (text.length < minimum || text.length > maximum) throw new EvidenceValidationError(`${field} must contain ${minimum} to ${maximum} characters.`, { field }); return text; }
function isoDate(value, field) { const date = new Date(String(value ?? '')); if (Number.isNaN(date.getTime())) throw new EvidenceValidationError(`${field} must be a valid ISO date.`, { field }); return date.toISOString(); }
function integer(value, field, minimum, maximum) { const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) throw new EvidenceValidationError(`${field} must be an integer from ${minimum} to ${maximum}.`, { field }); return parsed; }
function enumValue(value, allowed, field) { const text = String(value ?? ''); if (!allowed.has(text)) throw new EvidenceValidationError(`${field} must be one of ${[...allowed].join(', ')}.`, { field }); return text; }
function environmentValue(value) { const clean = typeof value === 'string' ? value.trim() : value; return clean === '' || clean === undefined || clean === null ? undefined : clean; }
function stableStringify(value) { if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`; if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`; return JSON.stringify(value); }

function disabledStore() { const status = Object.freeze({ status: 'disabled', enabled: false, mode: 'disabled' }); const denied = () => { throw new EvidenceConflictError('The regulatory case register is disabled.'); }; return Object.freeze({ mode: 'disabled', enabled: false, createCase: denied, addEvidence: denied, submitResponse: denied, approveResponse: denied, closeCase: denied, cancelCase: denied, list() { return []; }, get: denied, events() { return []; }, verifyTenant(tenantId) { return { valid: true, tenantId, checkedCases: 0, checkedEvents: 0, headSequence: 0, headHash: null }; }, tenantStatus() { return status; }, health() { return status; } }); }
