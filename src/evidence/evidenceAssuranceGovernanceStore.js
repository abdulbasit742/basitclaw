import { randomUUID } from 'node:crypto';
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
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
} from './evidenceCrypto.js';
import {
  EvidenceConflictError,
  EvidenceIntegrityError,
  EvidenceStoreError,
  EvidenceValidationError
} from './evidenceRegistry.js';

const FORMAT = 'basitclaw-assurance-governance-request';
const INDEX_FORMAT = 'basitclaw-assurance-governance-bundle-index';
const MODES = new Set(['disabled', 'shared-file']);
const STATES = new Set(['pending', 'approved', 'sealed', 'rejected', 'revoked', 'delivered', 'expired']);
const REQUEST_ID = /^AGR-[a-f0-9]{32}$/;
const BUNDLE_ID = /^ASB-[a-f0-9]{32}$/;
const EVIDENCE_ID = /^EVD-[a-f0-9]{32}$/;
const HASH = /^[a-f0-9]{64}$/;
const SAFE_ID = /^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{1,191}$/;

export class EvidenceAssuranceGovernanceStoreError extends EvidenceStoreError {
  constructor(message = 'The assurance governance store is unavailable.', details = {}, cause = null) {
    super(message, details, cause);
    this.name = 'EvidenceAssuranceGovernanceStoreError';
    this.code = 'EVIDENCE_ASSURANCE_GOVERNANCE_STORE_UNAVAILABLE';
  }
}

export class EvidenceAssuranceGovernanceIntegrityError extends EvidenceIntegrityError {
  constructor(message = 'Assurance governance integrity verification failed.', details = {}, cause = null) {
    super(message, details, cause);
    this.name = 'EvidenceAssuranceGovernanceIntegrityError';
    this.code = 'EVIDENCE_ASSURANCE_GOVERNANCE_INTEGRITY_FAILED';
  }
}

export function createEvidenceAssuranceGovernanceStore({
  mode = 'disabled',
  required = false,
  directory,
  encryptionKeys,
  encryptionPrimaryKeyId,
  recipientPolicies = {},
  approvalQuorum = 2,
  requestTtlMinutes = 1440,
  maximumRequests = 100_000,
  now = () => new Date(),
  mutex = null
} = {}) {
  const selectedMode = enumValue(mode, MODES, 'mode');
  const isRequired = booleanValue(required, 'required');
  if (selectedMode === 'disabled') {
    if (isRequired) throw new TypeError('Required assurance governance cannot be disabled.');
    return disabledStore();
  }
  if (!String(directory ?? '').trim()) throw new TypeError('An assurance governance directory is required.');
  const root = resolve(String(directory));
  const encryption = parseEvidenceKeyring(encryptionKeys, encryptionPrimaryKeyId);
  const policies = parsePolicies(recipientPolicies);
  const quorum = integer(approvalQuorum, 'approvalQuorum', 2, 10);
  const ttlMs = integer(requestTtlMinutes, 'requestTtlMinutes', 5, 43_200) * 60_000;
  const limit = integer(maximumRequests, 'maximumRequests', 100, 1_000_000);
  const lock = mutex ?? createFileMutex({ directory: resolve(root, '.locks'), now });
  mkdirSync(root, { recursive: true, mode: 0o700 });

  function request(input, { actor, role } = {}) {
    const source = validateRequest(input, policies, now, ttlMs);
    const requester = identifier(actor, 'actor');
    const requesterRole = identifier(role, 'role');
    return lock.withLock(`assurance-governance:${source.tenantId}`, () => {
      if (requestNames(source.tenantId).length >= limit) {
        throw new EvidenceAssuranceGovernanceStoreError('The assurance governance request limit has been reached.', { maximumRequests: limit });
      }
      const requestId = `AGR-${randomUUID().replaceAll('-', '')}`;
      const requestedAt = now().toISOString();
      const record = {
        format: FORMAT,
        version: 1,
        requestId,
        tenantId: source.tenantId,
        evidenceId: source.evidenceId,
        evidenceVersion: source.evidenceVersion,
        contentSha256: source.contentSha256,
        recipientId: source.recipientId,
        purpose: source.purpose,
        purposeCode: source.purposeCode,
        legalBasis: source.legalBasis,
        residencyZone: source.residencyZone,
        requestedBy: requester,
        requestedByRole: requesterRole,
        requestedAt,
        expiresAt: source.expiresAt,
        state: 'pending',
        approvals: [],
        bundleId: null,
        bundlePackageSha256: null,
        sealedAt: null,
        rejectedAt: null,
        revokedAt: null,
        deliveredAt: null,
        events: []
      };
      appendEvent(record, 'assurance_governance.requested', requester, {
        recipientId: source.recipientId,
        purposeCode: source.purposeCode,
        legalBasis: source.legalBasis,
        residencyZone: source.residencyZone
      }, requestedAt);
      writeRecord(record);
      return publicRecord(record, quorum);
    });
  }

  function approve(tenantId, requestId, { actor, role } = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = requestIdentifier(requestId);
    const approver = identifier(actor, 'actor');
    const approverRole = identifier(role, 'role');
    return lock.withLock(`assurance-governance:${tenant}`, () => {
      const record = readRecord(tenant, id);
      persistExpiry(record);
      if (!['pending', 'approved'].includes(record.state)) {
        throw new EvidenceConflictError('Only an active assurance request can be approved.', { requestId: id, state: record.state });
      }
      if (record.requestedBy === approver) {
        throw new EvidenceConflictError('The assurance requester cannot approve their own request.', { requestId: id });
      }
      if (record.approvals.some((entry) => entry.actor === approver)) {
        throw new EvidenceConflictError('The principal has already approved this assurance request.', { requestId: id });
      }
      const approvedAt = now().toISOString();
      record.approvals.push({ actor: approver, role: approverRole, approvedAt });
      record.state = record.approvals.length >= quorum ? 'approved' : 'pending';
      appendEvent(record, 'assurance_governance.approved', approver, {
        approvals: record.approvals.length,
        quorum
      }, approvedAt);
      writeRecord(record);
      return publicRecord(record, quorum);
    });
  }

  function attachBundle(tenantId, requestId, { bundleId, packageSha256 } = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = requestIdentifier(requestId);
    const bundle = bundleIdentifier(bundleId);
    const packageDigest = hashValue(packageSha256, 'packageSha256');
    return lock.withLock(`assurance-governance:${tenant}`, () => {
      const record = readRecord(tenant, id);
      persistExpiry(record);
      if (record.state === 'sealed' && record.bundleId === bundle && record.bundlePackageSha256 === packageDigest) {
        return publicRecord(record, quorum);
      }
      if (record.state !== 'approved' || record.approvals.length < quorum) {
        throw new EvidenceConflictError('The assurance request has not reached approval quorum.', { requestId: id, state: record.state });
      }
      if (lookupBundleLocked(bundle)) throw new EvidenceAssuranceGovernanceIntegrityError('The assurance bundle is already linked to another governance request.', { bundleId: bundle });
      record.state = 'sealed';
      record.bundleId = bundle;
      record.bundlePackageSha256 = packageDigest;
      record.sealedAt = now().toISOString();
      appendEvent(record, 'assurance_governance.bundle_sealed', 'system', { bundleId: bundle, packageSha256: packageDigest }, record.sealedAt);
      writeRecord(record);
      updateBundleIndex((index) => { index.entries[bundle] = { tenantId: tenant, requestId: id }; });
      return publicRecord(record, quorum);
    });
  }

  function reject(tenantId, requestId, { actor, reason } = {}) {
    return transition(tenantId, requestId, actor, reason, 'rejected', 'assurance_governance.rejected');
  }

  function revoke(tenantId, requestId, { actor, reason } = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = requestIdentifier(requestId);
    const principal = identifier(actor, 'actor');
    const cleanReason = cleanText(reason, 'reason', 10, 500);
    return lock.withLock(`assurance-governance:${tenant}`, () => {
      const record = readRecord(tenant, id);
      if (record.state === 'delivered') throw new EvidenceConflictError('A delivered assurance bundle cannot be retroactively revoked.', { requestId: id });
      if (['rejected', 'revoked', 'expired'].includes(record.state)) throw new EvidenceConflictError('The assurance request is already terminal.', { requestId: id, state: record.state });
      record.state = 'revoked';
      record.revokedAt = now().toISOString();
      appendEvent(record, 'assurance_governance.revoked', principal, { reason: cleanReason, bundleId: record.bundleId }, record.revokedAt);
      writeRecord(record);
      return publicRecord(record, quorum);
    });
  }

  function deliveryAllowed(bundleId) {
    const bundle = bundleIdentifier(bundleId);
    return lock.withLock('assurance-governance:bundle-index', () => {
      const reference = lookupBundleLocked(bundle);
      if (!reference) return false;
      const record = readRecord(reference.tenantId, reference.requestId);
      if (expireRecord(record, now())) writeRecord(record);
      return record.state === 'sealed';
    });
  }

  function recordSuppressedDelivery(bundleId, recipientId) {
    const bundle = bundleIdentifier(bundleId);
    const recipient = identifier(recipientId, 'recipientId');
    return lock.withLock('assurance-governance:bundle-index', () => {
      const reference = lookupBundleLocked(bundle);
      if (!reference) return null;
      const record = readRecord(reference.tenantId, reference.requestId);
      const last = record.events.at(-1);
      if (last?.type !== 'assurance_governance.delivery_suppressed' || last?.details?.recipientId !== recipient) {
        appendEvent(record, 'assurance_governance.delivery_suppressed', 'system', { bundleId: bundle, recipientId: recipient, state: record.state }, now().toISOString());
        writeRecord(record);
      }
      return publicRecord(record, quorum);
    });
  }

  function markDelivered(bundleId, recipientId) {
    const bundle = bundleIdentifier(bundleId);
    const recipient = identifier(recipientId, 'recipientId');
    return lock.withLock('assurance-governance:bundle-index', () => {
      const reference = lookupBundleLocked(bundle);
      if (!reference) throw new EvidenceAssuranceGovernanceIntegrityError('The delivered bundle is not linked to a governance request.', { bundleId: bundle });
      const record = readRecord(reference.tenantId, reference.requestId);
      if (record.state === 'delivered') return publicRecord(record, quorum);
      if (record.state !== 'sealed') throw new EvidenceConflictError('The assurance request no longer permits delivery acknowledgement.', { bundleId: bundle, state: record.state });
      record.state = 'delivered';
      record.deliveredAt = now().toISOString();
      appendEvent(record, 'assurance_governance.delivered', recipient, { bundleId: bundle }, record.deliveredAt);
      writeRecord(record);
      return publicRecord(record, quorum);
    });
  }

  function get(tenantId, requestId) {
    const tenant = identifier(tenantId, 'tenantId');
    return lock.withLock(`assurance-governance:${tenant}`, () => {
      const record = readRecord(tenant, requestIdentifier(requestId));
      if (expireRecord(record, now())) writeRecord(record);
      return publicRecord(record, quorum);
    });
  }

  function list(tenantId, { evidenceId = null, state = null, limit: requestedLimit = 500 } = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const evidence = evidenceId === null ? null : evidenceIdentifier(evidenceId);
    const selectedState = state === null ? null : enumValue(state, STATES, 'state');
    const maximum = integer(requestedLimit, 'limit', 1, 5000);
    return lock.withLock(`assurance-governance:${tenant}`, () => {
      const rows = [];
      for (const name of requestNames(tenant)) {
        const record = readRecord(tenant, name.slice(0, -5));
        if (expireRecord(record, now())) writeRecord(record);
        if (evidence && record.evidenceId !== evidence) continue;
        if (selectedState && record.state !== selectedState) continue;
        rows.push(publicRecord(record, quorum));
      }
      return rows.sort((a, b) => b.requestedAt.localeCompare(a.requestedAt)).slice(0, maximum);
    });
  }

  function report(tenantId) {
    const rows = list(tenantId, { limit: 5000 });
    const byState = Object.fromEntries([...STATES].map((state) => [state, 0]));
    const byRecipient = {};
    const byPurposeCode = {};
    const byResidencyZone = {};
    for (const row of rows) {
      byState[row.state] += 1;
      byRecipient[row.recipientId] = (byRecipient[row.recipientId] ?? 0) + 1;
      byPurposeCode[row.purposeCode] = (byPurposeCode[row.purposeCode] ?? 0) + 1;
      byResidencyZone[row.residencyZone] = (byResidencyZone[row.residencyZone] ?? 0) + 1;
    }
    return { total: rows.length, approvalQuorum: quorum, byState, byRecipient, byPurposeCode, byResidencyZone };
  }

  function verifyTenant(tenantId) {
    const tenant = identifier(tenantId, 'tenantId');
    return lock.withLock(`assurance-governance:${tenant}`, () => {
      let checkedRequests = 0;
      let checkedEvents = 0;
      for (const name of requestNames(tenant)) {
        const record = readRecord(tenant, name.slice(0, -5));
        verifyRecord(record);
        checkedRequests += 1;
        checkedEvents += record.events.length;
      }
      return { valid: true, tenantId: tenant, checkedRequests, checkedEvents };
    });
  }

  function health() {
    try {
      mkdirSync(root, { recursive: true, mode: 0o700 });
      return {
        status: policies.size ? 'ready' : 'attention',
        enabled: true,
        required: isRequired,
        mode: 'encrypted-assurance-approval-governance',
        encryptedRecords: true,
        hashChainedEvents: true,
        approvalQuorum: quorum,
        recipientPolicies: policies.size,
        requestTtlMinutes: ttlMs / 60_000,
        mutex: lock.health()
      };
    } catch (error) {
      return { status: 'unavailable', enabled: true, required: isRequired, error: error?.code ?? 'assurance_governance_store_unavailable' };
    }
  }

  function transition(tenantId, requestId, actor, reason, state, eventType) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = requestIdentifier(requestId);
    const principal = identifier(actor, 'actor');
    const cleanReason = cleanText(reason, 'reason', 10, 500);
    return lock.withLock(`assurance-governance:${tenant}`, () => {
      const record = readRecord(tenant, id);
      if (!['pending', 'approved'].includes(record.state)) throw new EvidenceConflictError('Only an unsealed assurance request can be rejected.', { requestId: id, state: record.state });
      record.state = state;
      record.rejectedAt = now().toISOString();
      appendEvent(record, eventType, principal, { reason: cleanReason }, record.rejectedAt);
      writeRecord(record);
      return publicRecord(record, quorum);
    });
  }

  function persistExpiry(record) {
    if (expireRecord(record, now())) {
      writeRecord(record);
      throw new EvidenceConflictError('The assurance governance request has expired.', { requestId: record.requestId });
    }
  }

  function writeRecord(record) {
    verifyRecord(record);
    const path = recordPath(root, record.tenantId, record.requestId);
    atomicWrite(path, encryptEvidenceJson(record, encryption, recordAad(record.tenantId, record.requestId)));
  }

  function readRecord(tenantId, requestId) {
    const path = recordPath(root, tenantId, requestId);
    if (!existsSync(path)) throw new EvidenceValidationError('The assurance governance request was not found.', { requestId });
    try {
      const record = decryptEvidenceJson(readEvidenceJson(path), encryption, recordAad(tenantId, requestId), EvidenceAssuranceGovernanceIntegrityError);
      verifyRecord(record);
      return record;
    } catch (error) {
      if (error instanceof EvidenceAssuranceGovernanceIntegrityError) throw error;
      throw new EvidenceAssuranceGovernanceStoreError('An assurance governance request is unreadable.', { requestId }, error);
    }
  }

  function lookupBundleLocked(bundleId) {
    const index = readBundleIndex();
    return index.entries[bundleId] ?? null;
  }

  function updateBundleIndex(mutator) {
    const index = readBundleIndex();
    mutator(index);
    index.updatedAt = now().toISOString();
    atomicWrite(indexPath(root), encryptEvidenceJson(index, encryption, indexAad()));
  }

  function readBundleIndex() {
    const path = indexPath(root);
    if (!existsSync(path)) return { format: INDEX_FORMAT, version: 1, entries: {}, updatedAt: null };
    try {
      const index = decryptEvidenceJson(readEvidenceJson(path), encryption, indexAad(), EvidenceAssuranceGovernanceIntegrityError);
      if (!index || index.format !== INDEX_FORMAT || index.version !== 1 || !index.entries || typeof index.entries !== 'object' || Array.isArray(index.entries)) {
        throw new EvidenceAssuranceGovernanceIntegrityError('The assurance governance bundle index is invalid.');
      }
      return index;
    } catch (error) {
      if (error instanceof EvidenceAssuranceGovernanceIntegrityError) throw error;
      throw new EvidenceAssuranceGovernanceStoreError('The assurance governance bundle index is unreadable.', {}, error);
    }
  }

  return Object.freeze({
    enabled: true,
    required: isRequired,
    mode: selectedMode,
    approvalQuorum: quorum,
    request,
    approve,
    attachBundle,
    reject,
    revoke,
    deliveryAllowed,
    recordSuppressedDelivery,
    markDelivered,
    get,
    list,
    report,
    verifyTenant,
    health
  });
}

export function createEvidenceAssuranceGovernanceStoreFromEnvironment({ env = process.env } = {}) {
  const mode = envValue(env.WORKFORCE_AUDIT_ASSURANCE_GOVERNANCE_MODE) ?? 'disabled';
  const required = parseBoolean(envValue(env.WORKFORCE_AUDIT_ASSURANCE_GOVERNANCE_REQUIRED) ?? false);
  if (mode === 'disabled') return createEvidenceAssuranceGovernanceStore({ mode, required });
  const keysRaw = envValue(env.WORKFORCE_AUDIT_ASSURANCE_GOVERNANCE_KEYS);
  const primaryKeyId = envValue(env.WORKFORCE_AUDIT_ASSURANCE_GOVERNANCE_PRIMARY_KEY_ID);
  const policiesRaw = envValue(env.WORKFORCE_AUDIT_ASSURANCE_RECIPIENT_POLICIES);
  if (!keysRaw) throw new EvidenceAssuranceGovernanceStoreError('Dedicated assurance governance encryption keys are required.', { reason: 'missing_governance_keys' });
  if (!primaryKeyId) throw new EvidenceAssuranceGovernanceStoreError('The assurance governance primary key ID is required.', { reason: 'missing_governance_primary_key_id' });
  if (!policiesRaw) throw new EvidenceAssuranceGovernanceStoreError('Assurance recipient policies are required.', { reason: 'missing_recipient_policies' });
  try {
    return createEvidenceAssuranceGovernanceStore({
      mode,
      required,
      directory: envValue(env.WORKFORCE_AUDIT_ASSURANCE_GOVERNANCE_DIR),
      encryptionKeys: JSON.parse(keysRaw),
      encryptionPrimaryKeyId: primaryKeyId,
      recipientPolicies: JSON.parse(policiesRaw),
      approvalQuorum: envValue(env.WORKFORCE_AUDIT_ASSURANCE_APPROVAL_QUORUM) ?? 2,
      requestTtlMinutes: envValue(env.WORKFORCE_AUDIT_ASSURANCE_REQUEST_TTL_MINUTES) ?? 1440,
      maximumRequests: envValue(env.WORKFORCE_AUDIT_ASSURANCE_GOVERNANCE_MAX_REQUESTS) ?? 100_000
    });
  } catch (error) {
    if (error instanceof EvidenceAssuranceGovernanceStoreError) throw error;
    throw new EvidenceAssuranceGovernanceStoreError('Assurance governance configuration is invalid.', { reason: error?.code ?? 'invalid_configuration' }, error);
  }
}

function parsePolicies(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new TypeError('Assurance recipient policies must be an object.');
  const entries = Object.entries(raw);
  if (!entries.length || entries.length > 100) throw new TypeError('Assurance recipient policies must contain 1 to 100 entries.');
  const policies = new Map();
  for (const [recipientId, input] of entries) {
    identifier(recipientId, 'recipientId');
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw new TypeError(`Assurance recipient policy ${recipientId} must be an object.`);
    const allowedTenants = setOfIdentifiers(input.allowedTenants, `recipient policy ${recipientId} allowedTenants`);
    const allowedResidencyZones = setOfIdentifiers(input.allowedResidencyZones, `recipient policy ${recipientId} allowedResidencyZones`);
    const allowedPurposeCodes = setOfIdentifiers(input.allowedPurposeCodes, `recipient policy ${recipientId} allowedPurposeCodes`);
    const allowedLegalBases = setOfIdentifiers(input.allowedLegalBases, `recipient policy ${recipientId} allowedLegalBases`);
    const validUntil = input.validUntil ? isoDate(input.validUntil, `recipient policy ${recipientId} validUntil`) : null;
    policies.set(recipientId, Object.freeze({
      recipientId,
      enabled: input.enabled !== false,
      allowedTenants,
      allowedResidencyZones,
      allowedPurposeCodes,
      allowedLegalBases,
      validUntil
    }));
  }
  return policies;
}

function validateRequest(input, policies, now, ttlMs) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new EvidenceValidationError('A valid assurance governance request is required.');
  const tenantId = identifier(input.tenantId, 'tenantId');
  const evidenceId = evidenceIdentifier(input.evidenceId);
  const evidenceVersion = integer(input.evidenceVersion, 'evidenceVersion', 1, 1_000_000);
  const contentSha256 = hashValue(input.contentSha256, 'contentSha256');
  const recipientId = identifier(input.recipientId, 'recipientId');
  const policy = policies.get(recipientId);
  if (!policy || !policy.enabled) throw new EvidenceConflictError('The assurance recipient is not operationally approved.', { recipientId });
  if (policy.validUntil && new Date(policy.validUntil) <= now()) throw new EvidenceConflictError('The assurance recipient policy has expired.', { recipientId, validUntil: policy.validUntil });
  if (!policy.allowedTenants.has('*') && !policy.allowedTenants.has(tenantId)) throw new EvidenceConflictError('The assurance recipient is not approved for this tenant.', { recipientId, tenantId });
  const purposeCode = identifier(input.purposeCode, 'purposeCode');
  if (!policy.allowedPurposeCodes.has(purposeCode)) throw new EvidenceConflictError('The assurance purpose code is not approved for this recipient.', { recipientId, purposeCode });
  const legalBasis = identifier(input.legalBasis, 'legalBasis');
  if (!policy.allowedLegalBases.has(legalBasis)) throw new EvidenceConflictError('The assurance legal basis is not approved for this recipient.', { recipientId, legalBasis });
  const residencyZone = identifier(input.residencyZone, 'residencyZone');
  if (!policy.allowedResidencyZones.has(residencyZone)) throw new EvidenceConflictError('The assurance residency zone is not approved for this recipient.', { recipientId, residencyZone });
  const requestedAt = now();
  return {
    tenantId,
    evidenceId,
    evidenceVersion,
    contentSha256,
    recipientId,
    purpose: cleanText(input.purpose, 'purpose', 10, 500),
    purposeCode,
    legalBasis,
    residencyZone,
    expiresAt: new Date(requestedAt.getTime() + ttlMs).toISOString()
  };
}

function expireRecord(record, current) {
  if (!['delivered', 'rejected', 'revoked', 'expired'].includes(record.state) && new Date(record.expiresAt) <= current) {
    record.state = 'expired';
    appendEvent(record, 'assurance_governance.expired', 'system', { bundleId: record.bundleId }, current.toISOString());
    return true;
  }
  return false;
}

function verifyRecord(record) {
  if (!record || record.format !== FORMAT || record.version !== 1 || !REQUEST_ID.test(record.requestId)
      || !EVIDENCE_ID.test(record.evidenceId) || !HASH.test(record.contentSha256) || !STATES.has(record.state)) {
    throw new EvidenceAssuranceGovernanceIntegrityError('An assurance governance request has an invalid identity.', { requestId: record?.requestId ?? null });
  }
  let previousHash = '0'.repeat(64);
  for (let index = 0; index < record.events.length; index += 1) {
    const event = record.events[index];
    const suppliedHash = event.recordHash;
    const { recordHash, ...body } = event;
    if (event.sequence !== index + 1 || event.previousHash !== previousHash || suppliedHash !== sha256(stableStringify(body))) {
      throw new EvidenceAssuranceGovernanceIntegrityError('The assurance governance event chain is invalid.', { requestId: record.requestId, sequence: index + 1 });
    }
    previousHash = suppliedHash;
  }
  if (record.state === 'sealed' || record.state === 'delivered') {
    if (!BUNDLE_ID.test(record.bundleId ?? '') || !HASH.test(record.bundlePackageSha256 ?? '')) {
      throw new EvidenceAssuranceGovernanceIntegrityError('The assurance governance bundle link is invalid.', { requestId: record.requestId });
    }
  }
}

function publicRecord(record, quorum) {
  return {
    requestId: record.requestId,
    evidenceId: record.evidenceId,
    evidenceVersion: record.evidenceVersion,
    contentSha256: record.contentSha256,
    recipientId: record.recipientId,
    purpose: record.purpose,
    purposeCode: record.purposeCode,
    legalBasis: record.legalBasis,
    residencyZone: record.residencyZone,
    requestedBy: record.requestedBy,
    requestedByRole: record.requestedByRole,
    requestedAt: record.requestedAt,
    expiresAt: record.expiresAt,
    state: record.state,
    approvals: record.approvals.map((entry) => ({ ...entry })),
    approvalQuorum: quorum,
    readyToSeal: record.state === 'approved' && record.approvals.length >= quorum,
    bundleId: record.bundleId,
    bundlePackageSha256: record.bundlePackageSha256,
    sealedAt: record.sealedAt,
    rejectedAt: record.rejectedAt,
    revokedAt: record.revokedAt,
    deliveredAt: record.deliveredAt,
    eventCount: record.events.length,
    chainHead: record.events.at(-1)?.recordHash ?? null
  };
}

function appendEvent(record, type, actor, details, timestamp) {
  const previousHash = record.events.at(-1)?.recordHash ?? '0'.repeat(64);
  const event = { sequence: record.events.length + 1, type, actor, timestamp, details, previousHash };
  event.recordHash = sha256(stableStringify(event));
  record.events.push(event);
}

function atomicWrite(path, value) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.${randomUUID()}.tmp`;
  let descriptor = null;
  try {
    descriptor = openSync(temporary, 'wx', 0o600);
    writeFileSync(descriptor, `${JSON.stringify(value)}\n`, 'utf8');
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = null;
    renameSync(temporary, path);
    fsyncDirectory(dirname(path));
  } catch (error) {
    if (descriptor !== null) try { closeSync(descriptor); } catch {}
    try { rmSync(temporary, { force: true }); } catch {}
    throw new EvidenceAssuranceGovernanceStoreError('The assurance governance state could not be committed.', {}, error);
  }
}

function fsyncDirectory(path) { const descriptor = openSync(path, 'r'); try { fsyncSync(descriptor); } finally { closeSync(descriptor); } }
function tenantDirectory(root, tenantId) { const path = resolve(root, sha256(`tenant:${identifier(tenantId, 'tenantId')}`)); mkdirSync(path, { recursive: true, mode: 0o700 }); return path; }
function recordPath(root, tenantId, requestId) { return resolve(tenantDirectory(root, tenantId), `${requestId}.json`); }
function requestNames(tenantId) { return readdirSync(tenantDirectory(this?.root ?? '', tenantId)); }
