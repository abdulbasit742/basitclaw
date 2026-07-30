import {
  constants,
  createPublicKey,
  publicEncrypt,
  randomBytes
} from 'node:crypto';
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync
} from 'node:fs';
import { dirname, resolve } from 'node:path';
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
  EvidenceValidationError
} from './evidenceRegistry.js';

const INDEX_FORMAT = 'basitclaw-evidence-disclosure-index';
const PACKAGE_FORMAT = 'basitclaw-evidence-disclosure-package';
const REQUEST_ID = /^DSR-[a-f0-9]{32}$/;
const PACKAGE_ID = /^DSP-[a-f0-9]{32}$/;
const EVIDENCE_ID = /^EVD-[a-f0-9]{32}$/;
const HASH = /^[a-f0-9]{64}$/;
const MODES = new Set(['disabled', 'shared-file']);
const STATES = new Set(['pending', 'packaged', 'rejected', 'revoked']);
const PACKAGE_ALGORITHM = 'RSA-OAEP-SHA256+A256GCM';

export class EvidenceDisclosureStoreError extends EvidenceStoreError {
  constructor(message = 'The evidence disclosure store is unavailable.', details = {}, cause = null) {
    super(message, details, cause);
    this.name = 'EvidenceDisclosureStoreError';
    this.code = 'EVIDENCE_DISCLOSURE_STORE_UNAVAILABLE';
  }
}

export class EvidenceDisclosureIntegrityError extends EvidenceIntegrityError {
  constructor(message = 'Evidence disclosure integrity verification failed.', details = {}, cause = null) {
    super(message, details, cause);
    this.name = 'EvidenceDisclosureIntegrityError';
    this.code = 'EVIDENCE_DISCLOSURE_INTEGRITY_FAILED';
  }
}

export class EvidenceDisclosureApprovalError extends EvidenceConflictError {
  constructor(message = 'The evidence disclosure approval policy is not satisfied.', details = {}) {
    super(message, details);
    this.name = 'EvidenceDisclosureApprovalError';
    this.code = 'EVIDENCE_DISCLOSURE_APPROVAL_REQUIRED';
  }
}

export function createEvidenceDisclosureStore({
  mode = 'disabled',
  directory,
  encryptionKeys,
  encryptionPrimaryKeyId,
  minimumApprovers = 2,
  maximumEvidenceItems = 100,
  maximumPackageBytes = 25_000_000,
  maximumTtlHours = 168,
  resolveEvidence,
  now = () => new Date(),
  mutex = null
} = {}) {
  const selectedMode = enumValue(mode, MODES, 'mode');
  if (selectedMode === 'disabled') return disabledStore();
  if (!String(directory ?? '').trim()) throw new TypeError('An evidence disclosure directory is required.');
  if (typeof resolveEvidence !== 'function') throw new TypeError('An evidence disclosure resolver is required.');

  const root = resolve(String(directory));
  const encryption = parseEvidenceKeyring(encryptionKeys, encryptionPrimaryKeyId);
  const approvalQuorum = integer(minimumApprovers, 'minimumApprovers', 1, 10);
  const itemLimit = integer(maximumEvidenceItems, 'maximumEvidenceItems', 1, 1000);
  const byteLimit = integer(maximumPackageBytes, 'maximumPackageBytes', 1024, 500_000_000);
  const ttlLimitHours = integer(maximumTtlHours, 'maximumTtlHours', 1, 720);
  const lock = mutex ?? createFileMutex({ directory: resolve(root, '.locks'), now });
  mkdirSync(root, { recursive: true, mode: 0o700 });

  function createRequest(input, context = {}) {
    const request = normaliseCreate(input, context, {
      itemLimit,
      ttlLimitHours,
      now
    });
    const recipient = parseRecipientKey(request.recipientPublicKeyPem);
    const resolved = request.evidence.map((selection) => normaliseResolved(
      resolveEvidence(request.tenantId, selection),
      selection
    ));
    const selections = resolved.map((entry) => publicSelection(entry));
    const requestId = `DSR-${sha256(stableStringify({
      tenantId: request.tenantId,
      requester: request.requestedBy,
      recipientId: request.recipientId,
      recipientKeyFingerprint: recipient.fingerprint,
      caseReference: request.caseReference,
      purpose: request.purpose,
      evidence: selections,
      requestedAt: request.requestedAt,
      expiresAt: request.expiresAt
    })).slice(0, 32)}`;

    return lock.withLock(`evidence-disclosures:${request.tenantId}`, () => {
      const index = loadIndex(request.tenantId);
      const duplicate = index.requests.find((entry) => entry.requestId === requestId);
      if (duplicate) return { created: false, duplicate: true, request: publicRequest(duplicate, now()) };
      const record = {
        requestId,
        tenantId: request.tenantId,
        state: 'pending',
        requestedBy: request.requestedBy,
        requestedAt: request.requestedAt,
        expiresAt: request.expiresAt,
        recipientId: request.recipientId,
        recipientKeyId: request.recipientKeyId,
        recipientPublicKeyPem: recipient.publicKeyPem,
        recipientKeyFingerprint: recipient.fingerprint,
        caseReference: request.caseReference,
        purpose: request.purpose,
        evidence: selections,
        approvals: [],
        rejectedAt: null,
        rejectedBy: null,
        rejectionReason: null,
        revokedAt: null,
        revokedBy: null,
        revocationReason: null,
        packageId: null,
        packageEnvelopeSha256: null,
        packagedAt: null
      };
      index.requests.push(record);
      appendEvent(index, {
        type: 'disclosure.requested',
        requestId,
        actor: request.requestedBy,
        details: {
          recipientId: request.recipientId,
          recipientKeyFingerprint: recipient.fingerprint,
          evidenceCount: selections.length,
          caseReference: request.caseReference
        },
        occurredAt: request.requestedAt
      });
      saveIndex(request.tenantId, index);
      return { created: true, duplicate: false, request: publicRequest(record, now()) };
    });
  }

  function approve(tenantId, requestId, input, context = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = requestIdentifier(requestId);
    const actor = identifier(context.actor, 'actor');
    const reason = cleanText(input?.reason, 'reason', 10, 500);
    if (input?.confirmation !== `APPROVE DISCLOSURE ${id}`) {
      throw new EvidenceValidationError(`confirmation must be exactly APPROVE DISCLOSURE ${id}.`, { field: 'confirmation' });
    }
    return lock.withLock(`evidence-disclosures:${tenant}`, () => {
      const index = loadIndex(tenant);
      const record = findRequest(index, id);
      assertPending(record, now());
      if (record.requestedBy === actor) {
        throw new EvidenceDisclosureApprovalError('The disclosure requester cannot approve their own request.', {
          requestId: id,
          reason: 'self_approval'
        });
      }
      if (record.approvals.some((entry) => entry.actor === actor)) {
        throw new EvidenceDisclosureApprovalError('The disclosure approver has already approved this request.', {
          requestId: id,
          reason: 'duplicate_approval'
        });
      }
      const approvedAt = now().toISOString();
      record.approvals.push({ actor, reason, approvedAt });
      appendEvent(index, {
        type: 'disclosure.approved', requestId: id, actor,
        details: { approvalCount: record.approvals.length, minimumApprovers: approvalQuorum },
        occurredAt: approvedAt
      });
      let packaged = false;
      if (record.approvals.length >= approvalQuorum) {
        packageRecord(record);
        packaged = true;
        appendEvent(index, {
          type: 'disclosure.packaged', requestId: id, actor,
          details: { packageId: record.packageId, evidenceCount: record.evidence.length },
          occurredAt: record.packagedAt
        });
      }
      saveIndex(tenant, index);
      return { approved: true, packaged, request: publicRequest(record, now()) };
    });
  }

  function reject(tenantId, requestId, input, context = {}) {
    return terminalDecision('rejected', tenantId, requestId, input, context);
  }

  function revoke(tenantId, requestId, input, context = {}) {
    return terminalDecision('revoked', tenantId, requestId, input, context);
  }

  function terminalDecision(decision, tenantId, requestId, input, context) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = requestIdentifier(requestId);
    const actor = identifier(context.actor, 'actor');
    const reason = cleanText(input?.reason, 'reason', 10, 500);
    const confirmation = `${decision === 'rejected' ? 'REJECT' : 'REVOKE'} DISCLOSURE ${id}`;
    if (input?.confirmation !== confirmation) {
      throw new EvidenceValidationError(`confirmation must be exactly ${confirmation}.`, { field: 'confirmation' });
    }
    return lock.withLock(`evidence-disclosures:${tenant}`, () => {
      const index = loadIndex(tenant);
      const record = findRequest(index, id);
      if (decision === 'rejected') {
        assertPending(record, now());
        record.state = 'rejected';
        record.rejectedAt = now().toISOString();
        record.rejectedBy = actor;
        record.rejectionReason = reason;
      } else {
        if (!['pending', 'packaged'].includes(record.state)) {
          throw new EvidenceConflictError('Only pending or packaged disclosures can be revoked.', { requestId: id, state: record.state });
        }
        record.state = 'revoked';
        record.revokedAt = now().toISOString();
        record.revokedBy = actor;
        record.revocationReason = reason;
      }
      appendEvent(index, {
        type: `disclosure.${decision}`, requestId: id, actor,
        details: { reason },
        occurredAt: decision === 'rejected' ? record.rejectedAt : record.revokedAt
      });
      saveIndex(tenant, index);
      return { updated: true, request: publicRequest(record, now()) };
    });
  }

  function list(tenantId, { state = null, limit = 200 } = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const selectedState = state === null ? null : enumValue(state, STATES, 'state');
    const index = loadSafe(tenant);
    return index.requests
      .filter((entry) => !selectedState || effectiveState(entry, now()) === selectedState)
      .sort((left, right) => right.requestedAt.localeCompare(left.requestedAt))
      .slice(0, integer(limit, 'limit', 1, 2000))
      .map((entry) => publicRequest(entry, now()));
  }

  function get(tenantId, requestId) {
    const tenant = identifier(tenantId, 'tenantId');
    const record = findRequest(loadSafe(tenant), requestIdentifier(requestId));
    return publicRequest(record, now());
  }

  function sealedPackage(tenantId, requestId) {
    const tenant = identifier(tenantId, 'tenantId');
    const record = findRequest(loadSafe(tenant), requestIdentifier(requestId));
    const state = effectiveState(record, now());
    if (state !== 'packaged') {
      throw new EvidenceConflictError('The disclosure package is not available.', {
        requestId: record.requestId,
        state
      });
    }
    const envelope = readPackage(tenant, record.packageId);
    const digest = sha256(Buffer.from(stableStringify(envelope)));
    if (digest !== record.packageEnvelopeSha256) {
      throw new EvidenceDisclosureIntegrityError('The disclosure package envelope does not match its request record.', {
        requestId: record.requestId,
        packageId: record.packageId
      });
    }
    return envelope;
  }

  function events(tenantId, requestId = null, { limit = 500 } = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = requestId === null ? null : requestIdentifier(requestId);
    return loadSafe(tenant).events
      .filter((entry) => !id || entry.requestId === id)
      .slice(-integer(limit, 'limit', 1, 5000))
      .reverse()
      .map((entry) => ({ ...entry }));
  }

  function verifyTenant(tenantId) {
    const tenant = identifier(tenantId, 'tenantId');
    const index = loadSafe(tenant);
    let checkedPackages = 0;
    for (const record of index.requests) {
      if (!record.packageId) continue;
      const envelope = readPackage(tenant, record.packageId);
      if (sha256(Buffer.from(stableStringify(envelope))) !== record.packageEnvelopeSha256) {
        throw new EvidenceDisclosureIntegrityError('A disclosure package envelope digest is invalid.', {
          requestId: record.requestId,
          packageId: record.packageId
        });
      }
      checkedPackages += 1;
    }
    return {
      valid: true,
      tenantId: tenant,
      checkedRequests: index.requests.length,
      checkedPackages,
      checkedEvents: index.events.length,
      headSequence: index.sequence,
      headHash: index.headHash
    };
  }

  function tenantStatus(tenantId) {
    const tenant = identifier(tenantId, 'tenantId');
    try {
      const index = loadSafe(tenant);
      const counts = { pending: 0, packaged: 0, rejected: 0, revoked: 0, expired: 0 };
      for (const record of index.requests) counts[effectiveState(record, now())] += 1;
      return {
        status: 'ready', enabled: true, minimumApprovers: approvalQuorum,
        total: index.requests.length, ...counts,
        headSequence: index.sequence, headHash: index.headHash
      };
    } catch (error) {
      return { status: 'unavailable', enabled: true, error: error?.code ?? 'evidence_disclosure_store_unavailable' };
    }
  }

  function health() {
    try {
      mkdirSync(root, { recursive: true, mode: 0o700 });
      const tenantDirectoryCount = readdirSync(root, { withFileTypes: true })
        .filter((entry) => entry.isDirectory() && entry.name !== '.locks').length;
      return {
        status: 'ready', enabled: true, mode: 'shared-file-governed-disclosure',
        encryptedRecords: true, recipientSealedPackages: true,
        requesterApprovalSeparation: true, minimumApprovers: approvalQuorum,
        maximumEvidenceItems: itemLimit, maximumPackageBytes: byteLimit,
        maximumTtlHours: ttlLimitHours, tenantDirectoryCount,
        mutex: lock.health()
      };
    } catch (error) {
      return { status: 'unavailable', enabled: true, mode: 'shared-file-governed-disclosure', error: error?.code ?? 'evidence_disclosure_store_unavailable' };
    }
  }

  function packageRecord(record) {
    const packageId = `DSP-${sha256(`${record.requestId}|${record.recipientKeyFingerprint}`).slice(0, 32)}`;
    const path = packagePath(record.tenantId, packageId);
    let envelope;
    if (existsSync(path)) {
      envelope = readPackage(record.tenantId, packageId);
      if (envelope.requestId !== record.requestId || envelope.recipientKeyFingerprint !== record.recipientKeyFingerprint) {
        throw new EvidenceDisclosureIntegrityError('A conflicting recipient-sealed disclosure package already exists.', {
          requestId: record.requestId,
          packageId
        });
      }
    } else {
      const resolved = record.evidence.map((selection) => normaliseResolved(
        resolveEvidence(record.tenantId, selection),
        selection
      ));
      const totalBytes = resolved.reduce((sum, entry) => sum + entry.sizeBytes, 0);
      if (totalBytes > byteLimit) {
        throw new EvidenceValidationError('The evidence disclosure exceeds the configured package byte limit.', {
          field: 'evidence', totalBytes, maximumPackageBytes: byteLimit
        });
      }
      const manifest = {
        format: 'basitclaw-evidence-disclosure-manifest',
        version: 1,
        packageId,
        requestId: record.requestId,
        tenantId: record.tenantId,
        recipientId: record.recipientId,
        recipientKeyId: record.recipientKeyId,
        recipientKeyFingerprint: record.recipientKeyFingerprint,
        caseReference: record.caseReference,
        purpose: record.purpose,
        requestedBy: record.requestedBy,
        requestedAt: record.requestedAt,
        approvedBy: record.approvals.map((entry) => ({ actor: entry.actor, approvedAt: entry.approvedAt })),
        expiresAt: record.expiresAt,
        evidence: resolved.map((entry) => ({
          ...publicSelection(entry),
          filename: entry.filename,
          mediaType: entry.mediaType,
          contentBase64: entry.content.toString('base64')
        }))
      };
      const plaintext = Buffer.from(stableStringify(manifest));
      const contentKey = randomBytes(32);
      const iv = randomBytes(12);
      const { createCipheriv } = awaitCrypto();
      const cipher = createCipheriv('aes-256-gcm', contentKey, iv);
      const aad = Buffer.from(`basitclaw:evidence-disclosure:${packageId}:${record.requestId}`);
      cipher.setAAD(aad);
      const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      const authTag = cipher.getAuthTag();
      const recipientKey = createPublicKey(record.recipientPublicKeyPem);
      const wrappedKey = publicEncrypt({
        key: recipientKey,
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      }, contentKey);
      envelope = {
        format: PACKAGE_FORMAT,
        version: 1,
        packageId,
        requestId: record.requestId,
        algorithm: PACKAGE_ALGORITHM,
        recipientKeyId: record.recipientKeyId,
        recipientKeyFingerprint: record.recipientKeyFingerprint,
        aad: aad.toString('base64'),
        wrappedKey: wrappedKey.toString('base64'),
        iv: iv.toString('base64'),
        authTag: authTag.toString('base64'),
        ciphertext: ciphertext.toString('base64'),
        plaintextSha256: sha256(plaintext),
        evidenceCount: resolved.length,
        sealedAt: now().toISOString(),
        expiresAt: record.expiresAt
      };
      writeJsonExclusive(path, envelope, packageId);
    }
    record.state = 'packaged';
    record.packageId = packageId;
    record.packageEnvelopeSha256 = sha256(Buffer.from(stableStringify(envelope)));
    record.packagedAt = envelope.sealedAt;
  }

  function loadIndex(tenant) {
    const path = indexPath(tenant);
    if (!existsSync(path)) return emptyIndex(tenant, now());
    let envelope;
    try { envelope = readEvidenceJson(path); }
    catch (error) { throw new EvidenceDisclosureStoreError('The evidence disclosure index is unreadable.', {}, error); }
    const index = decryptEvidenceJson(envelope, encryption, indexAad(tenant), EvidenceDisclosureIntegrityError);
    if (!index || index.format !== INDEX_FORMAT || index.version !== 1 || index.tenantId !== tenant
        || !Array.isArray(index.requests) || !Array.isArray(index.events)) {
      throw new EvidenceDisclosureIntegrityError('The evidence disclosure index identity is invalid.');
    }
    verifyEventChain(index);
    return index;
  }

  function loadSafe(tenant) {
    try { return loadIndex(tenant); }
    catch (error) {
      if (error instanceof EvidenceDisclosureStoreError || error instanceof EvidenceDisclosureIntegrityError) throw error;
      throw new EvidenceDisclosureStoreError('The evidence disclosure index could not be loaded.', {}, error);
    }
  }

  function saveIndex(tenant, index) {
    index.updatedAt = now().toISOString();
    atomicWriteEvidenceJson(indexPath(tenant), encryptEvidenceJson(index, encryption, indexAad(tenant)));
  }

  function indexPath(tenant) {
    return resolve(tenantEvidenceDirectory(root, tenant), 'disclosures.evidence');
  }

  function packagePath(tenant, packageId) {
    const directory = resolve(tenantEvidenceDirectory(root, tenant), 'packages');
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    return resolve(directory, `${packageId}.sealed`);
  }

  function readPackage(tenant, packageId) {
    const id = packageIdentifier(packageId);
    let envelope;
    try { envelope = JSON.parse(readFileSync(packagePath(tenant, id), 'utf8')); }
    catch (error) { throw new EvidenceDisclosureStoreError('The recipient-sealed disclosure package is unreadable.', { packageId: id }, error); }
    if (!envelope || envelope.format !== PACKAGE_FORMAT || envelope.version !== 1 || envelope.packageId !== id
        || !REQUEST_ID.test(envelope.requestId) || envelope.algorithm !== PACKAGE_ALGORITHM) {
      throw new EvidenceDisclosureIntegrityError('The recipient-sealed disclosure package identity is invalid.', { packageId: id });
    }
    return envelope;
  }

  return Object.freeze({
    mode: selectedMode,
    enabled: true,
    minimumApprovers: approvalQuorum,
    directory: root,
    createRequest,
    approve,
    reject,
    revoke,
    list,
    get,
    sealedPackage,
    events,
    verifyTenant,
    tenantStatus,
    health
  });
}

export function createEvidenceDisclosureStoreFromEnvironment({ env = process.env, resolveEvidence } = {}) {
  try {
    const mode = environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_MODE) ?? 'disabled';
    if (mode === 'disabled') return createEvidenceDisclosureStore({ mode });
    const rawKeys = environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_KEYS);
    const primaryKeyId = environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_PRIMARY_KEY_ID);
    if (!rawKeys || !primaryKeyId) {
      throw new EvidenceDisclosureStoreError('Dedicated evidence disclosure keys and primary key ID are required.', {
        reason: 'missing_disclosure_keys'
      });
    }
    return createEvidenceDisclosureStore({
      mode,
      directory: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_DIR)
        ?? '.runtime-data/workforce-audit-evidence-disclosures',
      encryptionKeys: JSON.parse(rawKeys),
      encryptionPrimaryKeyId: primaryKeyId,
      minimumApprovers: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_MINIMUM_APPROVERS) ?? 2,
      maximumEvidenceItems: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_MAX_ITEMS) ?? 100,
      maximumPackageBytes: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_MAX_BYTES) ?? 25_000_000,
      maximumTtlHours: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_MAX_TTL_HOURS) ?? 168,
      resolveEvidence
    });
  } catch (error) {
    if (error instanceof EvidenceDisclosureStoreError) throw error;
    throw new EvidenceDisclosureStoreError('Evidence disclosure configuration is invalid.', {
      reason: error?.code ?? 'invalid_configuration'
    }, error);
  }
}

function normaliseCreate(input, context, { itemLimit, ttlLimitHours, now }) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new EvidenceValidationError('A valid evidence disclosure request is required.');
  }
  const tenantId = identifier(context.tenantId, 'tenantId');
  const requestedBy = identifier(context.actor, 'actor');
  const recipientId = identifier(input.recipientId, 'recipientId');
  const recipientKeyId = identifier(input.recipientKeyId, 'recipientKeyId');
  const caseReference = cleanText(input.caseReference, 'caseReference', 3, 191);
  const purpose = cleanText(input.purpose, 'purpose', 10, 500);
  const requestedAt = now().toISOString();
  const expiresAt = isoDate(input.expiresAt, 'expiresAt');
  const ttl = new Date(expiresAt).getTime() - new Date(requestedAt).getTime();
  if (ttl <= 0 || ttl > ttlLimitHours * 3_600_000) {
    throw new EvidenceValidationError(`expiresAt must be within ${ttlLimitHours} hours.`, { field: 'expiresAt' });
  }
  if (!Array.isArray(input.evidence) || input.evidence.length < 1 || input.evidence.length > itemLimit) {
    throw new EvidenceValidationError(`evidence must contain 1 to ${itemLimit} selections.`, { field: 'evidence' });
  }
  const seen = new Set();
  const evidence = input.evidence.map((entry, index) => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      throw new EvidenceValidationError(`evidence[${index}] must be an object.`, { field: `evidence[${index}]` });
    }
    const evidenceId = evidenceIdentifier(entry.evidenceId);
    const version = integer(entry.version, `evidence[${index}].version`, 1, 1_000_000);
    const key = `${evidenceId}:${version}`;
    if (seen.has(key)) throw new EvidenceValidationError('Duplicate evidence selections are not allowed.', { field: 'evidence' });
    seen.add(key);
    return { evidenceId, version };
  });
  return {
    tenantId, requestedBy, requestedAt, expiresAt,
    recipientId, recipientKeyId,
    recipientPublicKeyPem: String(input.recipientPublicKeyPem ?? ''),
    caseReference, purpose, evidence
  };
}

function normaliseResolved(input, selection) {
  if (!input || typeof input !== 'object' || !Buffer.isBuffer(input.content)) {
    throw new EvidenceDisclosureStoreError('The selected evidence could not be resolved.', { selection });
  }
  const evidenceId = evidenceIdentifier(input.evidenceId);
  const version = integer(input.version, 'version', 1, 1_000_000);
  const contentSha256 = hashValue(input.contentSha256, 'contentSha256');
  const sizeBytes = integer(input.sizeBytes, 'sizeBytes', 0, 500_000_000);
  if (evidenceId !== selection.evidenceId || version !== selection.version
      || input.content.length !== sizeBytes || sha256(input.content) !== contentSha256) {
    throw new EvidenceDisclosureIntegrityError('Resolved evidence does not match the immutable selection.', { selection });
  }
  return {
    evidenceId, version, contentSha256, sizeBytes,
    filename: cleanText(input.filename, 'filename', 1, 255),
    mediaType: cleanText(input.mediaType, 'mediaType', 1, 255),
    preservationArchiveId: input.preservationArchiveId ? String(input.preservationArchiveId) : null,
    preservationReceiptSha256: input.preservationReceiptSha256 ? hashValue(input.preservationReceiptSha256, 'preservationReceiptSha256') : null,
    timeAttestationProviders: Array.isArray(input.timeAttestationProviders)
      ? [...new Set(input.timeAttestationProviders.map((value) => identifier(value, 'timeAttestationProvider')))].sort()
      : [],
    content: Buffer.from(input.content)
  };
}

function publicSelection(entry) {
  return {
    evidenceId: entry.evidenceId,
    version: entry.version,
    contentSha256: entry.contentSha256,
    sizeBytes: entry.sizeBytes,
    preservationArchiveId: entry.preservationArchiveId,
    preservationReceiptSha256: entry.preservationReceiptSha256,
    timeAttestationProviders: entry.timeAttestationProviders
  };
}

function parseRecipientKey(value) {
  let publicKey;
  try { publicKey = createPublicKey(String(value ?? '')); }
  catch (error) { throw new EvidenceValidationError('recipientPublicKeyPem must contain a valid public key.', { field: 'recipientPublicKeyPem' }, error); }
  if (!['rsa', 'rsa-pss'].includes(publicKey.asymmetricKeyType)) {
    throw new EvidenceValidationError('recipientPublicKeyPem must be an RSA public key.', { field: 'recipientPublicKeyPem' });
  }
  if ((publicKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) {
    throw new EvidenceValidationError('recipientPublicKeyPem must be at least 2048 bits.', { field: 'recipientPublicKeyPem' });
  }
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const fingerprint = sha256(publicKey.export({ type: 'spki', format: 'der' }));
  return { publicKeyPem, fingerprint };
}

function emptyIndex(tenantId, date) {
  const time = date.toISOString();
  return { format: INDEX_FORMAT, version: 1, tenantId, createdAt: time, updatedAt: time, sequence: 0, headHash: null, requests: [], events: [] };
}

function appendEvent(index, input) {
  const event = {
    eventId: `DSE-${sha256(`${input.requestId}|${input.type}|${index.sequence + 1}|${input.occurredAt}`).slice(0, 32)}`,
    sequence: index.sequence + 1,
    previousHash: index.headHash,
    ...input
  };
  event.hash = eventHash(event);
  index.events.push(event);
  index.sequence = event.sequence;
  index.headHash = event.hash;
}

function verifyEventChain(index) {
  let sequence = 1;
  let previousHash = null;
  for (const event of index.events) {
    if (event.sequence !== sequence || event.previousHash !== previousHash || event.hash !== eventHash(event)) {
      throw new EvidenceDisclosureIntegrityError('The evidence disclosure event chain is invalid.', {
        eventId: event.eventId,
        expectedSequence: sequence
      });
    }
    sequence += 1;
    previousHash = event.hash;
  }
  if (index.sequence !== sequence - 1 || index.headHash !== previousHash) {
    throw new EvidenceDisclosureIntegrityError('The evidence disclosure chain head is inconsistent.');
  }
}

function eventHash(event) { const { hash, ...body } = event; return sha256(stableStringify(body)); }
function findRequest(index, requestId) { const record = index.requests.find((entry) => entry.requestId === requestId); if (!record) throw new EvidenceValidationError('The evidence disclosure request was not found.', { requestId }); return record; }
function assertPending(record, date) { const state = effectiveState(record, date); if (state !== 'pending') throw new EvidenceConflictError('The evidence disclosure request is not pending.', { requestId: record.requestId, state }); }
function effectiveState(record, date) { if (['rejected', 'revoked'].includes(record.state)) return record.state; if (new Date(record.expiresAt) <= date) return 'expired'; return record.state; }
function publicRequest(record, date) { return { requestId: record.requestId, state: effectiveState(record, date), requestedBy: record.requestedBy, requestedAt: record.requestedAt, expiresAt: record.expiresAt, recipientId: record.recipientId, recipientKeyId: record.recipientKeyId, recipientKeyFingerprint: record.recipientKeyFingerprint, caseReference: record.caseReference, purpose: record.purpose, evidence: record.evidence.map((entry) => ({ ...entry })), approvals: record.approvals.map((entry) => ({ ...entry })), minimumApprovers: null, packageId: record.packageId, packagedAt: record.packagedAt, rejectedAt: record.rejectedAt, rejectedBy: record.rejectedBy, rejectionReason: record.rejectionReason, revokedAt: record.revokedAt, revokedBy: record.revokedBy, revocationReason: record.revocationReason }; }
function writeJsonExclusive(path, value, packageId) { mkdirSync(dirname(path), { recursive: true, mode: 0o700 }); let descriptor = null; let created = false; let committed = false; try { descriptor = openSync(path, 'wx', 0o600); created = true; writeFileSync(descriptor, `${JSON.stringify(value)}\n`, 'utf8'); fsyncSync(descriptor); closeSync(descriptor); descriptor = null; committed = true; const directory = openSync(dirname(path), 'r'); try { fsyncSync(directory); } finally { closeSync(directory); } } catch (error) { if (descriptor !== null) try { closeSync(descriptor); } catch {} if (created && !committed) try { rmSync(path, { force: true }); } catch {} if (error?.code === 'EEXIST') throw new EvidenceDisclosureIntegrityError('A conflicting recipient-sealed disclosure package already exists.', { packageId }); throw new EvidenceDisclosureStoreError('The recipient-sealed disclosure package could not be committed.', { packageId }, error); } }
function indexAad(tenantId) { return `basitclaw:evidence-disclosures:${tenantId}`; }
function requestIdentifier(value) { const id = String(value ?? ''); if (!REQUEST_ID.test(id)) throw new EvidenceValidationError('requestId is invalid.', { field: 'requestId' }); return id; }
function packageIdentifier(value) { const id = String(value ?? ''); if (!PACKAGE_ID.test(id)) throw new EvidenceValidationError('packageId is invalid.', { field: 'packageId' }); return id; }
function evidenceIdentifier(value) { const id = String(value ?? ''); if (!EVIDENCE_ID.test(id)) throw new EvidenceValidationError('evidenceId is invalid.', { field: 'evidenceId' }); return id; }
function hashValue(value, field) { const text = String(value ?? '').toLowerCase(); if (!HASH.test(text)) throw new EvidenceValidationError(`${field} must be a SHA-256 digest.`, { field }); return text; }
function identifier(value, field) { const text = String(value ?? '').trim(); if (!/^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{1,191}$/.test(text)) throw new EvidenceValidationError(`${field} is invalid.`, { field }); return text; }
function cleanText(value, field, minimum, maximum) { const text = String(value ?? '').trim(); if (text.length < minimum || text.length > maximum) throw new EvidenceValidationError(`${field} must contain ${minimum} to ${maximum} characters.`, { field }); return text; }
function isoDate(value, field) { const date = new Date(String(value ?? '')); if (Number.isNaN(date.getTime())) throw new EvidenceValidationError(`${field} must be a valid ISO date.`, { field }); return date.toISOString(); }
function integer(value, field, minimum, maximum) { const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) throw new EvidenceValidationError(`${field} must be an integer from ${minimum} to ${maximum}.`, { field }); return parsed; }
function enumValue(value, allowed, field) { const text = String(value ?? ''); if (!allowed.has(text)) throw new EvidenceValidationError(`${field} must be one of ${[...allowed].join(', ')}.`, { field }); return text; }
function environmentValue(value) { const clean = typeof value === 'string' ? value.trim() : value; return clean === '' || clean === undefined || clean === null ? undefined : clean; }
function stableStringify(value) { if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`; if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`; return JSON.stringify(value); }
function awaitCrypto() { return requireCrypto(); }
function requireCrypto() { return { createCipheriv: (algorithm, key, iv) => globalThis.__basitclawCreateCipheriv?.(algorithm, key, iv) }; }

function disabledStore() {
  const status = Object.freeze({ status: 'disabled', enabled: false, mode: 'disabled' });
  return Object.freeze({
    mode: 'disabled', enabled: false, minimumApprovers: 0,
    createRequest() { throw new EvidenceConflictError('Evidence disclosure is disabled.'); },
    approve() { throw new EvidenceConflictError('Evidence disclosure is disabled.'); },
    reject() { throw new EvidenceConflictError('Evidence disclosure is disabled.'); },
    revoke() { throw new EvidenceConflictError('Evidence disclosure is disabled.'); },
    list() { return []; },
    get() { throw new EvidenceConflictError('Evidence disclosure is disabled.'); },
    sealedPackage() { throw new EvidenceConflictError('Evidence disclosure is disabled.'); },
    events() { return []; },
    verifyTenant(tenantId) { return { valid: true, tenantId, checkedRequests: 0, checkedPackages: 0, checkedEvents: 0, headSequence: 0, headHash: null }; },
    tenantStatus() { return status; },
    health() { return status; }
  });
}
