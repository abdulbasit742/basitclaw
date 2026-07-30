import {
  constants,
  createCipheriv,
  createHmac,
  createPublicKey,
  randomBytes,
  randomUUID,
  timingSafeEqual,
  publicEncrypt
} from 'node:crypto';
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
  sha256,
  strictBase64
} from './evidenceCrypto.js';
import {
  EvidenceConflictError,
  EvidenceIntegrityError,
  EvidenceStoreError,
  EvidenceValidationError
} from './evidenceRegistry.js';

const MODES = new Set(['disabled', 'shared-file']);
const STATES = new Set(['requested', 'approved', 'sealed', 'claimed', 'acknowledged', 'revoked', 'expired', 'dead_letter']);
const DISCLOSURE_ID = /^DSC-[a-f0-9]{32}$/;
const EVIDENCE_ID = /^EVD-[a-f0-9]{32}$/;
const HASH = /^[a-f0-9]{64}$/;
const SAFE_ID = /^[a-zA-Z0-9][a-zA-Z0-9._:-]{1,191}$/;
const DAY_MS = 86_400_000;

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

export class EvidenceDisclosureAuthenticationError extends Error {
  constructor(message = 'The disclosure recipient signature is invalid.', details = {}) {
    super(message);
    this.name = 'EvidenceDisclosureAuthenticationError';
    this.code = 'EVIDENCE_DISCLOSURE_AUTHENTICATION_FAILED';
    this.statusCode = 401;
    this.details = details;
  }
}

export function createEvidenceDisclosureStore({
  mode = 'disabled',
  directory,
  encryptionKeys,
  encryptionPrimaryKeyId,
  recipients = {},
  tenantResidencyZones = {},
  approvalQuorum = 2,
  defaultTtlMinutes = 1440,
  claimLeaseMs = 300_000,
  maximumPackageBytes = 25_000_000,
  maximumRecords = 100_000,
  now = () => new Date(),
  mutex = null
} = {}) {
  const selectedMode = enumValue(mode, MODES, 'mode');
  if (selectedMode === 'disabled') return disabledStore();
  if (!String(directory ?? '').trim()) throw new TypeError('An evidence disclosure directory is required.');
  const root = resolve(String(directory));
  const encryption = parseEvidenceKeyring(encryptionKeys, encryptionPrimaryKeyId);
  const recipientMap = parseRecipients(recipients);
  const zonesByTenant = parseTenantZones(tenantResidencyZones);
  const quorum = integer(approvalQuorum, 'approvalQuorum', 2, 10);
  const ttlMinutes = integer(defaultTtlMinutes, 'defaultTtlMinutes', 5, 43_200);
  const leaseMs = integer(claimLeaseMs, 'claimLeaseMs', 10_000, 86_400_000);
  const maxBytes = integer(maximumPackageBytes, 'maximumPackageBytes', 1_024, 100_000_000);
  const maxRecords = integer(maximumRecords, 'maximumRecords', 1, 1_000_000);
  const lock = mutex ?? createFileMutex({ directory: resolve(root, '.locks'), now });
  mkdirSync(root, { recursive: true, mode: 0o700 });
  mkdirSync(resolve(root, '.replay'), { recursive: true, mode: 0o700 });

  function request(input, { actor, role } = {}) {
    const source = validateRequest(input, recipientMap, zonesByTenant, ttlMinutes, now);
    const requester = identifier(actor, 'actor');
    const requesterRole = identifier(role, 'role');
    return lock.withLock(`evidence-disclosure:${source.tenantId}`, () => {
      const currentCount = recordNames(source.tenantId).length;
      if (currentCount >= maxRecords) throw new EvidenceDisclosureStoreError('The disclosure record limit has been reached.', { maximumRecords: maxRecords });
      const disclosureId = `DSC-${randomUUID().replaceAll('-', '')}`;
      const createdAt = now().toISOString();
      const record = {
        format: 'basitclaw-evidence-disclosure-v1', version: 1, disclosureId,
        tenantId: source.tenantId, evidenceId: source.evidenceId, evidenceVersion: source.evidenceVersion,
        contentSha256: source.contentSha256, sizeBytes: source.sizeBytes,
        recipientId: source.recipientId, residencyZone: source.residencyZone,
        purpose: source.purpose, requestedBy: requester, requestedByRole: requesterRole,
        requestedAt: createdAt, expiresAt: source.expiresAt, state: 'requested',
        approvals: [], package: null, claim: null, acknowledgedAt: null, revokedAt: null,
        events: []
      };
      appendEvent(record, 'disclosure.requested', requester, { recipientId: source.recipientId, residencyZone: source.residencyZone }, createdAt);
      writeRecord(record);
      return publicRecord(record);
    });
  }

  function approve(tenantId, disclosureId, { actor, role, contentProvider } = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = disclosureIdentifier(disclosureId);
    const approver = identifier(actor, 'actor');
    const approverRole = identifier(role, 'role');
    if (typeof contentProvider !== 'function') throw new TypeError('A disclosure content provider is required.');
    return lock.withLock(`evidence-disclosure:${tenant}`, () => {
      const record = readRecord(tenant, id);
      expireRecord(record, now);
      if (!['requested', 'approved'].includes(record.state)) throw new EvidenceConflictError('Only pending disclosure requests can be approved.', { disclosureId: id, state: record.state });
      if (record.requestedBy === approver) throw new EvidenceConflictError('The disclosure requester cannot approve their own request.', { disclosureId: id });
      if (record.approvals.some((entry) => entry.actor === approver)) throw new EvidenceConflictError('The principal has already approved this disclosure.', { disclosureId: id });
      const approvedAt = now().toISOString();
      record.approvals.push({ actor: approver, role: approverRole, approvedAt });
      record.state = record.approvals.length >= quorum ? 'approved' : 'requested';
      appendEvent(record, 'disclosure.approved', approver, { approvals: record.approvals.length, quorum }, approvedAt);
      if (record.approvals.length >= quorum) {
        const content = contentProvider(Object.freeze({ ...publicRecord(record) }));
        sealRecord(record, content, recipientMap.get(record.recipientId), maxBytes, now);
      }
      writeRecord(record);
      return publicRecord(record);
    });
  }

  function revoke(tenantId, disclosureId, { actor, reason } = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = disclosureIdentifier(disclosureId);
    const principal = identifier(actor, 'actor');
    const cleanReason = cleanText(reason, 'reason', 10, 500);
    return lock.withLock(`evidence-disclosure:${tenant}`, () => {
      const record = readRecord(tenant, id);
      if (['acknowledged', 'expired', 'revoked'].includes(record.state)) throw new EvidenceConflictError('The disclosure can no longer be revoked.', { disclosureId: id, state: record.state });
      record.state = 'revoked';
      record.revokedAt = now().toISOString();
      record.package = null;
      record.claim = null;
      appendEvent(record, 'disclosure.revoked', principal, { reason: cleanReason }, record.revokedAt);
      writeRecord(record);
      return publicRecord(record);
    });
  }

  function claimSigned(bodyBytes, headers) {
    const authentication = authenticateRecipient(bodyBytes, headers, recipientMap, now, root);
    let body;
    try { body = JSON.parse(bodyBytes.toString('utf8') || '{}'); }
    catch { throw new EvidenceValidationError('Disclosure claim body must be valid JSON.', { field: 'body' }); }
    const tenant = identifier(body.tenantId, 'tenantId');
    const limit = integer(body.limit ?? 10, 'limit', 1, 100);
    return lock.withLock(`evidence-disclosure:${tenant}`, () => {
      const claimed = [];
      for (const name of recordNames(tenant)) {
        if (claimed.length >= limit) break;
        const record = readRecord(tenant, name.slice(0, -5));
        const changed = expireRecord(record, now);
        if (changed) writeRecord(record);
        if (record.recipientId !== authentication.recipientId) continue;
        if (record.state === 'claimed' && new Date(record.claim.expiresAt) <= now()) {
          record.state = 'sealed';
          record.claim = null;
          appendEvent(record, 'disclosure.claim_expired', 'system', {}, now().toISOString());
        }
        if (record.state !== 'sealed') continue;
        const claimToken = randomBytes(32).toString('base64url');
        const claimedAt = now().toISOString();
        record.state = 'claimed';
        record.claim = { tokenHash: sha256(claimToken), claimedAt, expiresAt: new Date(now().getTime() + leaseMs).toISOString() };
        appendEvent(record, 'disclosure.claimed', authentication.recipientId, {}, claimedAt);
        writeRecord(record);
        claimed.push({ ...publicRecord(record), claimToken, package: record.package });
      }
      return { recipientId: authentication.recipientId, tenantId: tenant, jobs: claimed };
    });
  }

  function acknowledgeSigned(disclosureId, bodyBytes, headers) {
    const authentication = authenticateRecipient(bodyBytes, headers, recipientMap, now, root);
    let body;
    try { body = JSON.parse(bodyBytes.toString('utf8') || '{}'); }
    catch { throw new EvidenceValidationError('Disclosure acknowledgement body must be valid JSON.', { field: 'body' }); }
    const tenant = identifier(body.tenantId, 'tenantId');
    const token = String(body.claimToken ?? '');
    if (token.length < 20 || token.length > 512) throw new EvidenceValidationError('claimToken is invalid.', { field: 'claimToken' });
    const id = disclosureIdentifier(disclosureId);
    return lock.withLock(`evidence-disclosure:${tenant}`, () => {
      const record = readRecord(tenant, id);
      expireRecord(record, now);
      if (record.recipientId !== authentication.recipientId) throw new EvidenceDisclosureAuthenticationError(undefined, { reason: 'recipient_mismatch' });
      if (record.state !== 'claimed' || !record.claim) throw new EvidenceConflictError('The disclosure is not currently claimed.', { disclosureId: id, state: record.state });
      if (new Date(record.claim.expiresAt) <= now()) throw new EvidenceConflictError('The disclosure claim has expired.', { disclosureId: id });
      if (!safeEqualHex(record.claim.tokenHash, sha256(token))) throw new EvidenceDisclosureAuthenticationError(undefined, { reason: 'claim_token' });
      record.state = 'acknowledged';
      record.acknowledgedAt = now().toISOString();
      record.package = null;
      record.claim = null;
      appendEvent(record, 'disclosure.acknowledged', authentication.recipientId, {}, record.acknowledgedAt);
      writeRecord(record);
      return publicRecord(record);
    });
  }

  function get(tenantId, disclosureId) {
    const tenant = identifier(tenantId, 'tenantId');
    return lock.withLock(`evidence-disclosure:${tenant}`, () => publicRecord(readRecord(tenant, disclosureIdentifier(disclosureId))));
  }

  function list(tenantId, { evidenceId = null, state = null, limit = 500 } = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const evidence = evidenceId === null ? null : evidenceIdentifier(evidenceId);
    const selectedState = state === null ? null : enumValue(state, STATES, 'state');
    const maximum = integer(limit, 'limit', 1, 5000);
    return lock.withLock(`evidence-disclosure:${tenant}`, () => recordNames(tenant)
      .map((name) => readRecord(tenant, name.slice(0, -5)))
      .filter((record) => !evidence || record.evidenceId === evidence)
      .filter((record) => !selectedState || record.state === selectedState)
      .sort((left, right) => right.requestedAt.localeCompare(left.requestedAt))
      .slice(0, maximum)
      .map(publicRecord));
  }

  function report(tenantId) {
    const rows = list(tenantId, { limit: 5000 });
    const byState = Object.fromEntries([...STATES].map((state) => [state, 0]));
    const byRecipient = {};
    const byResidencyZone = {};
    for (const row of rows) {
      byState[row.state] += 1;
      byRecipient[row.recipientId] = (byRecipient[row.recipientId] ?? 0) + 1;
      byResidencyZone[row.residencyZone] = (byResidencyZone[row.residencyZone] ?? 0) + 1;
    }
    return { total: rows.length, byState, byRecipient, byResidencyZone, approvalQuorum: quorum };
  }

  function verifyTenant(tenantId) {
    const tenant = identifier(tenantId, 'tenantId');
    return lock.withLock(`evidence-disclosure:${tenant}`, () => {
      let checkedRecords = 0;
      let checkedEvents = 0;
      for (const name of recordNames(tenant)) {
        const record = readRecord(tenant, name.slice(0, -5));
        verifyRecord(record);
        checkedRecords += 1;
        checkedEvents += record.events.length;
      }
      return { valid: true, tenantId: tenant, checkedRecords, checkedEvents };
    });
  }

  function health() {
    try {
      mkdirSync(root, { recursive: true, mode: 0o700 });
      return {
        status: recipientMap.size ? 'ready' : 'attention', enabled: true,
        mode: 'shared-file-governed-disclosure', encryptedRecords: true,
        recipientSealedPackages: true, dualApproval: quorum >= 2,
        approvalQuorum: quorum, recipients: recipientMap.size,
        maximumPackageBytes: maxBytes, mutex: lock.health()
      };
    } catch (error) {
      return { status: 'unavailable', enabled: true, mode: 'shared-file-governed-disclosure', error: error?.code ?? 'evidence_disclosure_store_unavailable' };
    }
  }

  function recordNames(tenantId) {
    const directory = tenantDirectory(root, tenantId);
    return readdirSync(directory).filter((name) => /^DSC-[a-f0-9]{32}\.json$/.test(name)).sort();
  }

  function writeRecord(record) {
    verifyRecord(record);
    const path = recordPath(root, record.tenantId, record.disclosureId);
    const envelope = encryptEvidenceJson(record, encryption, recordAad(record.tenantId, record.disclosureId));
    atomicWrite(path, envelope);
  }

  function readRecord(tenantId, disclosureId) {
    const path = recordPath(root, tenantId, disclosureId);
    if (!existsSync(path)) throw new EvidenceConflictError('The evidence disclosure does not exist.', { disclosureId });
    let envelope;
    try { envelope = readEvidenceJson(path); }
    catch (error) { throw new EvidenceDisclosureStoreError('An evidence disclosure record is unreadable.', { disclosureId }, error); }
    const record = decryptEvidenceJson(envelope, encryption, recordAad(tenantId, disclosureId), EvidenceDisclosureIntegrityError);
    verifyRecord(record);
    return record;
  }

  return Object.freeze({
    enabled: true, mode: selectedMode, approvalQuorum: quorum,
    request, approve, revoke, claimSigned, acknowledgeSigned,
    get, list, report, verifyTenant, health
  });
}

export function createEvidenceDisclosureStoreFromEnvironment({ env = process.env } = {}) {
  const mode = environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_MODE) ?? 'disabled';
  if (mode === 'disabled') return createEvidenceDisclosureStore({ mode });
  try {
    const keysText = requiredEnvironment(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_KEYS, 'WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_KEYS');
    const recipientsText = requiredEnvironment(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_RECIPIENTS, 'WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_RECIPIENTS');
    return createEvidenceDisclosureStore({
      mode,
      directory: requiredEnvironment(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_DIR, 'WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_DIR'),
      encryptionKeys: JSON.parse(keysText),
      encryptionPrimaryKeyId: requiredEnvironment(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_PRIMARY_KEY_ID, 'WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_PRIMARY_KEY_ID'),
      recipients: JSON.parse(recipientsText),
      tenantResidencyZones: JSON.parse(environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_TENANT_ZONES) ?? '{}'),
      approvalQuorum: Number(environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_APPROVAL_QUORUM) ?? 2),
      defaultTtlMinutes: Number(environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_TTL_MINUTES) ?? 1440),
      claimLeaseMs: Number(environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_CLAIM_LEASE_MS) ?? 300000),
      maximumPackageBytes: Number(environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_MAX_PACKAGE_BYTES) ?? 25000000),
      maximumRecords: Number(environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_MAX_RECORDS) ?? 100000)
    });
  } catch (error) {
    if (error instanceof EvidenceDisclosureStoreError) throw error;
    throw new EvidenceDisclosureStoreError('Evidence disclosure configuration is invalid.', { reason: error?.message ?? 'invalid_configuration' }, error);
  }
}

function validateRequest(input, recipients, zonesByTenant, ttlMinutes, now) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new EvidenceValidationError('A disclosure request object is required.');
  const tenantId = identifier(input.tenantId, 'tenantId');
  const evidenceId = evidenceIdentifier(input.evidenceId);
  const evidenceVersion = integer(input.evidenceVersion, 'evidenceVersion', 1, 1_000_000);
  const contentSha256 = hashValue(input.contentSha256, 'contentSha256');
  const sizeBytes = integer(input.sizeBytes, 'sizeBytes', 0, 100_000_000);
  const recipientId = identifier(input.recipientId, 'recipientId');
  const recipient = recipients.get(recipientId);
  if (!recipient) throw new EvidenceValidationError('recipientId is not approved.', { field: 'recipientId' });
  const residencyZone = identifier(input.residencyZone, 'residencyZone');
  const tenantZones = zonesByTenant.get(tenantId) ?? new Set();
  if (tenantZones.size && !tenantZones.has(residencyZone)) throw new EvidenceConflictError('The requested residency zone is not permitted for this tenant.', { residencyZone });
  if (!recipient.allowedZones.has(residencyZone)) throw new EvidenceConflictError('The recipient is not approved for the requested residency zone.', { recipientId, residencyZone });
  const requestedExpiry = input.expiresAt ? new Date(input.expiresAt) : new Date(now().getTime() + ttlMinutes * 60_000);
  if (Number.isNaN(requestedExpiry.getTime()) || requestedExpiry <= now() || requestedExpiry > new Date(now().getTime() + 30 * DAY_MS)) {
    throw new EvidenceValidationError('expiresAt must be in the future and no more than 30 days away.', { field: 'expiresAt' });
  }
  return {
    tenantId, evidenceId, evidenceVersion, contentSha256, sizeBytes, recipientId, residencyZone,
    purpose: cleanText(input.purpose, 'purpose', 10, 500), expiresAt: requestedExpiry.toISOString()
  };
}

function sealRecord(record, contentInput, recipient, maximumPackageBytes, now) {
  if (!contentInput || typeof contentInput !== 'object' || !Buffer.isBuffer(contentInput.content)) throw new EvidenceDisclosureIntegrityError('The disclosure content provider returned invalid content.', { disclosureId: record.disclosureId });
  const content = Buffer.from(contentInput.content);
  if (content.length !== record.sizeBytes || sha256(content) !== record.contentSha256) throw new EvidenceDisclosureIntegrityError('Disclosure content does not match immutable evidence metadata.', { disclosureId: record.disclosureId });
  if (content.length > maximumPackageBytes) throw new EvidenceConflictError('The evidence version exceeds the disclosure package limit.', { maximumPackageBytes });
  const sealedAt = now().toISOString();
  const metadata = {
    format: 'basitclaw-recipient-sealed-evidence-v1', disclosureId: record.disclosureId,
    tenantId: record.tenantId, evidenceId: record.evidenceId, evidenceVersion: record.evidenceVersion,
    contentSha256: record.contentSha256, sizeBytes: record.sizeBytes,
    recipientId: record.recipientId, residencyZone: record.residencyZone,
    purpose: record.purpose, sealedAt, expiresAt: record.expiresAt,
    filename: cleanText(contentInput.filename, 'filename', 1, 255),
    mediaType: cleanText(contentInput.mediaType, 'mediaType', 1, 255)
  };
  const key = randomBytes(32);
  const iv = randomBytes(12);
  const aad = Buffer.from(stableStringify(metadata));
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(content), cipher.final()]);
  const wrappedKey = publicEncrypt({ key: recipient.publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, key);
  record.package = {
    ...metadata, algorithm: 'aes-256-gcm+rsa-oaep-sha256',
    iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64'), wrappedKey: wrappedKey.toString('base64'),
    publicKeyId: recipient.publicKeyId
  };
  record.state = 'sealed';
  appendEvent(record, 'disclosure.sealed', 'system', { recipientId: record.recipientId, publicKeyId: recipient.publicKeyId }, sealedAt);
}

function expireRecord(record, now) {
  const current = now();
  if (!['acknowledged', 'revoked', 'expired'].includes(record.state) && new Date(record.expiresAt) <= current) {
    record.state = 'expired';
    record.package = null;
    record.claim = null;
    appendEvent(record, 'disclosure.expired', 'system', {}, current.toISOString());
    return true;
  }
  return false;
}

function appendEvent(record, type, actor, details, timestamp) {
  const previousHash = record.events.at(-1)?.recordHash ?? '0'.repeat(64);
  const event = { sequence: record.events.length + 1, type, actor, timestamp, details, previousHash };
  event.recordHash = sha256(stableStringify(event));
  record.events.push(event);
}

function verifyRecord(record) {
  if (!record || record.format !== 'basitclaw-evidence-disclosure-v1' || record.version !== 1
      || !DISCLOSURE_ID.test(record.disclosureId) || !EVIDENCE_ID.test(record.evidenceId)
      || !HASH.test(record.contentSha256) || !STATES.has(record.state)) {
    throw new EvidenceDisclosureIntegrityError('An evidence disclosure record has an invalid identity.', { disclosureId: record?.disclosureId ?? null });
  }
  let previousHash = '0'.repeat(64);
  for (let index = 0; index < record.events.length; index += 1) {
    const event = record.events[index];
    const suppliedHash = event.recordHash;
    const { recordHash, ...body } = event;
    if (event.sequence !== index + 1 || event.previousHash !== previousHash || suppliedHash !== sha256(stableStringify(body))) {
      throw new EvidenceDisclosureIntegrityError('The disclosure event chain is invalid.', { disclosureId: record.disclosureId, sequence: index + 1 });
    }
    previousHash = suppliedHash;
  }
  if (record.state === 'sealed' || record.state === 'claimed') {
    if (!record.package || record.package.disclosureId !== record.disclosureId || record.package.contentSha256 !== record.contentSha256) {
      throw new EvidenceDisclosureIntegrityError('The sealed disclosure package is missing or mismatched.', { disclosureId: record.disclosureId });
    }
  }
  return record;
}

function publicRecord(record) {
  return {
    disclosureId: record.disclosureId, evidenceId: record.evidenceId, evidenceVersion: record.evidenceVersion,
    contentSha256: record.contentSha256, sizeBytes: record.sizeBytes,
    recipientId: record.recipientId, residencyZone: record.residencyZone, purpose: record.purpose,
    requestedBy: record.requestedBy, requestedByRole: record.requestedByRole,
    requestedAt: record.requestedAt, expiresAt: record.expiresAt, state: record.state,
    approvals: record.approvals.map((entry) => ({ ...entry })),
    sealedAt: record.package?.sealedAt ?? null, claimedAt: record.claim?.claimedAt ?? null,
    acknowledgedAt: record.acknowledgedAt, revokedAt: record.revokedAt,
    chainHead: record.events.at(-1)?.recordHash ?? null, eventCount: record.events.length
  };
}

function parseRecipients(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new TypeError('Disclosure recipients must be an object.');
  const map = new Map();
  for (const [recipientId, value] of Object.entries(raw)) {
    identifier(recipientId, 'recipientId');
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(`Recipient ${recipientId} must be an object.`);
    const publicKeyId = identifier(value.publicKeyId, 'publicKeyId');
    const publicKey = createPublicKey(value.publicKeyPem);
    if (publicKey.asymmetricKeyType !== 'rsa' || (publicKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) throw new TypeError(`Recipient ${recipientId} requires an RSA public key of at least 2048 bits.`);
    const allowedZones = new Set((value.allowedZones ?? []).map((zone) => identifier(zone, 'allowedZone')));
    if (!allowedZones.size) throw new TypeError(`Recipient ${recipientId} must allow at least one residency zone.`);
    const hmacKeys = parseHmacKeys(value.hmacKeys, recipientId);
    map.set(recipientId, Object.freeze({ recipientId, publicKeyId, publicKey, allowedZones, hmacKeys }));
  }
  if (!map.size || map.size > 1000) throw new TypeError('Disclosure recipients must contain 1 to 1000 entries.');
  return map;
}

function parseHmacKeys(raw, recipientId) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new TypeError(`Recipient ${recipientId} hmacKeys must be an object.`);
  const map = new Map();
  for (const [keyId, encoded] of Object.entries(raw)) {
    identifier(keyId, 'keyId');
    const key = strictBase64(encoded, `recipient ${recipientId} HMAC key ${keyId}`);
    if (key.length < 32 || key.length > 128) throw new TypeError(`Recipient ${recipientId} HMAC key ${keyId} must decode to 32 to 128 bytes.`);
    map.set(keyId, key);
  }
  if (!map.size) throw new TypeError(`Recipient ${recipientId} must have at least one HMAC key.`);
  return map;
}

function parseTenantZones(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new TypeError('Tenant residency zones must be an object.');
  return new Map(Object.entries(raw).map(([tenantId, zones]) => [identifier(tenantId, 'tenantId'), new Set((zones ?? []).map((zone) => identifier(zone, 'residencyZone')))]));
}

function authenticateRecipient(bodyBytes, headers, recipients, now, root) {
  const recipientId = header(headers, 'x-basitclaw-recipient-id');
  const keyId = header(headers, 'x-basitclaw-recipient-key-id');
  const timestamp = header(headers, 'x-basitclaw-recipient-timestamp');
  const nonce = header(headers, 'x-basitclaw-recipient-nonce');
  const signature = header(headers, 'x-basitclaw-recipient-signature');
  const recipient = recipients.get(recipientId);
  const key = recipient?.hmacKeys.get(keyId);
  const date = new Date(timestamp);
  if (!recipient || !key || Number.isNaN(date.getTime()) || Math.abs(now().getTime() - date.getTime()) > 300_000
      || !/^[a-zA-Z0-9._:-]{16,191}$/.test(nonce) || !/^[a-f0-9]{64}$/.test(signature)) {
    throw new EvidenceDisclosureAuthenticationError(undefined, { reason: 'invalid_signature' });
  }
  const canonical = `${recipientId}\n${keyId}\n${timestamp}\n${nonce}\n${sha256(bodyBytes)}`;
  const expected = createHmac('sha256', key).update(canonical).digest();
  const supplied = Buffer.from(signature, 'hex');
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) throw new EvidenceDisclosureAuthenticationError(undefined, { reason: 'invalid_signature' });
  consumeNonce(root, recipientId, nonce, timestamp);
  return { recipientId, keyId };
}

function consumeNonce(root, recipientId, nonce, timestamp) {
  const directory = resolve(root, '.replay', sha256(recipientId));
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const path = resolve(directory, `${sha256(nonce)}.nonce`);
  let descriptor;
  try {
    descriptor = openSync(path, 'wx', 0o600);
    writeFileSync(descriptor, `${timestamp}\n`, 'utf8');
    fsyncSync(descriptor);
  } catch (error) {
    if (error?.code === 'EEXIST') throw new EvidenceDisclosureAuthenticationError(undefined, { reason: 'nonce_replay' });
    throw new EvidenceDisclosureStoreError('Recipient replay protection is unavailable.', {}, error);
  } finally {
    if (descriptor !== undefined) try { closeSync(descriptor); } catch {}
  }
}

function tenantDirectory(root, tenantId) {
  const directory = resolve(root, sha256(identifier(tenantId, 'tenantId')), 'records');
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  return directory;
}
function recordPath(root, tenantId, disclosureId) { return resolve(tenantDirectory(root, tenantId), `${disclosureId}.json`); }
function recordAad(tenantId, disclosureId) { return `basitclaw:evidence-disclosure:${tenantId}:${disclosureId}`; }
function atomicWrite(path, value) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.tmp-${process.pid}-${randomUUID()}`;
  let descriptor;
  try {
    descriptor = openSync(temporary, 'wx', 0o600);
    writeFileSync(descriptor, `${JSON.stringify(value)}\n`, 'utf8');
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    renameSync(temporary, path);
    const directory = openSync(dirname(path), 'r');
    try { fsyncSync(directory); } finally { closeSync(directory); }
  } catch (error) {
    if (descriptor !== undefined) try { closeSync(descriptor); } catch {}
    try { rmSync(temporary, { force: true }); } catch {}
    throw new EvidenceDisclosureStoreError('The evidence disclosure record could not be committed.', {}, error);
  }
}
function disclosureIdentifier(value) { const id = String(value ?? ''); if (!DISCLOSURE_ID.test(id)) throw new EvidenceValidationError('disclosureId is invalid.', { field: 'disclosureId' }); return id; }
function evidenceIdentifier(value) { const id = String(value ?? ''); if (!EVIDENCE_ID.test(id)) throw new EvidenceValidationError('evidenceId is invalid.', { field: 'evidenceId' }); return id; }
function hashValue(value, field) { const text = String(value ?? '').toLowerCase(); if (!HASH.test(text)) throw new EvidenceValidationError(`${field} must be a SHA-256 digest.`, { field }); return text; }
function identifier(value, field) { const text = String(value ?? '').trim(); if (!SAFE_ID.test(text)) throw new EvidenceValidationError(`${field} is invalid.`, { field }); return text; }
function cleanText(value, field, minimum, maximum) { const text = String(value ?? '').trim(); if (text.length < minimum || text.length > maximum) throw new EvidenceValidationError(`${field} must contain ${minimum} to ${maximum} characters.`, { field }); return text; }
function integer(value, field, minimum, maximum) { const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) throw new EvidenceValidationError(`${field} must be an integer from ${minimum} to ${maximum}.`, { field }); return parsed; }
function enumValue(value, allowed, field) { const text = String(value ?? ''); if (!allowed.has(text)) throw new EvidenceValidationError(`${field} must be one of ${[...allowed].join(', ')}.`, { field }); return text; }
function header(headers, name) { const value = headers?.[name]; return Array.isArray(value) ? String(value[0] ?? '').trim() : String(value ?? '').trim(); }
function requiredEnvironment(value, name) { const clean = environmentValue(value); if (clean === undefined) throw new EvidenceDisclosureStoreError(`${name} is required when evidence disclosure is enabled.`, { reason: `missing_${name.toLowerCase()}` }); return clean; }
function environmentValue(value) { const clean = typeof value === 'string' ? value.trim() : value; return clean === '' || clean === undefined || clean === null ? undefined : clean; }
function safeEqualHex(left, right) { const a = Buffer.from(left, 'hex'); const b = Buffer.from(right, 'hex'); return a.length === b.length && timingSafeEqual(a, b); }
function stableStringify(value) { if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`; if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`; return JSON.stringify(value); }

function disabledStore() {
  const status = Object.freeze({ status: 'disabled', enabled: false, mode: 'disabled', approvalQuorum: 0 });
  return Object.freeze({
    enabled: false, mode: 'disabled', approvalQuorum: 0,
    request() { throw new EvidenceConflictError('Evidence disclosure is disabled.'); },
    approve() { throw new EvidenceConflictError('Evidence disclosure is disabled.'); },
    revoke() { throw new EvidenceConflictError('Evidence disclosure is disabled.'); },
    claimSigned() { throw new EvidenceConflictError('Evidence disclosure is disabled.'); },
    acknowledgeSigned() { throw new EvidenceConflictError('Evidence disclosure is disabled.'); },
    get() { throw new EvidenceConflictError('Evidence disclosure is disabled.'); },
    list() { return []; }, report() { return { total: 0, byState: {}, byRecipient: {}, byResidencyZone: {}, approvalQuorum: 0 }; },
    verifyTenant(tenantId) { return { valid: true, tenantId, checkedRecords: 0, checkedEvents: 0 }; }, health() { return status; }
  });
}
