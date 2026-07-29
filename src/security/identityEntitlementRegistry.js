import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  randomUUID
} from 'node:crypto';
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync
} from 'node:fs';
import { dirname, resolve } from 'node:path';
import { permissionsForRole } from './accessControl.js';
import { createFileMutex } from './fileMutex.js';
import { deriveFederatedSubject, exactIssuer } from './federatedIdentity.js';

const FORMAT = 'basitclaw-identity-entitlements';
const VERSION = 1;
const MODES = new Set(['disabled', 'observe', 'enforce']);

export class IdentityEntitlementError extends Error {
  constructor(message, code = 'IDENTITY_ENTITLEMENT_DENIED', details = {}) {
    super(message);
    this.name = 'IdentityEntitlementError';
    this.code = code;
    this.details = details;
  }
}

export class IdentityEntitlementStoreError extends Error {
  constructor(message = 'The identity entitlement store is unavailable.', details = {}) {
    super(message);
    this.name = 'IdentityEntitlementStoreError';
    this.code = 'IDENTITY_ENTITLEMENT_STORE_UNAVAILABLE';
    this.details = details;
  }
}

export class IdentityEntitlementConflictError extends Error {
  constructor(message = 'The identity entitlement changed before this request was committed.', details = {}) {
    super(message);
    this.name = 'IdentityEntitlementConflictError';
    this.code = 'IDENTITY_ENTITLEMENT_CONFLICT';
    this.details = details;
  }
}

export function createIdentityEntitlementRegistry({
  mode = 'disabled',
  directory = '.runtime-data/workforce-audit-identities',
  keys = null,
  primaryKeyId = null,
  reviewMaxAgeDays = 365,
  eventRetention = 10_000,
  mutex = null,
  now = () => new Date()
} = {}) {
  const lifecycleMode = String(mode);
  if (!MODES.has(lifecycleMode)) throw new TypeError('Identity entitlement mode must be disabled, observe, or enforce.');
  const root = resolve(String(directory));
  const safeReviewDays = integer(reviewMaxAgeDays, 'reviewMaxAgeDays', 1, 3650);
  const safeEventRetention = integer(eventRetention, 'eventRetention', 100, 100_000);

  if (lifecycleMode === 'disabled') return createDisabledIdentityEntitlementRegistry();

  const keyring = normaliseKeyring(keys, primaryKeyId);
  const filePath = resolve(root, 'entitlements.enc.json');
  const lock = mutex ?? createFileMutex({ directory: resolve(root, '.locks') });
  ensureDirectory(root);

  function enforce(principal) {
    if (principal?.authMethod !== 'oidc') return principal;
    const snapshot = readSnapshot();
    const record = snapshot.users[principal.subject];
    const current = now();
    if (!record) {
      if (lifecycleMode === 'observe') return observed(principal, 'unprovisioned');
      throw denied('The federated identity has not been provisioned.', 'IDENTITY_NOT_PROVISIONED', principal);
    }
    if (!record.active) {
      if (lifecycleMode === 'observe') return observed(principal, 'suspended', record);
      throw denied('The federated identity is suspended.', 'IDENTITY_SUSPENDED', principal, record);
    }
    if (record.tenantId !== principal.tenantId || record.role !== principal.role) {
      if (lifecycleMode === 'observe') return observed(principal, 'mismatched', record);
      throw denied('The federated token does not match the approved entitlement.', 'IDENTITY_ENTITLEMENT_MISMATCH', principal, record);
    }
    if (new Date(record.reviewBy).getTime() <= current.getTime()) {
      if (lifecycleMode === 'observe') return observed(principal, 'review_overdue', record);
      throw denied('The federated identity entitlement review is overdue.', 'IDENTITY_REVIEW_OVERDUE', principal, record);
    }
    return observed(principal, 'active', record);
  }

  function upsert(input, context = {}) {
    return mutate((snapshot) => {
      const clean = normaliseProvisioningInput(input, { now, reviewMaxAgeDays: safeReviewDays });
      const subject = deriveFederatedSubject(clean.issuer, clean.externalSubject).subject;
      const existing = snapshot.users[subject] ?? null;
      assertVersion(existing, input.expectedVersion);
      const timestamp = now().toISOString();
      const record = {
        id: existing?.id ?? `IDN-${randomUUID()}`,
        subject,
        tenantId: clean.tenantId,
        role: clean.role,
        active: clean.active,
        displayName: clean.displayName,
        reviewBy: clean.reviewBy,
        source: clean.source,
        createdAt: existing?.createdAt ?? timestamp,
        updatedAt: timestamp,
        version: (existing?.version ?? 0) + 1
      };
      snapshot.users[subject] = record;
      appendEvent(snapshot, {
        actor: safeActor(context.actor),
        action: existing ? 'identity.entitlement.updated' : 'identity.entitlement.created',
        subject,
        tenantId: record.tenantId,
        role: record.role,
        active: record.active,
        reason: clean.reason,
        version: record.version
      }, safeEventRetention, timestamp);
      return structuredClone(record);
    });
  }

  function patch(id, changes, context = {}) {
    return mutate((snapshot) => {
      const existing = findById(snapshot, id);
      assertVersion(existing, changes.expectedVersion);
      if (changes.active !== undefined && typeof changes.active !== 'boolean') throw new TypeError('active must be a boolean.');
      const timestamp = now().toISOString();
      const next = {
        ...existing,
        tenantId: changes.tenantId === undefined ? existing.tenantId : safeIdentifier(changes.tenantId, 'tenantId'),
        role: changes.role === undefined ? existing.role : safeRole(changes.role),
        active: changes.active === undefined ? existing.active : changes.active,
        displayName: changes.displayName === undefined ? existing.displayName : optionalText(changes.displayName, 256),
        reviewBy: changes.reviewBy === undefined ? existing.reviewBy : reviewDate(changes.reviewBy, now()),
        updatedAt: timestamp,
        version: existing.version + 1
      };
      snapshot.users[existing.subject] = next;
      appendEvent(snapshot, {
        actor: safeActor(context.actor),
        action: next.active ? 'identity.entitlement.updated' : 'identity.entitlement.suspended',
        subject: next.subject,
        tenantId: next.tenantId,
        role: next.role,
        active: next.active,
        reason: requiredReason(changes.reason),
        version: next.version
      }, safeEventRetention, timestamp);
      return structuredClone(next);
    });
  }

  function deactivate(id, { expectedVersion, reason } = {}, context = {}) {
    return patch(id, { active: false, expectedVersion, reason }, context);
  }

  function get(id) {
    return structuredClone(findById(readSnapshot(), id));
  }

  function getBySubject(subject) {
    const record = readSnapshot().users[String(subject)] ?? null;
    return record ? structuredClone(record) : null;
  }

  function list({ startIndex = 1, count = 100, active = null, tenantId = null } = {}) {
    const snapshot = readSnapshot();
    const offset = integer(startIndex, 'startIndex', 1, Number.MAX_SAFE_INTEGER) - 1;
    const limit = integer(count, 'count', 1, 500);
    let records = Object.values(snapshot.users).sort((a, b) => a.id.localeCompare(b.id));
    if (active !== null) records = records.filter((item) => item.active === Boolean(active));
    if (tenantId) records = records.filter((item) => item.tenantId === safeIdentifier(tenantId, 'tenantId'));
    return {
      totalResults: records.length,
      startIndex: offset + 1,
      itemsPerPage: Math.min(limit, Math.max(0, records.length - offset)),
      resources: structuredClone(records.slice(offset, offset + limit))
    };
  }

  function listEvents({ limit = 100 } = {}) {
    const safeLimit = integer(limit, 'limit', 1, 1000);
    return structuredClone(readSnapshot().events.slice(-safeLimit).reverse());
  }

  function reviewStatus() {
    const snapshot = readSnapshot();
    const current = now().getTime();
    const records = Object.values(snapshot.users);
    const overdue = records.filter((item) => item.active && new Date(item.reviewBy).getTime() <= current);
    const dueSoon = records.filter((item) => item.active && new Date(item.reviewBy).getTime() > current
      && new Date(item.reviewBy).getTime() <= current + 30 * 86_400_000);
    return {
      status: overdue.length > 0 ? 'attention' : 'ready',
      generatedAt: now().toISOString(),
      total: records.length,
      active: records.filter((item) => item.active).length,
      suspended: records.filter((item) => !item.active).length,
      overdue: overdue.length,
      dueWithin30Days: dueSoon.length,
      tenantCount: new Set(records.map((item) => item.tenantId)).size,
      sequence: snapshot.sequence
    };
  }

  function health() {
    try {
      const review = reviewStatus();
      const { status: reviewStatusValue, ...reviewMetrics } = review;
      return {
        status: 'ready',
        reviewStatus: reviewStatusValue,
        enabled: true,
        required: lifecycleMode === 'enforce',
        mode: lifecycleMode,
        encrypted: true,
        durable: true,
        distributed: true,
        configuredKeyCount: keyring.keys.size,
        primaryKeyId: keyring.primaryKeyId,
        ...reviewMetrics
      };
    } catch (error) {
      return {
        status: 'unavailable', enabled: true, required: lifecycleMode === 'enforce', mode: lifecycleMode,
        encrypted: true, durable: true, distributed: true, error: error.message
      };
    }
  }

  function tenantIds() {
    return [...new Set(Object.values(readSnapshot().users).filter((item) => item.active).map((item) => item.tenantId))];
  }

  function mutate(operation) {
    try {
      return lock.withLock('identity-entitlements', () => {
        const snapshot = readSnapshotUnlocked();
        const result = operation(snapshot);
        snapshot.updatedAt = now().toISOString();
        snapshot.sequence += 1;
        writeSnapshotUnlocked(snapshot);
        return result;
      });
    } catch (error) {
      if (error instanceof IdentityEntitlementError || error instanceof IdentityEntitlementConflictError) throw error;
      throw storeError(error);
    }
  }

  function readSnapshot() {
    try { return lock.withLock('identity-entitlements', readSnapshotUnlocked); }
    catch (error) { throw storeError(error); }
  }

  function readSnapshotUnlocked() {
    if (!existsSync(filePath)) return emptySnapshot(now());
    let envelope;
    try { envelope = JSON.parse(readFileSync(filePath, 'utf8')); }
    catch (error) { throw new Error(`Identity entitlement envelope is unreadable: ${error.message}`); }
    return decryptEnvelope(envelope, keyring);
  }

  function writeSnapshotUnlocked(snapshot) {
    const envelope = encryptSnapshot(snapshot, keyring);
    atomicWrite(filePath, `${JSON.stringify(envelope)}\n`);
  }

  return {
    enforce, upsert, patch, deactivate, get, getBySubject, list, listEvents, reviewStatus, health, tenantIds,
    mode: lifecycleMode, directory: root
  };
}

export function createIdentityEntitlementRegistryFromEnvironment(env = process.env, options = {}) {
  const mode = String(env.WORKFORCE_AUDIT_IDENTITY_ENTITLEMENT_MODE ?? 'disabled');
  if (mode === 'disabled') return createIdentityEntitlementRegistry({ mode });
  const keys = parseRequiredJson(env.WORKFORCE_AUDIT_IDENTITY_STORE_KEYS, 'WORKFORCE_AUDIT_IDENTITY_STORE_KEYS');
  const primaryKeyId = String(env.WORKFORCE_AUDIT_IDENTITY_STORE_PRIMARY_KEY_ID ?? '');
  if (!primaryKeyId) throw new TypeError('WORKFORCE_AUDIT_IDENTITY_STORE_PRIMARY_KEY_ID is required when entitlement lifecycle is enabled.');
  if (env.NODE_ENV === 'production' && mode !== 'enforce') {
    throw new TypeError('Production entitlement lifecycle must use enforce mode when enabled.');
  }
  return createIdentityEntitlementRegistry({
    mode,
    directory: env.WORKFORCE_AUDIT_IDENTITY_STORE_DIR ?? '.runtime-data/workforce-audit-identities',
    keys,
    primaryKeyId,
    reviewMaxAgeDays: Number(env.WORKFORCE_AUDIT_IDENTITY_REVIEW_MAX_AGE_DAYS ?? 365),
    eventRetention: Number(env.WORKFORCE_AUDIT_IDENTITY_EVENT_RETENTION ?? 10_000),
    ...options
  });
}

export function createDisabledIdentityEntitlementRegistry() {
  const disabled = () => {
    throw new IdentityEntitlementError(
      'The identity entitlement lifecycle is disabled.',
      'IDENTITY_ENTITLEMENT_LIFECYCLE_DISABLED'
    );
  };
  return {
    mode: 'disabled',
    enforce: (principal) => principal,
    upsert: disabled,
    patch: disabled,
    deactivate: disabled,
    get: disabled,
    getBySubject: () => null,
    tenantIds: () => [],
    health: () => ({ status: 'disabled', enabled: false, required: false, mode: 'disabled' }),
    reviewStatus: () => ({ status: 'disabled', total: 0, active: 0, suspended: 0, overdue: 0, dueWithin30Days: 0, tenantCount: 0, sequence: 0 }),
    list: () => ({ totalResults: 0, startIndex: 1, itemsPerPage: 0, resources: [] }),
    listEvents: () => []
  };
}

function normaliseProvisioningInput(input, { now, reviewMaxAgeDays }) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new TypeError('Identity provisioning input must be an object.');
  const current = now();
  if (input.active !== undefined && typeof input.active !== 'boolean') throw new TypeError('active must be a boolean.');
  return {
    issuer: exactIssuer(input.issuer),
    externalSubject: requiredText(input.externalSubject, 'externalSubject', 512),
    tenantId: safeIdentifier(input.tenantId, 'tenantId'),
    role: safeRole(input.role),
    active: input.active !== false,
    displayName: optionalText(input.displayName, 256),
    reviewBy: input.reviewBy ? reviewDate(input.reviewBy, current) : new Date(current.getTime() + reviewMaxAgeDays * 86_400_000).toISOString(),
    reason: requiredReason(input.reason),
    source: safeIdentifier(input.source ?? 'scim', 'source')
  };
}

function observed(principal, status, record = null) {
  return Object.freeze({
    ...principal,
    entitlementStatus: status,
    ...(record ? {
      entitlementId: record.id,
      entitlementVersion: record.version,
      entitlementReviewBy: record.reviewBy,
      approvedTenantId: record.tenantId,
      approvedRole: record.role
    } : {})
  });
}

function denied(message, code, principal, record = null) {
  return new IdentityEntitlementError(message, code, {
    subject: principal.subject,
    tenantId: principal.tenantId,
    approvedTenantId: record?.tenantId ?? null,
    approvedRole: record?.role ?? null,
    reason: code.toLowerCase()
  });
}

function assertVersion(existing, expectedVersion) {
  if (expectedVersion === undefined || expectedVersion === null) return;
  const expected = Number(expectedVersion);
  const actual = existing?.version ?? 0;
  if (!Number.isInteger(expected) || expected !== actual) {
    throw new IdentityEntitlementConflictError(undefined, { expectedVersion: expected, actualVersion: actual });
  }
}

function findById(snapshot, id) {
  const safeId = String(id ?? '').trim();
  const record = Object.values(snapshot.users).find((item) => item.id === safeId);
  if (!record) throw new IdentityEntitlementError('The identity entitlement was not found.', 'IDENTITY_ENTITLEMENT_NOT_FOUND', { id: safeId });
  return record;
}

function appendEvent(snapshot, input, retention, occurredAt) {
  const previousHash = snapshot.events.at(-1)?.hash ?? snapshot.eventAnchorHash ?? null;
  const event = {
    id: `IDE-${randomUUID()}`,
    sequence: (snapshot.events.at(-1)?.sequence ?? snapshot.eventAnchorSequence ?? 0) + 1,
    occurredAt,
    ...input,
    previousHash
  };
  event.hash = createHash('sha256').update(canonicalJson(event)).digest('hex');
  snapshot.events.push(event);
  if (snapshot.events.length > retention) {
    const removed = snapshot.events.splice(0, snapshot.events.length - retention);
    const anchor = removed.at(-1);
    snapshot.eventAnchorSequence = anchor.sequence;
    snapshot.eventAnchorHash = anchor.hash;
  }
}

function emptySnapshot(current) {
  return { format: FORMAT, version: VERSION, sequence: 0, updatedAt: current.toISOString(), users: {}, events: [], eventAnchorSequence: 0, eventAnchorHash: null };
}

function encryptSnapshot(snapshot, keyring) {
  const keyId = keyring.primaryKeyId;
  const key = keyring.keys.get(keyId);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const aad = Buffer.from(`${FORMAT}:${VERSION}:${keyId}`, 'utf8');
  cipher.setAAD(aad);
  const plaintext = Buffer.from(JSON.stringify(snapshot), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    format: FORMAT, version: VERSION, keyId,
    iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), ciphertext: ciphertext.toString('base64')
  };
}

function decryptEnvelope(envelope, keyring) {
  if (envelope?.format !== FORMAT || envelope?.version !== VERSION) throw new Error('Identity entitlement envelope format is invalid.');
  const key = keyring.keys.get(String(envelope.keyId));
  if (!key) throw new Error('Identity entitlement envelope references an unavailable historical key.');
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.iv, 'base64'));
    decipher.setAAD(Buffer.from(`${FORMAT}:${VERSION}:${envelope.keyId}`, 'utf8'));
    decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
    const plaintext = Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, 'base64')), decipher.final()]);
    const snapshot = JSON.parse(plaintext.toString('utf8'));
    validateSnapshot(snapshot);
    return snapshot;
  } catch (error) {
    throw new Error(`Identity entitlement envelope integrity check failed: ${error.message}`);
  }
}

function validateSnapshot(snapshot) {
  if (snapshot?.format !== FORMAT || snapshot?.version !== VERSION || !snapshot.users || !Array.isArray(snapshot.events)) {
    throw new Error('Identity entitlement snapshot is invalid.');
  }
  let previousHash = snapshot.eventAnchorHash ?? null;
  let previousSequence = Number(snapshot.eventAnchorSequence ?? 0);
  for (const event of snapshot.events) {
    const hash = event.hash;
    const comparable = { ...event };
    delete comparable.hash;
    const expected = createHash('sha256').update(canonicalJson(comparable)).digest('hex');
    if (hash !== expected || event.previousHash !== previousHash || event.sequence !== previousSequence + 1) {
      throw new Error('Identity entitlement event chain is invalid.');
    }
    previousHash = hash;
    previousSequence = event.sequence;
  }
}

function normaliseKeyring(value, primaryKeyId) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('Identity store keys must be an object.');
  const keys = new Map();
  for (const [id, encoded] of Object.entries(value)) {
    const keyId = safeIdentifier(id, 'keyId');
    const key = Buffer.from(String(encoded), 'base64');
    if (key.length !== 32 || key.toString('base64') !== String(encoded)) throw new TypeError(`Identity store key ${keyId} must be a base64-encoded 32-byte key.`);
    keys.set(keyId, key);
  }
  const primary = safeIdentifier(primaryKeyId, 'primaryKeyId');
  if (!keys.has(primary)) throw new TypeError('Identity store primary key ID is not present in the keyring.');
  return { keys, primaryKeyId: primary };
}

function atomicWrite(path, content) {
  ensureDirectory(dirname(path));
  const temporary = `${path}.tmp-${process.pid}-${randomUUID()}`;
  let fd;
  try {
    fd = openSync(temporary, 'wx', 0o600);
    writeFileSync(fd, content, 'utf8');
    fsyncSync(fd);
    closeSync(fd);
    fd = null;
    renameSync(temporary, path);
    const directoryFd = openSync(dirname(path), 'r');
    try { fsyncSync(directoryFd); } finally { closeSync(directoryFd); }
  } catch (error) {
    if (fd !== undefined && fd !== null) try { closeSync(fd); } catch {}
    try { unlinkSync(temporary); } catch {}
    throw error;
  }
}

function ensureDirectory(directory) { mkdirSync(directory, { recursive: true, mode: 0o700 }); }
function storeError(error) {
  if (error instanceof IdentityEntitlementStoreError) return error;
  return new IdentityEntitlementStoreError(undefined, { cause: error?.code ?? error?.message ?? 'unknown' });
}
function safeRole(value) {
  const role = String(value ?? '');
  try { permissionsForRole(role); } catch { throw new TypeError('Unsupported workforce-audit role.'); }
  return role;
}
function safeIdentifier(value, field) { const v = String(value ?? '').trim(); if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(v)) throw new TypeError(`${field} must be a safe identifier.`); return v; }
function requiredText(value, field, max) { const v = String(value ?? '').trim(); if (!v || v.length > max) throw new TypeError(`${field} must contain from 1 to ${max} characters.`); return v; }
function optionalText(value, max) { if (value === undefined || value === null || value === '') return null; return requiredText(value, 'text', max); }
function requiredReason(value) { return requiredText(value, 'reason', 500); }
function safeActor(value) { return safeIdentifier(value ?? 'identity-provider', 'actor'); }
function reviewDate(value, current) { const date = new Date(value); if (Number.isNaN(date.getTime()) || date.getTime() <= current.getTime()) throw new TypeError('reviewBy must be a future date.'); return date.toISOString(); }
function integer(value, field, min, max) { const n = Number(value); if (!Number.isSafeInteger(n) || n < min || n > max) throw new TypeError(`${field} must be an integer from ${min} to ${max}.`); return n; }
function parseRequiredJson(raw, field) { if (!raw) throw new TypeError(`${field} is required.`); try { return JSON.parse(raw); } catch { throw new TypeError(`${field} must contain valid JSON.`); } }
function canonicalJson(value) { return JSON.stringify(sortValue(value)); }
function sortValue(value) { if (Array.isArray(value)) return value.map(sortValue); if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortValue(value[key])])); return value; }
