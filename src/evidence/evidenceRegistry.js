import { createHash, randomUUID } from 'node:crypto';
import { basename, resolve } from 'node:path';
import { existsSync, mkdirSync, readdirSync, rmSync } from 'node:fs';
import { createFileMutex } from '../security/fileMutex.js';
import {
  atomicWriteEvidenceJson,
  decryptEvidenceJson,
  encryptEvidenceJson,
  parseEvidenceKeyring,
  readEvidenceJson,
  sha256,
  strictBase64,
  tenantEvidenceDirectory
} from './evidenceCrypto.js';

const CONTENT_FORMAT = 'basitclaw-workforce-audit-evidence';
const INDEX_FORMAT = 'basitclaw-workforce-audit-evidence-index';
const EVIDENCE_ID = /^EVD-[a-f0-9]{32}$/;
const PLACEHOLDER_ID = /^PLH-ENG-\d{4}-\d{3}-\d{2}$/;
const DAY_MS = 86_400_000;

class EvidenceError extends Error {
  constructor(message, code, statusCode, details = {}, cause = null) {
    super(message, cause ? { cause } : undefined);
    this.name = this.constructor.name;
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
  }
}

export class EvidenceValidationError extends EvidenceError {
  constructor(message, details = {}) {
    super(message, 'EVIDENCE_VALIDATION_FAILED', 400, details);
  }
}

export class EvidenceNotFoundError extends EvidenceError {
  constructor(id) {
    super('The requested evidence item was not found.', 'EVIDENCE_NOT_FOUND', 404, { evidenceId: id });
  }
}

export class EvidenceConflictError extends EvidenceError {
  constructor(message, details = {}) {
    super(message, 'EVIDENCE_CONFLICT', 409, details);
  }
}

export class EvidenceIntegrityError extends EvidenceError {
  constructor(message, details = {}, cause = null) {
    super(message, 'EVIDENCE_INTEGRITY_FAILED', 409, details, cause);
  }
}

export class EvidenceStoreError extends EvidenceError {
  constructor(message = 'The evidence store is unavailable.', details = {}, cause = null) {
    super(message, 'EVIDENCE_STORE_UNAVAILABLE', 503, details, cause);
  }
}

export function createEvidenceRegistry({
  mode = 'shared-file',
  required = false,
  directory,
  keys,
  primaryKeyId,
  maxBytes = 10_000_000,
  defaultRetentionDays = 2555,
  eventRetention = 10_000,
  now = () => new Date(),
  mutex = null
} = {}) {
  if (mode === 'disabled') return disabledRegistry(required);
  if (mode !== 'shared-file') throw new TypeError('Evidence mode must be shared-file or disabled.');
  if (!String(directory ?? '').trim()) throw new TypeError('An evidence directory is required.');

  const root = resolve(String(directory));
  const keyring = parseEvidenceKeyring(keys, primaryKeyId);
  const max = integer(maxBytes, 'maxBytes', 1, 100_000_000);
  const defaultDays = integer(defaultRetentionDays, 'defaultRetentionDays', 1, 36_500);
  const retainedEvents = integer(eventRetention, 'eventRetention', 100, 100_000);
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const lock = mutex ?? createFileMutex({ directory: resolve(root, '.locks') });

  function ingest(tenantId, input, { actor } = {}) {
    const tenant = tenantIdentifier(tenantId);
    const by = actorIdentifier(actor);
    const upload = normaliseUpload(input, { now, max, defaultDays });
    const evidenceId = `EVD-${randomUUID().replaceAll('-', '')}`;

    return lock.withLock(`evidence:${tenant}`, () => {
      const index = loadIndex(tenant);
      const version = createVersion(1, upload, by, now, keyring.primaryKeyId);
      const item = {
        evidenceId,
        tenantId: tenant,
        filename: upload.filename,
        mediaType: upload.mediaType,
        description: upload.description,
        sourceType: upload.sourceType,
        sourceSystem: upload.sourceSystem,
        collectedAt: upload.collectedAt,
        ingestedAt: version.createdAt,
        ingestedBy: by,
        retentionUntil: upload.retentionUntil,
        status: 'active',
        currentVersion: 1,
        versions: [version],
        legalHold: null,
        disposedAt: null,
        disposedBy: null,
        dispositionReason: null,
        purgePending: false
      };
      const path = contentPath(tenant, evidenceId, 1);
      try {
        atomicWriteEvidenceJson(
          path,
          encryptEvidenceJson(
            contentPayload(tenant, evidenceId, 1, upload),
            keyring,
            contentAad(tenant, evidenceId, 1)
          )
        );
        index.items.push(item);
        appendEvent(index, by, 'evidence.ingested', evidenceId, {
          version: 1,
          sha256: version.sha256,
          sizeBytes: version.sizeBytes,
          retentionUntil: item.retentionUntil,
          sourceType: item.sourceType
        });
        saveIndex(tenant, index);
        return publicItem(item);
      } catch (error) {
        try { rmSync(path, { force: true }); } catch {}
        throw storeFailure(error, 'ingest', evidenceId);
      }
    });
  }

  function addVersion(tenantId, evidenceId, input, { actor } = {}) {
    const tenant = tenantIdentifier(tenantId);
    const id = evidenceIdentifier(evidenceId);
    const by = actorIdentifier(actor);
    const upload = normaliseUpload(input, { now, max, defaultDays, retentionOptional: true });

    return lock.withLock(`evidence:${tenant}`, () => {
      const index = loadIndex(tenant);
      const item = findItem(index, id);
      assertActive(item);
      if (item.legalHold?.active && input.retentionUntil
          && new Date(input.retentionUntil) < new Date(item.retentionUntil)) {
        throw new EvidenceConflictError('Evidence under legal hold cannot have its retention shortened.', { evidenceId: id });
      }

      const number = item.currentVersion + 1;
      const version = createVersion(number, upload, by, now, keyring.primaryKeyId);
      const next = {
        ...item,
        filename: upload.filename,
        mediaType: upload.mediaType,
        description: input.description === undefined ? item.description : upload.description,
        sourceType: input.sourceType === undefined ? item.sourceType : upload.sourceType,
        sourceSystem: input.sourceSystem === undefined ? item.sourceSystem : upload.sourceSystem,
        collectedAt: input.collectedAt === undefined ? item.collectedAt : upload.collectedAt,
        retentionUntil: input.retentionUntil ? upload.retentionUntil : item.retentionUntil,
        currentVersion: number,
        versions: [...item.versions, version]
      };
      const path = contentPath(tenant, id, number);
      try {
        atomicWriteEvidenceJson(
          path,
          encryptEvidenceJson(
            contentPayload(tenant, id, number, upload),
            keyring,
            contentAad(tenant, id, number)
          )
        );
        Object.assign(item, next);
        appendEvent(index, by, 'evidence.version_added', id, {
          version: number,
          sha256: version.sha256,
          sizeBytes: version.sizeBytes
        });
        saveIndex(tenant, index);
        return publicItem(item);
      } catch (error) {
        try { rmSync(path, { force: true }); } catch {}
        throw storeFailure(error, 'add_version', id);
      }
    });
  }

  function list(tenantId, { status = null, legalHold = null, limit = 500 } = {}) {
    let items = loadSafe(tenantIdentifier(tenantId)).items;
    if (status) items = items.filter((item) => item.status === status);
    if (legalHold !== null) {
      items = items.filter((item) => Boolean(item.legalHold?.active) === Boolean(legalHold));
    }
    return items
      .slice(-integer(limit, 'limit', 1, 5000))
      .reverse()
      .map(publicItem);
  }

  function get(tenantId, evidenceId) {
    return publicItem(findItem(loadSafe(tenantIdentifier(tenantId)), evidenceIdentifier(evidenceId)));
  }

  function readContent(tenantId, evidenceId, { version = null } = {}) {
    const tenant = tenantIdentifier(tenantId);
    const id = evidenceIdentifier(evidenceId);
    const item = findItem(loadSafe(tenant), id);
    assertActive(item);
    const number = version === null
      ? item.currentVersion
      : integer(version, 'version', 1, item.currentVersion);
    const record = item.versions.find((entry) => entry.version === number);
    if (!record) throw new EvidenceNotFoundError(`${id}:v${number}`);
    const content = decryptContent(tenant, item, record);
    return {
      evidenceId: id,
      version: number,
      filename: record.filename ?? item.filename,
      mediaType: record.mediaType ?? item.mediaType,
      sha256: record.sha256,
      sizeBytes: record.sizeBytes,
      content
    };
  }

  function placeLegalHold(tenantId, evidenceId, input, { actor } = {}) {
    const tenant = tenantIdentifier(tenantId);
    const id = evidenceIdentifier(evidenceId);
    const by = actorIdentifier(actor);
    const reason = cleanText(input?.reason, 'reason', 10, 1000);
    const matterId = safeIdentifier(input?.matterId, 'matterId');
    const reviewAt = futureDate(input?.reviewAt, 'reviewAt', now());

    return mutate(tenant, id, by, 'evidence.legal_hold_placed', (item) => {
      assertActive(item);
      if (item.legalHold?.active) {
        throw new EvidenceConflictError('A legal hold is already active for this evidence item.', { evidenceId: id });
      }
      item.legalHold = {
        active: true,
        matterId,
        reason,
        placedAt: now().toISOString(),
        placedBy: by,
        reviewAt,
        releasedAt: null,
        releasedBy: null,
        releaseReason: null
      };
      return { matterFingerprint: sha256(Buffer.from(matterId)), reviewAt };
    });
  }

  function releaseLegalHold(tenantId, evidenceId, input, { actor } = {}) {
    const tenant = tenantIdentifier(tenantId);
    const id = evidenceIdentifier(evidenceId);
    const by = actorIdentifier(actor);
    if (input?.confirmation !== `RELEASE HOLD ${id}`) {
      throw new EvidenceValidationError(`confirmation must be exactly RELEASE HOLD ${id}.`, { field: 'confirmation' });
    }
    const reason = cleanText(input?.reason, 'reason', 10, 1000);

    return mutate(tenant, id, by, 'evidence.legal_hold_released', (item) => {
      assertActive(item);
      if (!item.legalHold?.active) {
        throw new EvidenceConflictError('No active legal hold exists for this evidence item.', { evidenceId: id });
      }
      const fingerprint = sha256(Buffer.from(item.legalHold.matterId));
      item.legalHold = {
        ...item.legalHold,
        active: false,
        releasedAt: now().toISOString(),
        releasedBy: by,
        releaseReason: reason
      };
      return { matterFingerprint: fingerprint };
    });
  }

  function dispose(tenantId, evidenceId, input, { actor, referencedBy = [] } = {}) {
    const tenant = tenantIdentifier(tenantId);
    const id = evidenceIdentifier(evidenceId);
    const by = actorIdentifier(actor);
    if (input?.confirmation !== `DISPOSE ${id}`) {
      throw new EvidenceValidationError(`confirmation must be exactly DISPOSE ${id}.`, { field: 'confirmation' });
    }
    const reason = cleanText(input?.reason, 'reason', 10, 1000);
    if (referencedBy.length) {
      throw new EvidenceConflictError('Evidence referenced by audit findings cannot be disposed.', {
        evidenceId: id,
        findingIds: referencedBy.slice(0, 100)
      });
    }

    return lock.withLock(`evidence:${tenant}`, () => {
      const index = loadIndex(tenant);
      const item = findItem(index, id);
      assertActive(item);
      if (item.legalHold?.active) {
        throw new EvidenceConflictError('Evidence under legal hold cannot be disposed.', { evidenceId: id });
      }
      if (new Date(item.retentionUntil) > now()) {
        throw new EvidenceConflictError('Evidence cannot be disposed before its retention date.', {
          evidenceId: id,
          retentionUntil: item.retentionUntil
        });
      }

      item.status = 'disposed';
      item.disposedAt = now().toISOString();
      item.disposedBy = by;
      item.dispositionReason = reason;
      item.purgePending = true;
      appendEvent(index, by, 'evidence.disposition_committed', id, {
        versionCount: item.versions.length,
        retentionUntil: item.retentionUntil
      });
      saveIndex(tenant, index);

      let failed = false;
      for (const version of item.versions) {
        try { rmSync(contentPath(tenant, id, version.version), { force: true }); }
        catch { failed = true; }
      }
      if (!failed) {
        item.purgePending = false;
        appendEvent(index, by, 'evidence.content_purged', id, { versionCount: item.versions.length });
        saveIndex(tenant, index);
      }
      return publicItem(item);
    });
  }

  function assertUsableReferences(tenantId, references) {
    if (!Array.isArray(references)) {
      throw new EvidenceValidationError('Evidence references must be an array.', { field: 'evidenceRefs' });
    }
    const all = [...new Set(references.map((value) => String(value).trim()).filter(Boolean))];
    if (all.some((value) => !EVIDENCE_ID.test(value) && !PLACEHOLDER_ID.test(value))) {
      throw new EvidenceValidationError(
        'Evidence references must use registered EVD identifiers or valid PLH-ENG-YYYY-NNN-NN fieldwork placeholders.',
        { field: 'evidenceRefs' }
      );
    }
    const evidenceIds = all.filter((value) => EVIDENCE_ID.test(value));
    const tenant = tenantIdentifier(tenantId);
    const index = loadSafe(tenant);
    return evidenceIds.map((id) => {
      const item = findItem(index, id);
      assertActive(item);
      const currentVersion = item.versions.find((entry) => entry.version === item.currentVersion);
      decryptContent(tenant, item, currentVersion);
      return publicItem(item);
    });
  }

  function verify(tenantId, evidenceId = null) {
    const tenant = tenantIdentifier(tenantId);
    const index = loadSafe(tenant);
    verifyChain(index);
    const items = evidenceId ? [findItem(index, evidenceIdentifier(evidenceId))] : index.items;
    let checkedVersions = 0;
    for (const item of items) {
      if (item.status !== 'active') continue;
      for (const version of item.versions) {
        decryptContent(tenant, item, version);
        checkedVersions += 1;
      }
    }
    return {
      valid: true,
      tenantId: tenant,
      evidenceId: evidenceId ?? null,
      checkedItems: items.length,
      checkedVersions,
      eventCount: index.events.length,
      headSequence: index.sequence,
      headHash: index.headHash,
      anchorSequence: index.anchor?.sequence ?? 0
    };
  }

  function events(tenantId, { evidenceId = null, limit = 500 } = {}) {
    const index = loadSafe(tenantIdentifier(tenantId));
    const rows = evidenceId
      ? index.events.filter((event) => event.evidenceId === evidenceIdentifier(evidenceId))
      : index.events;
    return rows
      .slice(-integer(limit, 'limit', 1, 5000))
      .reverse()
      .map((event) => structuredClone(event));
  }

  function health() {
    try {
      mkdirSync(root, { recursive: true, mode: 0o700 });
      const tenants = readdirSync(root, { withFileTypes: true })
        .filter((entry) => entry.isDirectory() && entry.name !== '.locks').length;
      return {
        status: 'ready',
        enabled: true,
        required: Boolean(required),
        mode: 'shared-file-encrypted-evidence',
        durable: true,
        distributed: true,
        encrypted: true,
        maxBytes: max,
        defaultRetentionDays: defaultDays,
        eventRetention: retainedEvents,
        tenantDirectoryCount: tenants,
        mutex: lock.health()
      };
    } catch (error) {
      console.error('Evidence store health check failed', { code: error?.code ?? 'unknown', error });
      return {
        status: 'unavailable',
        enabled: true,
        required: Boolean(required),
        mode: 'shared-file-encrypted-evidence',
        error: error?.code ?? 'evidence_store_unavailable'
      };
    }
  }

  function tenantStatus(tenantId) {
    try {
      const index = loadSafe(tenantIdentifier(tenantId));
      const activeItems = index.items.filter((item) => item.status === 'active');
      const current = now();
      const holdReviewsOverdue = activeItems.filter((item) => item.legalHold?.active
        && item.legalHold.reviewAt
        && new Date(item.legalHold.reviewAt) <= current).length;
      const purgePending = index.items.filter((item) => item.purgePending).length;
      return {
        status: holdReviewsOverdue || purgePending ? 'attention' : 'ready',
        enabled: true,
        required: Boolean(required),
        total: index.items.length,
        active: activeItems.length,
        disposed: index.items.length - activeItems.length,
        legalHolds: activeItems.filter((item) => item.legalHold?.active).length,
        retentionDue: activeItems.filter((item) => new Date(item.retentionUntil) <= current
          && !item.legalHold?.active).length,
        holdReviewsOverdue,
        purgePending,
        headSequence: index.sequence,
        headHash: index.headHash,
        anchorSequence: index.anchor?.sequence ?? 0
      };
    } catch (error) {
      console.error('Evidence tenant status check failed', { code: error?.code ?? 'unknown', error });
      return {
        status: 'unavailable',
        enabled: true,
        required: Boolean(required),
        error: error?.code ?? 'evidence_store_unavailable'
      };
    }
  }

  function mutate(tenant, evidenceId, actor, action, operation) {
    return lock.withLock(`evidence:${tenant}`, () => {
      const index = loadIndex(tenant);
      const item = findItem(index, evidenceId);
      const metadata = operation(item) ?? {};
      appendEvent(index, actor, action, evidenceId, metadata);
      saveIndex(tenant, index);
      return publicItem(item);
    });
  }

  function loadSafe(tenant) {
    try {
      return loadIndex(tenant);
    } catch (error) {
      if (error instanceof EvidenceError) throw error;
      throw storeFailure(error, 'load_index');
    }
  }

  function loadIndex(tenant) {
    const path = indexPath(tenant);
    if (!existsSync(path)) return emptyIndex(tenant);
    let envelope;
    try {
      envelope = readEvidenceJson(path);
    } catch (error) {
      throw new EvidenceIntegrityError('The evidence index is unreadable.', { tenantId: tenant }, error);
    }
    const index = decryptEvidenceJson(envelope, keyring, indexAad(tenant), EvidenceIntegrityError);
    if (index.format !== INDEX_FORMAT || index.version !== 1 || index.tenantId !== tenant) {
      throw new EvidenceIntegrityError('The evidence index identity is invalid.', { tenantId: tenant });
    }
    verifyChain(index);
    return index;
  }

  function saveIndex(tenant, index) {
    atomicWriteEvidenceJson(
      indexPath(tenant),
      encryptEvidenceJson(index, keyring, indexAad(tenant))
    );
  }

  function indexPath(tenant) {
    return resolve(tenantEvidenceDirectory(root, tenant), 'index.evidence');
  }

  function contentPath(tenant, evidenceId, version) {
    const folder = resolve(tenantEvidenceDirectory(root, tenant), 'items', evidenceId);
    mkdirSync(folder, { recursive: true, mode: 0o700 });
    return resolve(folder, `v${String(version).padStart(6, '0')}.evidence`);
  }

  function decryptContent(tenant, item, version) {
    if (!version) {
      throw new EvidenceIntegrityError('The current evidence version metadata is missing.', {
        evidenceId: item.evidenceId
      });
    }
    const path = contentPath(tenant, item.evidenceId, version.version);
    if (!existsSync(path)) {
      throw new EvidenceIntegrityError('An evidence content version is missing.', {
        evidenceId: item.evidenceId,
        version: version.version
      });
    }
    let envelope;
    try {
      envelope = readEvidenceJson(path);
    } catch (error) {
      throw new EvidenceIntegrityError('An evidence content version is unreadable.', {
        evidenceId: item.evidenceId,
        version: version.version
      }, error);
    }
    const payload = decryptEvidenceJson(
      envelope,
      keyring,
      contentAad(tenant, item.evidenceId, version.version),
      EvidenceIntegrityError
    );
    if (payload.format !== CONTENT_FORMAT
        || payload.tenantId !== tenant
        || payload.evidenceId !== item.evidenceId
        || payload.version !== version.version) {
      throw new EvidenceIntegrityError('Evidence content identity verification failed.', {
        evidenceId: item.evidenceId,
        version: version.version
      });
    }
    let content;
    try {
      content = strictBase64(payload.contentBase64, 'stored content');
    } catch (error) {
      throw new EvidenceIntegrityError('Stored evidence content is invalid.', {
        evidenceId: item.evidenceId
      }, error);
    }
    const digest = sha256(content);
    if (digest !== version.sha256
        || digest !== payload.sha256
        || content.length !== version.sizeBytes
        || content.length !== payload.sizeBytes) {
      throw new EvidenceIntegrityError('Evidence content checksum verification failed.', {
        evidenceId: item.evidenceId,
        version: version.version
      });
    }
    return content;
  }

  function appendEvent(index, actor, action, evidenceId, metadata) {
    const event = {
      eventId: `EVT-${randomUUID()}`,
      sequence: index.sequence + 1,
      occurredAt: now().toISOString(),
      actor,
      action,
      evidenceId,
      metadata,
      previousHash: index.headHash
    };
    event.hash = custodyEventHash(event);
    if (!index.sequence) index.createdAt = event.occurredAt;
    index.events.push(event);
    index.sequence = event.sequence;
    index.headHash = event.hash;
    index.updatedAt = event.occurredAt;
    if (index.events.length > retainedEvents) {
      const removed = index.events.splice(0, index.events.length - retainedEvents);
      const tail = removed.at(-1);
      index.anchor = { sequence: tail.sequence, hash: tail.hash, createdAt: event.occurredAt };
    }
  }

  function verifyChain(index) {
    let previousHash = index.anchor?.hash ?? null;
    let expectedSequence = (index.anchor?.sequence ?? 0) + 1;
    for (const event of index.events) {
      if (event.sequence !== expectedSequence
          || event.previousHash !== previousHash
          || event.hash !== custodyEventHash(event)) {
        throw new EvidenceIntegrityError('The evidence chain-of-custody event history is invalid.', {
          failedEventId: event.eventId,
          expectedSequence
        });
      }
      previousHash = event.hash;
      expectedSequence += 1;
    }
    if (index.sequence !== expectedSequence - 1 || index.headHash !== previousHash) {
      throw new EvidenceIntegrityError('The evidence chain head is inconsistent.', {
        sequence: index.sequence
      });
    }
  }

  return {
    enabled: true,
    required: Boolean(required),
    mode: 'shared-file',
    ingest,
    addVersion,
    list,
    get,
    readContent,
    placeLegalHold,
    releaseLegalHold,
    dispose,
    assertUsableReferences,
    verify,
    events,
    health,
    tenantStatus,
    directory: root
  };
}

export function createEvidenceRegistryFromEnvironment(env = process.env) {
  const mode = String(environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_MODE) ?? 'disabled');
  let required;
  try {
    required = booleanValue(
      environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_REQUIRED) ?? false,
      'WORKFORCE_AUDIT_EVIDENCE_REQUIRED'
    );
  } catch (error) {
    throw new EvidenceStoreError('Evidence storage configuration is invalid.', {
      field: 'WORKFORCE_AUDIT_EVIDENCE_REQUIRED'
    }, error);
  }

  if (mode === 'disabled') {
    if (required) {
      throw new EvidenceStoreError('Required evidence storage cannot be disabled.', {
        reason: 'required_disabled'
      });
    }
    return disabledRegistry(false);
  }

  let keys;
  try {
    keys = JSON.parse(environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_KEYS));
  } catch (error) {
    throw new EvidenceStoreError(
      'WORKFORCE_AUDIT_EVIDENCE_KEYS must be a valid JSON object.',
      { field: 'WORKFORCE_AUDIT_EVIDENCE_KEYS' },
      error
    );
  }

  try {
    return createEvidenceRegistry({
      mode,
      required,
      directory: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_DIR)
        ?? '.runtime-data/workforce-audit-evidence',
      keys,
      primaryKeyId: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_PRIMARY_KEY_ID),
      maxBytes: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_MAX_BYTES) ?? 10_000_000,
      defaultRetentionDays: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_DEFAULT_RETENTION_DAYS) ?? 2555,
      eventRetention: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_EVENT_RETENTION) ?? 10_000
    });
  } catch (error) {
    if (error instanceof EvidenceStoreError) throw error;
    throw new EvidenceStoreError('Evidence storage configuration is invalid.', {
      reason: error?.code ?? 'invalid_configuration'
    }, error);
  }
}

function disabledRegistry(required) {
  const unavailable = () => {
    throw new EvidenceStoreError('Evidence storage is disabled.', { reason: 'disabled' });
  };
  return {
    enabled: false,
    required: Boolean(required),
    mode: 'disabled',
    ingest: unavailable,
    addVersion: unavailable,
    list: () => [],
    get: unavailable,
    readContent: unavailable,
    placeLegalHold: unavailable,
    releaseLegalHold: unavailable,
    dispose: unavailable,
    assertUsableReferences: () => [],
    verify: () => ({ valid: true, disabled: true, checkedItems: 0, checkedVersions: 0 }),
    events: () => [],
    health: () => ({ status: 'disabled', enabled: false, required: Boolean(required), mode: 'disabled' }),
    tenantStatus: () => ({ status: 'disabled', enabled: false, required: Boolean(required) })
  };
}

function normaliseUpload(input, { now, max, defaultDays, retentionOptional = false }) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new EvidenceValidationError('A valid evidence upload object is required.');
  }
  let content;
  try {
    content = strictBase64(input.contentBase64, 'contentBase64');
  } catch {
    throw new EvidenceValidationError('contentBase64 must be canonical base64.', {
      field: 'contentBase64'
    });
  }
  if (!content.length || content.length > max) {
    throw new EvidenceValidationError('Evidence content is empty or exceeds the configured size limit.', {
      field: 'contentBase64',
      maxBytes: max
    });
  }

  const filename = safeFilename(input.filename);
  const mediaType = safeMediaType(input.mediaType);
  const description = input.description
    ? cleanText(input.description, 'description', 1, 1000)
    : '';
  const sourceType = allowedValue(input.sourceType ?? 'uploaded', 'sourceType', [
    'uploaded',
    'system_export',
    'email',
    'interview',
    'observation',
    'external_provider'
  ]);
  const sourceSystem = input.sourceSystem
    ? cleanText(input.sourceSystem, 'sourceSystem', 1, 200)
    : null;
  const collected = input.collectedAt ? validDate(input.collectedAt, 'collectedAt') : now();
  if (collected > new Date(now().getTime() + 300_000)) {
    throw new EvidenceValidationError('collectedAt cannot be in the future.', {
      field: 'collectedAt'
    });
  }
  const retention = !input.retentionUntil && retentionOptional
    ? null
    : input.retentionUntil
      ? validDate(input.retentionUntil, 'retentionUntil')
      : new Date(now().getTime() + defaultDays * DAY_MS);
  if (retention && retention <= now()) {
    throw new EvidenceValidationError('retentionUntil must be in the future.', {
      field: 'retentionUntil'
    });
  }

  return {
    content,
    sha256: sha256(content),
    filename,
    mediaType,
    description,
    sourceType,
    sourceSystem,
    collectedAt: collected.toISOString(),
    retentionUntil: retention?.toISOString() ?? null
  };
}

function createVersion(version, upload, actor, now, keyId) {
  return {
    version,
    objectName: `v${String(version).padStart(6, '0')}.evidence`,
    sha256: upload.sha256,
    sizeBytes: upload.content.length,
    createdAt: now().toISOString(),
    createdBy: actor,
    keyId,
    filename: upload.filename,
    mediaType: upload.mediaType
  };
}

function contentPayload(tenantId, evidenceId, version, upload) {
  return {
    format: CONTENT_FORMAT,
    version,
    tenantId,
    evidenceId,
    filename: upload.filename,
    mediaType: upload.mediaType,
    sha256: upload.sha256,
    sizeBytes: upload.content.length,
    contentBase64: upload.content.toString('base64')
  };
}

function emptyIndex(tenantId) {
  return {
    format: INDEX_FORMAT,
    version: 1,
    tenantId,
    createdAt: new Date(0).toISOString(),
    updatedAt: new Date(0).toISOString(),
    sequence: 0,
    headHash: null,
    anchor: null,
    items: [],
    events: []
  };
}

function publicItem(item) {
  const legalHold = item.legalHold
    ? {
        active: Boolean(item.legalHold.active),
        placedAt: item.legalHold.placedAt,
        reviewAt: item.legalHold.reviewAt,
        releasedAt: item.legalHold.releasedAt
      }
    : null;
  return structuredClone({
    evidenceId: item.evidenceId,
    filename: item.filename,
    mediaType: item.mediaType,
    description: item.description,
    sourceType: item.sourceType,
    sourceSystem: item.sourceSystem,
    collectedAt: item.collectedAt,
    ingestedAt: item.ingestedAt,
    ingestedBy: item.ingestedBy,
    retentionUntil: item.retentionUntil,
    status: item.status,
    currentVersion: item.currentVersion,
    versions: item.versions.map((version) => ({
      version: version.version,
      sha256: version.sha256,
      sizeBytes: version.sizeBytes,
      createdAt: version.createdAt,
      filename: version.filename ?? item.filename,
      mediaType: version.mediaType ?? item.mediaType
    })),
    legalHold,
    disposedAt: item.disposedAt,
    disposedBy: item.disposedBy,
    purgePending: Boolean(item.purgePending)
  });
}

function findItem(index, evidenceId) {
  const item = index.items.find((candidate) => candidate.evidenceId === evidenceId);
  if (!item) throw new EvidenceNotFoundError(evidenceId);
  return item;
}

function assertActive(item) {
  if (item.status !== 'active') {
    throw new EvidenceConflictError('Disposed evidence cannot be used or changed.', {
      evidenceId: item.evidenceId,
      status: item.status
    });
  }
}

function custodyEventHash(event) {
  return createHash('sha256').update(JSON.stringify({
    eventId: event.eventId,
    sequence: event.sequence,
    occurredAt: event.occurredAt,
    actor: event.actor,
    action: event.action,
    evidenceId: event.evidenceId,
    metadata: event.metadata,
    previousHash: event.previousHash
  })).digest('hex');
}

function indexAad(tenant) {
  return `${INDEX_FORMAT}:1:${tenant}`;
}

function contentAad(tenant, evidenceId, version) {
  return `${CONTENT_FORMAT}:1:${tenant}:${evidenceId}:${version}`;
}

function storeFailure(error, operation, evidenceId = null) {
  if (error instanceof EvidenceError) return error;
  return new EvidenceStoreError('The evidence operation could not be committed to durable storage.', {
    operation,
    evidenceId,
    cause: error?.code ?? 'unknown'
  }, error);
}

function evidenceIdentifier(value) {
  const id = String(value ?? '');
  if (!EVIDENCE_ID.test(id)) {
    throw new EvidenceValidationError('evidenceId must be a valid EVD identifier.', {
      field: 'evidenceId'
    });
  }
  return id;
}

function tenantIdentifier(value) {
  const id = String(value ?? '');
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{1,127}$/.test(id)) {
    throw new EvidenceValidationError('tenantId must be a safe identifier.', {
      field: 'tenantId'
    });
  }
  return id;
}

function actorIdentifier(value) {
  const actor = String(value ?? '').trim();
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._:@-]{0,191}$/.test(actor)) {
    throw new EvidenceValidationError('A valid evidence actor is required.', {
      field: 'actor'
    });
  }
  return actor;
}

function safeIdentifier(value, field) {
  const id = String(value ?? '').trim();
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{1,191}$/.test(id)) {
    throw new EvidenceValidationError(`${field} must be a safe identifier.`, { field });
  }
  return id;
}

function safeFilename(value) {
  const filename = String(value ?? '').trim();
  if (!filename
      || filename.length > 255
      || basename(filename) !== filename
      || /[\u0000-\u001f<>:"/\\|?*]/.test(filename)) {
    throw new EvidenceValidationError('filename must be a safe base filename.', {
      field: 'filename'
    });
  }
  return filename;
}

function safeMediaType(value) {
  const mediaType = String(value ?? 'application/octet-stream').trim().toLowerCase();
  if (!/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(mediaType)
      || mediaType.length > 127) {
    throw new EvidenceValidationError('mediaType must be a valid MIME type.', {
      field: 'mediaType'
    });
  }
  return mediaType;
}

function cleanText(value, field, minimum, maximum) {
  const text = String(value ?? '').trim().replace(/[<>]/g, '');
  if (text.length < minimum || text.length > maximum) {
    throw new EvidenceValidationError(
      `${field} must contain ${minimum} to ${maximum} characters.`,
      { field }
    );
  }
  return text;
}

function allowedValue(value, field, allowed) {
  const candidate = String(value ?? '');
  if (!allowed.includes(candidate)) {
    throw new EvidenceValidationError(`${field} is not supported.`, {
      field,
      allowed
    });
  }
  return candidate;
}

function validDate(value, field) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw new EvidenceValidationError(`${field} must be a valid date.`, { field });
  }
  return date;
}

function futureDate(value, field, now) {
  if (!value) return null;
  const date = validDate(value, field);
  if (date <= now) {
    throw new EvidenceValidationError(`${field} must be in the future.`, { field });
  }
  return date.toISOString();
}

function integer(value, field, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new EvidenceValidationError(
      `${field} must be an integer from ${minimum} to ${maximum}.`,
      { field }
    );
  }
  return parsed;
}

function booleanValue(value, field) {
  if (value === true || value === 'true') return true;
  if (value === false || value === 'false') return false;
  throw new TypeError(`${field} must be true or false.`);
}

function environmentValue(value) {
  const clean = typeof value === 'string' ? value.trim() : value;
  return clean === '' || clean === undefined || clean === null ? undefined : clean;
}
