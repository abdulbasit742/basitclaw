import { mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { createFileMutex, SecurityControlBusyError, SecurityControlUnavailableError } from './fileMutex.js';
import { createSecurityArchiveCodec } from './securityArchiveCodec.js';
import { createSecurityArchiveFilesystem } from './securityArchiveFilesystem.js';

const DAY_MS = 86_400_000;

export class SecurityArchiveError extends Error {
  constructor(message = 'The security-event archive is unavailable.', details = {}) {
    super(message);
    this.name = 'SecurityArchiveError';
    this.code = 'SECURITY_ARCHIVE_UNAVAILABLE';
    this.details = details;
  }
}

export class SecurityArchiveIntegrityError extends Error {
  constructor(message = 'The security-event archive failed integrity verification.', details = {}) {
    super(message);
    this.name = 'SecurityArchiveIntegrityError';
    this.code = 'SECURITY_ARCHIVE_INTEGRITY_FAILED';
    this.details = details;
  }
}

export function createSecurityEventArchive({
  directory,
  encryptionKey,
  keyId = 'security-archive-v1',
  required = false,
  retentionDays = 90,
  maxSegmentBytes = 10_000_000,
  now = () => new Date(),
  mutex = null,
  lockLeaseMs = 10_000,
  lockAcquireTimeoutMs = 2_000,
  lockRetryMs = 10
} = {}) {
  if (!String(directory ?? '').trim()) throw new TypeError('A security archive directory is required.');
  const root = resolve(String(directory));
  const safeRetentionDays = integer(retentionDays, 'retentionDays', 1, 3650);
  const safeMaxSegmentBytes = integer(maxSegmentBytes, 'maxSegmentBytes', 1024, 1_000_000_000);
  const codec = createSecurityArchiveCodec({ masterKey: encryptionKey, keyId });
  const files = createSecurityArchiveFilesystem(root);
  const lock = mutex ?? createFileMutex({
    directory: resolve(root, 'locks'),
    leaseMs: lockLeaseMs,
    acquireTimeoutMs: lockAcquireTimeoutMs,
    retryMs: lockRetryMs,
    now
  });
  let lastError = null;

  function append(event) {
    try {
      const result = lock.withLock('security-archive', () => appendLocked(event));
      lastError = null;
      return result;
    } catch (error) {
      lastError = error.message;
      throw wrapArchiveError(error);
    }
  }

  function appendLocked(event) {
    if (!event || typeof event !== 'object' || Array.isArray(event)) throw new TypeError('A security event object is required.');
    const current = now();
    recoverPruneLocked();
    const anchor = readAnchor();
    const head = recoverHeadLocked(anchor, readHead(anchor));
    const envelope = codec.seal(event, {
      sequence: head.sequence + 1,
      previousHash: head.hash,
      writtenAt: current.toISOString()
    });
    const segment = files.selectSegment(current, head.segment, safeMaxSegmentBytes);
    files.appendSegment(segment, `${JSON.stringify(envelope)}\n`);
    writeHead(envelope, segment);
    pruneLocked(current, segment);
    return manifest(envelope, segment);
  }

  function list({ limit = 100, afterSequence = 0, type = null, severity = null } = {}) {
    const safeLimit = integer(limit, 'limit', 1, 500);
    const safeAfter = integer(afterSequence, 'afterSequence', 0, Number.MAX_SAFE_INTEGER);
    try {
      return lock.withLock('security-archive', () => {
        recoverPruneLocked();
        const anchor = readAnchor();
        const head = recoverHeadLocked(anchor, readHead(anchor));
        const output = [];
        for (const { envelope, segment } of readAllEnvelopes()) {
          if (envelope.sequence <= safeAfter) continue;
          const payload = verifyAndOpen(envelope);
          const event = payload.event;
          if (type && event.type !== type) continue;
          if (severity && event.severity !== severity) continue;
          output.push({ ...event, archive: manifest(envelope, segment) });
          if (output.length >= safeLimit) break;
        }
        return {
          events: output,
          anchorSequence: anchor.sequence,
          headSequence: head.sequence,
          nextSequence: output.at(-1)?.archive?.sequence ?? safeAfter
        };
      });
    } catch (error) {
      if (error instanceof SecurityArchiveIntegrityError) throw error;
      throw wrapArchiveError(error);
    }
  }

  function verify() {
    try {
      return lock.withLock('security-archive', () => verifyLocked());
    } catch (error) {
      if (error instanceof SecurityArchiveIntegrityError) {
        return {
          valid: false,
          failedArchiveId: error.details?.archiveId ?? null,
          error: error.message
        };
      }
      throw wrapArchiveError(error);
    }
  }

  function verifyLocked({ recover = true } = {}) {
    if (recover) recoverPruneLocked();
    const anchor = readAnchor();
    const recordedHead = readHead(anchor);
    const head = recover ? recoverHeadLocked(anchor, recordedHead) : recordedHead;
    let expectedSequence = anchor.sequence + 1;
    let previousHash = anchor.hash;
    let retainedEvents = 0;
    for (const { envelope } of readAllEnvelopes()) {
      if (envelope.sequence !== expectedSequence || envelope.previousHash !== previousHash) {
        throw new SecurityArchiveIntegrityError('The security archive sequence or hash link is invalid.', {
          archiveId: envelope.archiveId
        });
      }
      verifyAndOpen(envelope);
      previousHash = envelope.hash;
      expectedSequence += 1;
      retainedEvents += 1;
    }
    if (head.sequence !== expectedSequence - 1 || head.hash !== previousHash) {
      throw new SecurityArchiveIntegrityError('The security archive head does not match retained segments.');
    }
    return {
      valid: true,
      anchorSequence: anchor.sequence,
      retainedEvents,
      headSequence: head.sequence,
      headHash: head.hash,
      failedArchiveId: null
    };
  }

  function health() {
    try {
      mkdirSync(files.segmentsDirectory, { recursive: true, mode: 0o700 });
      const snapshot = lock.withLock('security-archive', () => {
        const integrity = verifyLocked();
        const anchor = readAnchor();
        return {
          integrity,
          segments: files.segmentNames(),
          anchor,
          head: readHead(anchor)
        };
      });
      return {
        status: snapshot.integrity.valid && !lastError ? 'ready' : 'unavailable',
        enabled: true,
        required: Boolean(required),
        mode: 'shared-file-encrypted-hash-chain',
        durable: true,
        distributed: true,
        encrypted: true,
        directory: root,
        keyId: codec.keyId,
        retentionDays: safeRetentionDays,
        maxSegmentBytes: safeMaxSegmentBytes,
        retainedSegments: snapshot.segments.length,
        anchorSequence: snapshot.anchor.sequence,
        headSequence: snapshot.head.sequence,
        lastArchivedAt: snapshot.head.updatedAt ?? null,
        integrity: snapshot.integrity,
        mutex: lock.health(),
        error: lastError
      };
    } catch (error) {
      return {
        status: 'unavailable',
        enabled: true,
        required: Boolean(required),
        mode: 'shared-file-encrypted-hash-chain',
        durable: true,
        distributed: true,
        encrypted: true,
        directory: root,
        keyId: codec.keyId,
        error: error.message
      };
    }
  }

  function readAllEnvelopes() {
    try { return files.readAll(); } catch (error) {
      throw new SecurityArchiveIntegrityError('A security archive segment could not be decoded.', {
        archiveId: null,
        cause: error.message
      });
    }
  }

  function readAnchor() {
    let stored;
    try { stored = files.readJson(files.anchorPath); } catch {
      throw new SecurityArchiveIntegrityError('The security archive retention anchor could not be decoded.');
    }
    if (!stored) return defaultAnchor();
    const { signature, ...anchor } = stored;
    if (!validAnchor(anchor) || !codec.verifySigned(anchor, signature, codec.signAnchor)) {
      throw new SecurityArchiveIntegrityError('The security archive retention anchor signature is invalid.');
    }
    return anchor;
  }

  function readHead(anchor) {
    let head;
    try { head = files.readJson(files.headPath); } catch {
      throw new SecurityArchiveIntegrityError('The security archive head could not be decoded.');
    }
    if (!head) return { version: 1, sequence: anchor.sequence, hash: anchor.hash, segment: null, updatedAt: null };
    if (head.version !== 1 || !Number.isInteger(head.sequence) || head.sequence < anchor.sequence
        || (head.hash !== null && typeof head.hash !== 'string')) {
      throw new SecurityArchiveIntegrityError('The security archive head failed validation.');
    }
    return head;
  }

  function recoverHeadLocked(anchor, head) {
    const segments = files.segmentNames();
    if (segments.length === 0) {
      if (head.sequence !== anchor.sequence || head.hash !== anchor.hash) {
        throw new SecurityArchiveIntegrityError('The security archive head exists without retained segments.');
      }
      return head;
    }

    if (head.segment && segments.includes(head.segment) && segments.at(-1) === head.segment) {
      const tail = readSegment(head.segment).at(-1);
      if (tail?.sequence === head.sequence && tail.hash === head.hash) {
        verifyAndOpen(tail);
        return head;
      }
      if (tail?.sequence === head.sequence + 1 && tail.previousHash === head.hash) {
        verifyAndOpen(tail);
        const recovered = headFromEnvelope(tail, head.segment);
        files.writeJson(files.headPath, recovered);
        return recovered;
      }
    }

    let expectedSequence = anchor.sequence + 1;
    let previousHash = anchor.hash;
    let tail = null;
    let tailSegment = null;
    for (const item of readAllEnvelopes()) {
      if (item.envelope.sequence !== expectedSequence || item.envelope.previousHash !== previousHash) {
        throw new SecurityArchiveIntegrityError('The security archive cannot recover its head from retained segments.', {
          archiveId: item.envelope.archiveId
        });
      }
      verifyAndOpen(item.envelope);
      previousHash = item.envelope.hash;
      expectedSequence += 1;
      tail = item.envelope;
      tailSegment = item.segment;
    }
    if (!tail || tail.sequence < head.sequence) {
      throw new SecurityArchiveIntegrityError('The security archive retained segments are behind the recorded head.');
    }
    if (tail.sequence === head.sequence && tail.hash !== head.hash) {
      throw new SecurityArchiveIntegrityError('The security archive head hash conflicts with retained segments.', {
        archiveId: tail.archiveId
      });
    }
    const recovered = headFromEnvelope(tail, tailSegment);
    if (recovered.sequence !== head.sequence || recovered.hash !== head.hash || recovered.segment !== head.segment) {
      files.writeJson(files.headPath, recovered);
    }
    return recovered;
  }

  function pruneLocked(current, activeSegment) {
    const cutoffDate = new Date(current.getTime() - safeRetentionDays * DAY_MS).toISOString().slice(0, 10);
    const deletable = files.segmentNames().filter((name) => name !== activeSegment && segmentDate(name) < cutoffDate);
    if (deletable.length === 0) return;

    verifyLocked({ recover: false });
    let anchor = readAnchor();
    for (const name of deletable) {
      const envelopes = readSegment(name);
      if (envelopes.length > 0) {
        const last = envelopes.at(-1);
        verifyAndOpen(last);
        anchor = { version: 1, sequence: last.sequence, hash: last.hash, prunedAt: current.toISOString() };
      }
    }
    const plan = { version: 1, createdAt: current.toISOString(), anchor, segments: deletable };
    files.writeJson(files.prunePlanPath, { ...plan, signature: codec.signPrunePlan(plan) });
    for (const name of deletable) {
      const original = files.resolveSegment(name);
      const pruning = files.resolveSegment(`${name}.pruning`);
      if (files.exists(original)) files.rename(original, pruning);
    }
    files.sync();
    files.writeJson(files.anchorPath, { ...anchor, signature: codec.signAnchor(anchor) });
    for (const name of deletable) files.remove(files.resolveSegment(`${name}.pruning`));
    files.remove(files.prunePlanPath);
    files.sync();
  }

  function recoverPruneLocked() {
    if (!files.exists(files.prunePlanPath)) return;
    let stored;
    try { stored = files.readJson(files.prunePlanPath); } catch {
      throw new SecurityArchiveIntegrityError('The security archive prune journal could not be decoded.');
    }
    const { signature, ...plan } = stored ?? {};
    if (!validPrunePlan(plan) || !codec.verifySigned(plan, signature, codec.signPrunePlan)) {
      throw new SecurityArchiveIntegrityError('The security archive prune journal signature is invalid.');
    }
    const currentAnchor = readAnchor();
    const committed = currentAnchor.sequence === plan.anchor.sequence && currentAnchor.hash === plan.anchor.hash;
    for (const name of plan.segments) {
      const original = files.resolveSegment(name);
      const pruning = files.resolveSegment(`${name}.pruning`);
      if (committed) {
        files.remove(original);
        files.remove(pruning);
      } else if (files.exists(pruning)) {
        if (files.exists(original)) files.remove(pruning);
        else files.rename(pruning, original);
      }
    }
    files.remove(files.prunePlanPath);
    files.sync();
  }

  function readSegment(name) {
    try { return files.readSegment(name); } catch (error) {
      throw new SecurityArchiveIntegrityError('A security archive segment contains invalid JSON.', {
        archiveId: null,
        segment: name,
        cause: error.message
      });
    }
  }

  function verifyAndOpen(envelope) {
    try {
      codec.verifyEnvelope(envelope);
      return codec.open(envelope);
    } catch (error) {
      throw new SecurityArchiveIntegrityError(error.message, { archiveId: error.archiveId ?? envelope?.archiveId ?? null });
    }
  }

  function writeHead(envelope, segment) {
    files.writeJson(files.headPath, headFromEnvelope(envelope, segment));
  }

  return {
    append,
    list,
    verify,
    health,
    required: Boolean(required),
    enabled: true,
    directory: root
  };
}

export function createDisabledSecurityEventArchive({ required = false } = {}) {
  if (required) throw new TypeError('A required security archive cannot be disabled.');
  const health = () => ({
    status: 'disabled', enabled: false, required: false, mode: 'disabled',
    durable: false, distributed: false, encrypted: false
  });
  return {
    enabled: false,
    required: false,
    append: () => null,
    list: ({ afterSequence = 0 } = {}) => ({ events: [], anchorSequence: 0, headSequence: 0, nextSequence: afterSequence }),
    verify: () => ({ valid: true, disabled: true, anchorSequence: 0, retainedEvents: 0, headSequence: 0, headHash: null }),
    health
  };
}

export function createSecurityEventArchiveFromEnvironment(env = process.env) {
  const mode = String(env.WORKFORCE_AUDIT_SECURITY_ARCHIVE_MODE ?? 'disabled');
  const required = String(env.WORKFORCE_AUDIT_SECURITY_ARCHIVE_REQUIRED ?? 'false') === 'true';
  if (!['disabled', 'shared-file'].includes(mode)) {
    throw new TypeError('WORKFORCE_AUDIT_SECURITY_ARCHIVE_MODE must be disabled or shared-file.');
  }
  if (mode === 'disabled') return createDisabledSecurityEventArchive({ required });
  return createSecurityEventArchive({
    directory: env.WORKFORCE_AUDIT_SECURITY_ARCHIVE_DIR ?? '.runtime-data/workforce-audit-security-archive',
    encryptionKey: env.WORKFORCE_AUDIT_SECURITY_ARCHIVE_KEY,
    keyId: env.WORKFORCE_AUDIT_SECURITY_ARCHIVE_KEY_ID ?? 'security-archive-v1',
    required,
    retentionDays: Number(env.WORKFORCE_AUDIT_SECURITY_ARCHIVE_RETENTION_DAYS ?? 90),
    maxSegmentBytes: Number(env.WORKFORCE_AUDIT_SECURITY_ARCHIVE_MAX_SEGMENT_BYTES ?? 10_000_000),
    lockLeaseMs: Number(env.WORKFORCE_AUDIT_SECURITY_CONTROL_LOCK_MS ?? 10_000),
    lockAcquireTimeoutMs: Number(env.WORKFORCE_AUDIT_SECURITY_CONTROL_ACQUIRE_TIMEOUT_MS ?? 2_000),
    lockRetryMs: Number(env.WORKFORCE_AUDIT_SECURITY_CONTROL_RETRY_MS ?? 10)
  });
}

function defaultAnchor() {
  return { version: 1, sequence: 0, hash: null, prunedAt: null };
}

function validAnchor(anchor) {
  return anchor?.version === 1 && Number.isInteger(anchor.sequence) && anchor.sequence >= 0
    && (anchor.hash === null || typeof anchor.hash === 'string');
}

function validPrunePlan(plan) {
  return plan?.version === 1 && validAnchor(plan.anchor) && Array.isArray(plan.segments)
    && plan.segments.every((name) => /^segment-\d{4}-\d{2}-\d{2}-\d{6}\.ndjson$/.test(name));
}

function headFromEnvelope(envelope, segment) {
  return {
    version: 1,
    sequence: envelope.sequence,
    hash: envelope.hash,
    segment,
    updatedAt: envelope.writtenAt
  };
}

function manifest(envelope, segment) {
  return {
    archiveId: envelope.archiveId,
    sequence: envelope.sequence,
    writtenAt: envelope.writtenAt,
    sourceEventId: envelope.sourceEventId,
    segment,
    hash: envelope.hash,
    previousHash: envelope.previousHash,
    keyId: envelope.keyId
  };
}

function segmentDate(name) {
  return name.slice(8, 18);
}

function wrapArchiveError(error) {
  if (error instanceof SecurityArchiveError || error instanceof SecurityArchiveIntegrityError) return error;
  if (error instanceof SecurityControlBusyError || error instanceof SecurityControlUnavailableError) {
    return new SecurityArchiveError('The security archive lock could not be used safely.', { cause: error.code });
  }
  return new SecurityArchiveError('The security archive filesystem operation failed.', {
    cause: error?.code ?? error?.message ?? 'unknown'
  });
}

function integer(value, field, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new TypeError(`${field} must be an integer from ${minimum} to ${maximum}.`);
  }
  return parsed;
}
