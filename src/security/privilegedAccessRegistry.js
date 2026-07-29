import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from 'node:crypto';
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { permissionsForRole } from './accessControl.js';
import { createFileMutex } from './fileMutex.js';

const FORMAT = 'basitclaw-privileged-access';
const VERSION = 1;
const MODES = new Set(['disabled', 'observe', 'enforce']);
const TERMINAL = new Set(['denied', 'cancelled', 'revoked', 'expired']);
const MANAGEMENT = new Set(['privileged:request', 'privileged:read', 'privileged:approve', 'privileged:revoke', 'privileged:break_glass']);
const ROLE_PERMISSIONS = new Set(['audit_viewer', 'auditor', 'audit_manager', 'compliance_admin'].flatMap(permissionsForRole));

export class PrivilegedAccessError extends Error {
  constructor(message = 'Privileged access is not authorised.', code = 'PRIVILEGED_ACCESS_DENIED', details = {}, statusCode = 403) {
    super(message);
    this.name = 'PrivilegedAccessError';
    this.code = code;
    this.details = details;
    this.statusCode = statusCode;
  }
}

export class PrivilegedAccessConflictError extends Error {
  constructor(message = 'The privileged-access request changed before this operation was committed.', details = {}) {
    super(message);
    this.name = 'PrivilegedAccessConflictError';
    this.code = 'PRIVILEGED_ACCESS_CONFLICT';
    this.details = details;
    this.statusCode = 409;
  }
}

export class PrivilegedAccessStoreError extends Error {
  constructor(message = 'The privileged-access store is unavailable.', details = {}) {
    super(message);
    this.name = 'PrivilegedAccessStoreError';
    this.code = 'PRIVILEGED_ACCESS_STORE_UNAVAILABLE';
    this.details = details;
    this.statusCode = 503;
  }
}

export function createPrivilegedAccessRegistry(options = {}) {
  const mode = String(options.mode ?? 'disabled');
  if (!MODES.has(mode)) throw new TypeError('Privileged-access mode must be disabled, observe, or enforce.');
  if (mode === 'disabled') return createDisabledPrivilegedAccessRegistry();

  const root = resolve(String(options.directory ?? '.runtime-data/workforce-audit-privileged-access'));
  const keyring = keyringOf(options.keys, options.primaryKeyId);
  const protectedPermissions = protectedSet(options.protectedPermissions ?? ['backup:restore', 'resilience:run', 'security:read']);
  const approvalsRequired = integer(options.approvalsRequired ?? 2, 'approvalsRequired', 2, 5);
  const approvalWindowMs = integer(options.approvalWindowMinutes ?? 1440, 'approvalWindowMinutes', 5, 10080) * 60000;
  const maxDuration = integer(options.maxDurationMinutes ?? 120, 'maxDurationMinutes', 5, 1440);
  const breakGlassEnabled = Boolean(options.breakGlassEnabled);
  const breakGlassMax = integer(options.breakGlassMaxDurationMinutes ?? 15, 'breakGlassMaxDurationMinutes', 5, 60);
  const reviewMs = integer(options.breakGlassReviewMinutes ?? 1440, 'breakGlassReviewMinutes', 60, 10080) * 60000;
  const requiredAmr = stringList(options.requiredAmr ?? ['mfa'], 'requiredAmr', 0, 20);
  const requiredAcr = stringList(options.requiredAcr ?? [], 'requiredAcr', 0, 20);
  const allowApiKey = Boolean(options.allowApiKey);
  const eventRetention = integer(options.eventRetention ?? 10000, 'eventRetention', 100, 100000);
  const requestRetentionMs = integer(options.requestRetentionDays ?? 365, 'requestRetentionDays', 30, 3650) * 86400000;
  const now = options.now ?? (() => new Date());
  const path = resolve(root, 'privileged-access.enc.json');
  const mutex = options.mutex ?? createFileMutex({ directory: resolve(root, '.locks') });
  mkdirSync(root, { recursive: true, mode: 0o700 });

  function authorise(principal, permission) {
    if (!protectedPermissions.has(permission)) return principal;
    try {
      eligible(principal, 'use');
      const current = now();
      const grant = Object.values(read().requests)
        .map((item) => effective(item, current))
        .find((item) => item.status === 'active'
          && item.subject === principal.subject
          && item.tenantId === principal.tenantId
          && item.permissions.includes(permission));
      if (!grant) {
        throw new PrivilegedAccessError(
          'An active just-in-time grant is required for this operation.',
          'PRIVILEGED_ACCESS_REQUIRED',
          { permission }
        );
      }
      return Object.freeze({
        ...principal,
        privilegedAccess: Object.freeze({
          status: 'active',
          requestId: grant.id,
          permission,
          permissions: [...grant.permissions],
          expiresAt: grant.expiresAt,
          breakGlass: grant.breakGlass
        })
      });
    } catch (error) {
      if (mode === 'observe' && error instanceof PrivilegedAccessError) return observed(principal, permission, error.code);
      throw error;
    }
  }

  function requestAccess(principal, input = {}, context = {}) {
    eligible(principal, 'request', false);
    manage(principal, 'privileged:request');
    const permissions = requested(input.permissions, protectedPermissions, principal.permissions);
    const durationMinutes = integer(input.durationMinutes, 'durationMinutes', 5, maxDuration);
    const reason = text(input.reason, 'reason', 20, 1000);
    const ticketRef = text(input.ticketRef, 'ticketRef', 3, 128);
    return mutate((snapshot, timestamp) => {
      const current = new Date(timestamp);
      const overlap = Object.values(snapshot.requests)
        .map((item) => effective(item, current))
        .find((item) => ['pending', 'active'].includes(item.status)
          && item.subject === principal.subject
          && item.tenantId === principal.tenantId
          && item.permissions.some((value) => permissions.includes(value)));
      if (overlap) {
        throw new PrivilegedAccessConflictError('An overlapping privileged-access request already exists.', { requestId: overlap.id });
      }
      const id = `PAM-${randomUUID()}`;
      const item = {
        id,
        subject: subject(principal.subject),
        tenantId: identifier(principal.tenantId, 'tenantId'),
        requesterRole: role(principal.role),
        permissions,
        reason,
        ticketRef,
        durationMinutes,
        status: 'pending',
        breakGlass: false,
        approvalsRequired,
        approvals: [],
        denial: null,
        requestedAt: timestamp,
        approvalExpiresAt: new Date(current.getTime() + approvalWindowMs).toISOString(),
        activatedAt: null,
        expiresAt: null,
        closedAt: null,
        postReviewBy: null,
        postReview: null,
        version: 1
      };
      snapshot.requests[id] = item;
      event(snapshot, timestamp, 'privileged_access.requested', actor(context.actor ?? principal.subject), item, { reason, ticketRef });
      return structuredClone(item);
    });
  }

  function approve(id, principal, input = {}, context = {}) {
    manage(principal, 'privileged:approve');
    eligible(principal, 'approve');
    const comment = text(input.comment, 'comment', 10, 1000);
    return mutate((snapshot, timestamp) => {
      const item = request(snapshot, id);
      version(item, input.expectedVersion);
      tenant(item, principal);
      if (effective(item, new Date(timestamp)).status !== 'pending') throw state(item, 'pending');
      if (item.subject === principal.subject) {
        throw new PrivilegedAccessError('Requesters cannot approve their own privileged access.', 'PRIVILEGED_ACCESS_SELF_APPROVAL_DENIED');
      }
      if (item.approvals.some((value) => value.subject === principal.subject)) {
        throw new PrivilegedAccessConflictError('This approver has already approved the request.');
      }
      item.approvals.push({ subject: subject(principal.subject), role: role(principal.role), approvedAt: timestamp, comment });
      item.version += 1;
      event(snapshot, timestamp, 'privileged_access.approved', actor(context.actor ?? principal.subject), item, {
        approver: principal.subject,
        approvalCount: item.approvals.length
      });
      if (item.approvals.length >= item.approvalsRequired) {
        item.status = 'active';
        item.activatedAt = timestamp;
        item.expiresAt = new Date(new Date(timestamp).getTime() + item.durationMinutes * 60000).toISOString();
        event(snapshot, timestamp, 'privileged_access.activated', 'system:privileged-access', item, { expiresAt: item.expiresAt });
      }
      return structuredClone(item);
    });
  }

  function deny(id, principal, input = {}, context = {}) {
    return closePending(id, principal, input, context, 'denied');
  }

  function cancel(id, principal, input = {}, context = {}) {
    manage(principal, 'privileged:request');
    const reason = text(input.reason, 'reason', 10, 1000);
    return mutate((snapshot, timestamp) => {
      const item = request(snapshot, id);
      version(item, input.expectedVersion);
      if (item.subject !== principal.subject || item.tenantId !== principal.tenantId) {
        throw new PrivilegedAccessError('Only the requester can cancel this request.', 'PRIVILEGED_ACCESS_CANCEL_DENIED');
      }
      const currentStatus = effective(item, new Date(timestamp)).status;
      if (!['pending', 'active'].includes(currentStatus)) throw state(item, 'pending or active');
      item.status = currentStatus === 'active' ? 'revoked' : 'cancelled';
      item.closedAt = timestamp;
      item.version += 1;
      event(snapshot, timestamp, 'privileged_access.cancelled', actor(context.actor ?? principal.subject), item, { reason });
      return structuredClone(item);
    });
  }

  function revoke(id, principal, input = {}, context = {}) {
    manage(principal, 'privileged:revoke');
    eligible(principal, 'revoke');
    const reason = text(input.reason, 'reason', 10, 1000);
    return mutate((snapshot, timestamp) => {
      const item = request(snapshot, id);
      version(item, input.expectedVersion);
      tenant(item, principal);
      if (effective(item, new Date(timestamp)).status !== 'active') throw state(item, 'active');
      item.status = 'revoked';
      item.closedAt = timestamp;
      item.version += 1;
      event(snapshot, timestamp, 'privileged_access.revoked', actor(context.actor ?? principal.subject), item, { reason });
      return structuredClone(item);
    });
  }

  function activateBreakGlass(principal, input = {}, context = {}) {
    if (!breakGlassEnabled) throw new PrivilegedAccessError('Emergency privileged access is disabled.', 'BREAK_GLASS_DISABLED');
    manage(principal, 'privileged:break_glass');
    eligible(principal, 'break_glass', true);
    if (String(input.confirmation ?? '') !== 'BREAK GLASS') {
      throw new PrivilegedAccessError('Exact break-glass confirmation is required.', 'BREAK_GLASS_CONFIRMATION_REQUIRED', {}, 400);
    }
    const permissions = requested(input.permissions, protectedPermissions, principal.permissions);
    const durationMinutes = integer(input.durationMinutes, 'durationMinutes', 5, breakGlassMax);
    const reason = text(input.reason, 'reason', 30, 1000);
    const incidentRef = text(input.incidentRef, 'incidentRef', 3, 128);
    return mutate((snapshot, timestamp) => {
      const id = `PAM-${randomUUID()}`;
      const item = {
        id,
        subject: subject(principal.subject),
        tenantId: identifier(principal.tenantId, 'tenantId'),
        requesterRole: role(principal.role),
        permissions,
        reason,
        ticketRef: incidentRef,
        durationMinutes,
        status: 'active',
        breakGlass: true,
        approvalsRequired: 0,
        approvals: [],
        denial: null,
        requestedAt: timestamp,
        approvalExpiresAt: null,
        activatedAt: timestamp,
        expiresAt: new Date(new Date(timestamp).getTime() + durationMinutes * 60000).toISOString(),
        closedAt: null,
        postReviewBy: new Date(new Date(timestamp).getTime() + reviewMs).toISOString(),
        postReview: null,
        version: 1
      };
      snapshot.requests[id] = item;
      event(snapshot, timestamp, 'privileged_access.break_glass_activated', actor(context.actor ?? principal.subject), item, {
        reason,
        incidentRef,
        expiresAt: item.expiresAt,
        postReviewBy: item.postReviewBy
      });
      return structuredClone(item);
    });
  }

  function completePostReview(id, principal, input = {}, context = {}) {
    manage(principal, 'privileged:approve');
    eligible(principal, 'review');
    const outcome = String(input.outcome ?? '');
    if (!['accepted', 'concern'].includes(outcome)) throw new TypeError('outcome must be accepted or concern.');
    const reason = text(input.reason, 'reason', 20, 1000);
    return mutate((snapshot, timestamp) => {
      const item = request(snapshot, id);
      version(item, input.expectedVersion);
      tenant(item, principal);
      if (!item.breakGlass) {
        throw new PrivilegedAccessError('Post-use review applies only to break-glass grants.', 'BREAK_GLASS_REVIEW_NOT_APPLICABLE', {}, 400);
      }
      if (item.subject === principal.subject) {
        throw new PrivilegedAccessError('Break-glass users cannot review their own emergency access.', 'BREAK_GLASS_SELF_REVIEW_DENIED');
      }
      if (item.postReview) throw new PrivilegedAccessConflictError('The break-glass grant has already been reviewed.');
      item.postReview = { reviewer: subject(principal.subject), reviewedAt: timestamp, outcome, reason };
      item.version += 1;
      event(snapshot, timestamp, 'privileged_access.break_glass_reviewed', actor(context.actor ?? principal.subject), item, { outcome, reason });
      return structuredClone(item);
    });
  }

  function closePending(id, principal, input, context, closeStatus) {
    manage(principal, 'privileged:approve');
    eligible(principal, 'deny');
    const reason = text(input.reason, 'reason', 10, 1000);
    return mutate((snapshot, timestamp) => {
      const item = request(snapshot, id);
      version(item, input.expectedVersion);
      tenant(item, principal);
      if (effective(item, new Date(timestamp)).status !== 'pending') throw state(item, 'pending');
      if (item.subject === principal.subject) {
        throw new PrivilegedAccessError('Requesters cannot review their own request.', 'PRIVILEGED_ACCESS_SELF_REVIEW_DENIED');
      }
      item.status = closeStatus;
      item.denial = { subject: subject(principal.subject), deniedAt: timestamp, reason };
      item.closedAt = timestamp;
      item.version += 1;
      event(snapshot, timestamp, `privileged_access.${closeStatus}`, actor(context.actor ?? principal.subject), item, { reason });
      return structuredClone(item);
    });
  }

  function get(id) {
    return structuredClone(effective(request(read(), id), now()));
  }

  function list(filters = {}) {
    const limit = integer(filters.limit ?? 100, 'limit', 1, 500);
    const current = now();
    let items = Object.values(read().requests).map((item) => effective(item, current));
    if (filters.tenantId) items = items.filter((item) => item.tenantId === identifier(filters.tenantId, 'tenantId'));
    if (filters.subject) items = items.filter((item) => item.subject === subject(filters.subject));
    if (filters.status) items = items.filter((item) => item.status === String(filters.status));
    return structuredClone(items.sort((a, b) => b.requestedAt.localeCompare(a.requestedAt)).slice(0, limit));
  }

  function listEvents({ limit = 100 } = {}) {
    return structuredClone(read().events.slice(-integer(limit, 'limit', 1, 1000)).reverse());
  }

  function status() {
    const snapshot = read();
    const current = now();
    const items = Object.values(snapshot.requests).map((item) => effective(item, current));
    const active = items.filter((item) => item.status === 'active');
    const overdue = items.filter((item) => item.breakGlass && item.postReviewBy && !item.postReview && new Date(item.postReviewBy) <= current);
    return {
      status: overdue.length ? 'attention' : 'ready',
      generatedAt: current.toISOString(),
      mode,
      protectedPermissionCount: protectedPermissions.size,
      approvalsRequired,
      active: active.length,
      pending: items.filter((item) => item.status === 'pending').length,
      breakGlassActive: active.filter((item) => item.breakGlass).length,
      overduePostReviews: overdue.length,
      total: items.length,
      revision: snapshot.revision,
      eventSequence: snapshot.eventSequence,
      integrity: verifyEvents(snapshot)
    };
  }

  function health() {
    try {
      const value = status();
      return {
        ...value,
        status: 'ready',
        reviewStatus: value.status,
        enabled: true,
        required: mode === 'enforce',
        encrypted: true,
        durable: true,
        distributed: true,
        allowApiKey,
        breakGlassEnabled,
        configuredKeyCount: keyring.keys.size,
        primaryKeyId: keyring.primaryKeyId,
        requiredAmrCount: requiredAmr.length,
        requiredAcrCount: requiredAcr.length
      };
    } catch (error) {
      return {
        status: 'unavailable', enabled: true, required: mode === 'enforce', mode,
        encrypted: true, durable: true, distributed: true, error: error.message
      };
    }
  }

  function verify() { return verifyEvents(read()); }
  function tenantIds() { return [...new Set(Object.values(read().requests).map((item) => item.tenantId))]; }

  function mutate(operation) {
    try {
      return mutex.withLock('privileged-access', () => {
        const snapshot = readUnlocked();
        const timestamp = now().toISOString();
        expire(snapshot, timestamp);
        prune(snapshot, new Date(timestamp));
        const result = operation(snapshot, timestamp);
        snapshot.updatedAt = timestamp;
        snapshot.revision += 1;
        trim(snapshot, timestamp);
        write(snapshot);
        return result;
      });
    } catch (error) {
      if (error instanceof PrivilegedAccessError || error instanceof PrivilegedAccessConflictError) throw error;
      throw storeError(error);
    }
  }

  function read() {
    try { return mutex.withLock('privileged-access', readUnlocked); }
    catch (error) { throw storeError(error); }
  }

  function readUnlocked() {
    if (!existsSync(path)) return empty(now());
    try { return decrypt(JSON.parse(readFileSync(path, 'utf8')), keyring); }
    catch (error) { throw storeError(error); }
  }

  function write(snapshot) {
    atomicWrite(path, `${JSON.stringify(encrypt(snapshot, keyring, now()))}\n`);
  }

  function eligible(principal, purpose, forceOidc = false) {
    if (!principal?.subject || !principal?.tenantId || !principal?.role) {
      throw new PrivilegedAccessError('A complete authenticated principal is required.', 'PRIVILEGED_PRINCIPAL_INVALID');
    }
    if ((forceOidc || !allowApiKey) && principal.authMethod !== 'oidc') {
      throw new PrivilegedAccessError('OIDC authentication is required for privileged access.', 'PRIVILEGED_ACCESS_OIDC_REQUIRED', { purpose });
    }
    if (principal.authMethod === 'oidc') {
      const methods = new Set(principal.authenticationContext?.amr ?? []);
      for (const requiredMethod of requiredAmr) {
        if (!methods.has(requiredMethod)) {
          throw new PrivilegedAccessError('The required step-up authentication method was not satisfied.', 'PRIVILEGED_ACCESS_AMR_REQUIRED', { required: requiredMethod, purpose });
        }
      }
      if (requiredAcr.length && !requiredAcr.includes(String(principal.authenticationContext?.acr ?? ''))) {
        throw new PrivilegedAccessError('The required step-up authentication context was not satisfied.', 'PRIVILEGED_ACCESS_ACR_REQUIRED', { purpose });
      }
    }
  }

  function expire(snapshot, timestamp) {
    for (const item of Object.values(snapshot.requests)) {
      const next = effective(item, new Date(timestamp));
      if (next.status === item.status) continue;
      item.status = next.status;
      item.closedAt = timestamp;
      item.version += 1;
      event(snapshot, timestamp, item.breakGlass ? 'privileged_access.break_glass_expired' : 'privileged_access.expired', 'system:privileged-access', item);
    }
  }

  function prune(snapshot, current) {
    const cutoff = current.getTime() - requestRetentionMs;
    for (const [id, item] of Object.entries(snapshot.requests)) {
      const value = effective(item, current);
      const closedAt = value.closedAt ?? value.expiresAt ?? value.approvalExpiresAt;
      if (TERMINAL.has(value.status) && closedAt && new Date(closedAt).getTime() <= cutoff && (!value.breakGlass || value.postReview)) {
        delete snapshot.requests[id];
      }
    }
  }

  function trim(snapshot, timestamp) {
    if (snapshot.events.length <= eventRetention) return;
    const removed = snapshot.events.splice(0, snapshot.events.length - eventRetention);
    const last = removed.at(-1);
    snapshot.anchor = { sequence: last.sequence, hash: last.hash, prunedAt: timestamp };
  }

  return {
    mode,
    directory: root,
    protectedPermissions: [...protectedPermissions],
    authorise,
    requestAccess,
    approve,
    deny,
    cancel,
    revoke,
    activateBreakGlass,
    completePostReview,
    get,
    list,
    listEvents,
    status,
    health,
    verify,
    tenantIds
  };
}

export function createPrivilegedAccessRegistryFromEnvironment(env = process.env, options = {}) {
  const mode = String(env.WORKFORCE_AUDIT_PRIVILEGED_ACCESS_MODE ?? 'disabled');
  if (mode === 'disabled') return createPrivilegedAccessRegistry({ mode });
  if (env.NODE_ENV === 'production' && mode !== 'enforce') {
    throw new TypeError('Production privileged access must use enforce mode when enabled.');
  }
  const allowApiKey = bool(env.WORKFORCE_AUDIT_PRIVILEGED_ACCESS_ALLOW_API_KEY ?? false, 'WORKFORCE_AUDIT_PRIVILEGED_ACCESS_ALLOW_API_KEY');
  if (env.NODE_ENV === 'production' && mode === 'enforce'
      && String(env.WORKFORCE_AUDIT_AUTH_MODE ?? 'api-key') === 'api-key' && !allowApiKey) {
    throw new TypeError('Enforced privileged access requires OIDC or hybrid authentication unless API-key use is explicitly enabled.');
  }
  const breakGlassEnabled = bool(env.WORKFORCE_AUDIT_BREAK_GLASS_ENABLED ?? false, 'WORKFORCE_AUDIT_BREAK_GLASS_ENABLED');
  const requiredAmr = csv(env.WORKFORCE_AUDIT_PRIVILEGED_ACCESS_REQUIRED_AMR ?? 'mfa');
  if (env.NODE_ENV === 'production' && breakGlassEnabled && requiredAmr.length === 0) {
    throw new TypeError('Production break-glass access requires at least one AMR assurance value.');
  }
  return createPrivilegedAccessRegistry({
    mode,
    directory: env.WORKFORCE_AUDIT_PRIVILEGED_ACCESS_DIR,
    keys: json(env.WORKFORCE_AUDIT_PRIVILEGED_ACCESS_KEYS, 'WORKFORCE_AUDIT_PRIVILEGED_ACCESS_KEYS'),
    primaryKeyId: required(env.WORKFORCE_AUDIT_PRIVILEGED_ACCESS_PRIMARY_KEY_ID, 'WORKFORCE_AUDIT_PRIVILEGED_ACCESS_PRIMARY_KEY_ID'),
    protectedPermissions: csv(env.WORKFORCE_AUDIT_PRIVILEGED_ACCESS_PROTECTED_PERMISSIONS ?? 'backup:restore,resilience:run,security:read'),
    approvalsRequired: Number(env.WORKFORCE_AUDIT_PRIVILEGED_ACCESS_APPROVALS_REQUIRED ?? 2),
    approvalWindowMinutes: Number(env.WORKFORCE_AUDIT_PRIVILEGED_ACCESS_APPROVAL_WINDOW_MINUTES ?? 1440),
    maxDurationMinutes: Number(env.WORKFORCE_AUDIT_PRIVILEGED_ACCESS_MAX_DURATION_MINUTES ?? 120),
    breakGlassEnabled,
    breakGlassMaxDurationMinutes: Number(env.WORKFORCE_AUDIT_BREAK_GLASS_MAX_DURATION_MINUTES ?? 15),
    breakGlassReviewMinutes: Number(env.WORKFORCE_AUDIT_BREAK_GLASS_REVIEW_MINUTES ?? 1440),
    requiredAmr,
    requiredAcr: csv(env.WORKFORCE_AUDIT_PRIVILEGED_ACCESS_REQUIRED_ACR),
    allowApiKey,
    eventRetention: Number(env.WORKFORCE_AUDIT_PRIVILEGED_ACCESS_EVENT_RETENTION ?? 10000),
    requestRetentionDays: Number(env.WORKFORCE_AUDIT_PRIVILEGED_ACCESS_RETENTION_DAYS ?? 365),
    ...options
  });
}

export function createDisabledPrivilegedAccessRegistry() {
  const disabled = () => {
    throw new PrivilegedAccessError('The privileged-access lifecycle is disabled.', 'PRIVILEGED_ACCESS_DISABLED', {}, 404);
  };
  return {
    mode: 'disabled',
    protectedPermissions: [],
    authorise: (principal) => principal,
    requestAccess: disabled,
    approve: disabled,
    deny: disabled,
    cancel: disabled,
    revoke: disabled,
    activateBreakGlass: disabled,
    completePostReview: disabled,
    get: disabled,
    list: () => [],
    listEvents: () => [],
    status: () => ({ status: 'disabled', mode: 'disabled', active: 0, pending: 0, total: 0, overduePostReviews: 0 }),
    health: () => ({ status: 'disabled', enabled: false, required: false, mode: 'disabled' }),
    verify: () => ({ valid: true, disabled: true, retainedEvents: 0 }),
    tenantIds: () => []
  };
}

function empty(now) {
  return {
    format: FORMAT,
    version: VERSION,
    revision: 0,
    eventSequence: 0,
    updatedAt: now.toISOString(),
    anchor: { sequence: 0, hash: null, prunedAt: null },
    requests: {},
    events: []
  };
}

function effective(item, current) {
  const value = structuredClone(item);
  if (value.status === 'pending' && value.approvalExpiresAt && new Date(value.approvalExpiresAt) <= current) value.status = 'expired';
  if (value.status === 'active' && value.expiresAt && new Date(value.expiresAt) <= current) value.status = 'expired';
  return value;
}

function event(snapshot, timestamp, action, performedBy, item, details = {}) {
  const previousHash = snapshot.events.at(-1)?.hash ?? snapshot.anchor.hash;
  const value = {
    id: `PAE-${randomUUID()}`,
    sequence: snapshot.eventSequence + 1,
    occurredAt: timestamp,
    actor: performedBy,
    action,
    requestId: item.id,
    subject: item.subject,
    tenantId: item.tenantId,
    permissions: item.permissions,
    breakGlass: item.breakGlass,
    ...details,
    previousHash
  };
  value.hash = digest(value);
  snapshot.eventSequence = value.sequence;
  snapshot.events.push(value);
}

function verifyEvents(snapshot) {
  let sequence = snapshot.anchor.sequence;
  let previousHash = snapshot.anchor.hash;
  for (const item of snapshot.events) {
    sequence += 1;
    const { hash, ...unsigned } = item;
    if (item.sequence !== sequence || item.previousHash !== previousHash || digest(unsigned) !== hash) {
      return { valid: false, failedEventId: item.id, retainedEvents: snapshot.events.length };
    }
    previousHash = hash;
  }
  return {
    valid: sequence === snapshot.eventSequence,
    retainedEvents: snapshot.events.length,
    anchorSequence: snapshot.anchor.sequence,
    headSequence: snapshot.eventSequence,
    headHash: previousHash
  };
}

function request(snapshot, id) {
  const safe = requestId(id);
  const value = snapshot.requests[safe];
  if (!value) throw new PrivilegedAccessError('Privileged-access request not found.', 'PRIVILEGED_ACCESS_NOT_FOUND', { requestId: safe }, 404);
  return value;
}

function version(item, expected) {
  const value = Number(expected);
  if (!Number.isInteger(value) || value < 1) {
    throw new PrivilegedAccessError('An expected request version is required.', 'PRIVILEGED_ACCESS_PRECONDITION_REQUIRED', {}, 428);
  }
  if (item.version !== value) {
    throw new PrivilegedAccessConflictError('The privileged-access request version does not match.', {
      currentVersion: item.version,
      expectedVersion: value
    });
  }
}

function tenant(item, principal) {
  if (item.tenantId !== principal.tenantId) {
    throw new PrivilegedAccessError('Privileged-access requests are tenant isolated.', 'PRIVILEGED_ACCESS_TENANT_MISMATCH');
  }
}

function state(item, expected) {
  return new PrivilegedAccessConflictError(`Privileged-access request must be ${expected}.`, { requestId: item.id, status: item.status });
}

function manage(principal, permission) {
  if (!principal?.permissions?.includes(permission)) {
    throw new PrivilegedAccessError('The authenticated principal cannot manage privileged access.', 'PRIVILEGED_ACCESS_MANAGEMENT_DENIED', { permission });
  }
}

function requested(values, protectedPermissions, standingPermissions = []) {
  const result = stringList(values, 'permissions', 1, 10);
  for (const permission of result) {
    if (!protectedPermissions.has(permission)) {
      throw new PrivilegedAccessError('The requested permission is not protected by just-in-time access.', 'PRIVILEGED_PERMISSION_NOT_PROTECTED', { permission }, 400);
    }
    if (!standingPermissions.includes(permission)) {
      throw new PrivilegedAccessError('The requested permission is not included in the approved standing role.', 'PRIVILEGED_PERMISSION_NOT_ASSIGNED', { permission });
    }
  }
  return [...new Set(result)].sort();
}

function protectedSet(values) {
  const result = new Set();
  for (const permission of stringList(values, 'protectedPermissions', 1, 50)) {
    if (!/^[a-z][a-z0-9_-]*:[a-z][a-z0-9_-]*$/.test(permission)
        || !ROLE_PERMISSIONS.has(permission)
        || MANAGEMENT.has(permission)) {
      throw new TypeError(`Protected permission is invalid: ${permission}`);
    }
    result.add(permission);
  }
  return result;
}

function observed(principal, permission, reason) {
  return Object.freeze({ ...principal, privilegedAccess: Object.freeze({ status: 'observed', permission, reason, enforced: false }) });
}

function role(value) {
  const result = String(value ?? '');
  permissionsForRole(result);
  return result;
}

function subject(value) {
  const result = String(value ?? '').trim();
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{1,255}$/.test(result)) throw new TypeError('subject must be a safe identifier.');
  return result;
}

function actor(value) {
  const result = String(value ?? '').trim();
  if (!result || result.length > 256) throw new TypeError('actor must contain 1 to 256 characters.');
  return result;
}

function requestId(value) {
  const result = String(value ?? '');
  if (!/^PAM-[0-9a-f-]{36}$/i.test(result)) {
    throw new PrivilegedAccessError('Privileged-access request ID is invalid.', 'PRIVILEGED_ACCESS_ID_INVALID', {}, 400);
  }
  return result;
}

function identifier(value, field) {
  const result = String(value ?? '').trim();
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{1,127}$/.test(result)) throw new TypeError(`${field} must be a safe identifier.`);
  return result;
}

function text(value, field, min, max) {
  const result = String(value ?? '').trim();
  if (result.length < min || result.length > max) throw new TypeError(`${field} must contain ${min} to ${max} characters.`);
  return result;
}

function stringList(value, field, min, max) {
  const values = Array.isArray(value) ? value : String(value ?? '').split(',');
  const result = [...new Set(values.map((item) => String(item).trim()).filter(Boolean))];
  if (result.length < min || result.length > max) throw new TypeError(`${field} must contain ${min} to ${max} values.`);
  return result;
}

function integer(value, field, min, max) {
  const result = Number(value);
  if (!Number.isInteger(result) || result < min || result > max) throw new TypeError(`${field} must be an integer from ${min} to ${max}.`);
  return result;
}

function bool(value, field) {
  if (typeof value === 'boolean') return value;
  if (String(value) === 'true') return true;
  if (String(value) === 'false') return false;
  throw new TypeError(`${field} must be true or false.`);
}

function csv(value) {
  if (value === undefined || value === null || value === '') return [];
  const raw = String(value).trim();
  if (raw.startsWith('[')) {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) throw new TypeError('Privileged-access list configuration must be an array.');
    return parsed;
  }
  return raw.split(',').map((item) => item.trim()).filter(Boolean);
}

function json(value, field) {
  if (!value) throw new TypeError(`${field} is required.`);
  try { return JSON.parse(String(value)); }
  catch { throw new TypeError(`${field} must contain valid JSON.`); }
}

function required(value, field) {
  const result = String(value ?? '').trim();
  if (!result) throw new TypeError(`${field} is required.`);
  return result;
}

function keyringOf(input, primaryKeyId) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new TypeError('Privileged-access encryption keys must be an object.');
  const keys = new Map(Object.entries(input).map(([id, value]) => [identifier(id, 'keyId'), base64(value, 32, `key ${id}`)]));
  const primary = identifier(primaryKeyId, 'primaryKeyId');
  if (!keys.has(primary)) throw new TypeError('The privileged-access primary key is not configured.');
  return { keys, primaryKeyId: primary };
}

function encrypt(snapshot, keyring, now) {
  const keyId = keyring.primaryKeyId;
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', keyring.keys.get(keyId), iv);
  cipher.setAAD(Buffer.from(`${FORMAT}|${VERSION}|${keyId}`));
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(snapshot)), cipher.final()]);
  return {
    format: FORMAT,
    version: VERSION,
    algorithm: 'aes-256-gcm',
    keyId,
    writtenAt: now.toISOString(),
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64')
  };
}

function decrypt(envelope, keyring) {
  if (!envelope || envelope.format !== FORMAT || envelope.version !== VERSION || envelope.algorithm !== 'aes-256-gcm') {
    throw new Error('Privileged-access envelope format is invalid.');
  }
  const key = keyring.keys.get(String(envelope.keyId));
  if (!key) throw new Error(`Privileged-access key ${envelope.keyId} is not configured.`);
  const decipher = createDecipheriv('aes-256-gcm', key, base64(envelope.iv, 12, 'iv'));
  decipher.setAAD(Buffer.from(`${FORMAT}|${VERSION}|${envelope.keyId}`));
  decipher.setAuthTag(base64(envelope.tag, 16, 'tag'));
  const snapshot = JSON.parse(Buffer.concat([
    decipher.update(base64(envelope.ciphertext, null, 'ciphertext', 64 * 1024 * 1024)),
    decipher.final()
  ]).toString('utf8'));
  if (!snapshot || snapshot.format !== FORMAT || snapshot.version !== VERSION
      || !snapshot.requests || !Array.isArray(snapshot.events) || !verifyEvents(snapshot).valid) {
    throw new Error('Privileged-access snapshot integrity failed.');
  }
  return snapshot;
}

function base64(value, length, field, maximum = null) {
  const encoded = String(value ?? '');
  const result = Buffer.from(encoded, 'base64');
  if (!encoded || result.toString('base64') !== encoded
      || (length !== null && result.length !== length)
      || (maximum !== null && result.length > maximum)) {
    throw new TypeError(`${field} must be valid canonical base64.`);
  }
  return result;
}

function atomicWrite(path, content) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temp = `${path}.tmp-${process.pid}-${randomUUID()}`;
  let descriptor;
  try {
    descriptor = openSync(temp, 'wx', 0o600);
    writeFileSync(descriptor, content, 'utf8');
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    renameSync(temp, path);
    let directoryDescriptor;
    try {
      directoryDescriptor = openSync(dirname(path), 'r');
      fsyncSync(directoryDescriptor);
    } finally {
      if (directoryDescriptor !== undefined) closeSync(directoryDescriptor);
    }
  } catch (error) {
    if (descriptor !== undefined) try { closeSync(descriptor); } catch { /* best effort */ }
    try { unlinkSync(temp); } catch { /* best effort */ }
    throw error;
  }
}

function digest(value) {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

function storeError(error) {
  return error instanceof PrivilegedAccessStoreError
    ? error
    : new PrivilegedAccessStoreError(undefined, { cause: error?.code ?? error?.message ?? 'unknown' });
}
