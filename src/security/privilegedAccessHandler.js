import { randomUUID } from 'node:crypto';
import {
  PrivilegedAccessConflictError,
  PrivilegedAccessError,
  PrivilegedAccessStoreError
} from './privilegedAccessRegistry.js';

const PREFIX = '/api/workforce-audit/privileged-access';
const REQUEST_ROUTE = new RegExp(`^${PREFIX}/requests/([^/]+)$`);
const ACTION_ROUTE = new RegExp(`^${PREFIX}/requests/([^/]+)/(approve|deny|cancel|revoke|review)$`);

export function createPrivilegedAccessHandler({ registry, authenticationGateway, securityTelemetry = null } = {}) {
  if (!registry || typeof registry.status !== 'function') throw new TypeError('A privileged-access registry is required.');
  if (!authenticationGateway || typeof authenticationGateway.authorise !== 'function') throw new TypeError('An authentication gateway is required.');

  function matches(pathname) {
    return pathname === PREFIX || pathname.startsWith(`${PREFIX}/`);
  }

  async function handle(req, res, principal, requestId = randomUUID()) {
    const url = new URL(req.url ?? '/', 'http://localhost');
    try {
      if (req.method === 'GET' && url.pathname === `${PREFIX}/status`) {
        authenticationGateway.authorise(principal, 'privileged:read');
        return sendJson(res, 200, { success: true, data: publicStatus(registry.status()), meta: meta(requestId, principal) }, requestId);
      }
      if (req.method === 'GET' && url.pathname === `${PREFIX}/requests`) {
        authenticationGateway.authorise(principal, 'privileged:read');
        const canReviewAll = principal.permissions.includes('privileged:approve') || principal.permissions.includes('privileged:revoke');
        const data = registry.list({
          tenantId: principal.tenantId,
          subject: canReviewAll ? safeSubject(url.searchParams.get('subject')) : principal.subject,
          status: url.searchParams.get('status'),
          limit: positiveInteger(url.searchParams.get('limit'), 100, 500)
        });
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }
      if (req.method === 'POST' && url.pathname === `${PREFIX}/requests`) {
        authenticationGateway.authorise(principal, 'privileged:request');
        const data = registry.requestAccess(principal, await readJson(req), { actor: principal.subject });
        record(securityTelemetry, event('privileged_access.requested', 'warning', principal, req, requestId, data));
        return sendJson(res, 201, { success: true, data, meta: meta(requestId, principal) }, requestId, { etag: etag(data.version) });
      }
      if (req.method === 'POST' && url.pathname === `${PREFIX}/break-glass`) {
        authenticationGateway.authorise(principal, 'privileged:break_glass');
        const data = registry.activateBreakGlass(principal, await readJson(req), { actor: principal.subject });
        record(securityTelemetry, event('privileged_access.break_glass_activated', 'critical', principal, req, requestId, data));
        return sendJson(res, 201, { success: true, data, meta: meta(requestId, principal) }, requestId, { etag: etag(data.version) });
      }

      const requestMatch = url.pathname.match(REQUEST_ROUTE);
      if (req.method === 'GET' && requestMatch) {
        authenticationGateway.authorise(principal, 'privileged:read');
        const data = registry.get(decodeURIComponent(requestMatch[1]));
        ensureVisible(data, principal);
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId, { etag: etag(data.version) });
      }

      const actionMatch = url.pathname.match(ACTION_ROUTE);
      if (req.method === 'POST' && actionMatch) {
        const id = decodeURIComponent(actionMatch[1]);
        const action = actionMatch[2];
        const input = await readJson(req);
        input.expectedVersion = expectedVersion(req.headers['if-match']);
        let data;
        if (action === 'approve') {
          authenticationGateway.authorise(principal, 'privileged:approve');
          data = registry.approve(id, principal, input, { actor: principal.subject });
        } else if (action === 'deny') {
          authenticationGateway.authorise(principal, 'privileged:approve');
          data = registry.deny(id, principal, input, { actor: principal.subject });
        } else if (action === 'cancel') {
          authenticationGateway.authorise(principal, 'privileged:request');
          data = registry.cancel(id, principal, input, { actor: principal.subject });
        } else if (action === 'revoke') {
          authenticationGateway.authorise(principal, 'privileged:revoke');
          data = registry.revoke(id, principal, input, { actor: principal.subject });
        } else {
          authenticationGateway.authorise(principal, 'privileged:approve');
          data = registry.completePostReview(id, principal, input, { actor: principal.subject });
        }
        const severity = action === 'approve' && data.status !== 'active' ? 'warning' : action === 'cancel' ? 'warning' : 'high';
        const eventType = {
          approve: 'privileged_access.approved',
          deny: 'privileged_access.denied',
          cancel: 'privileged_access.cancelled',
          revoke: 'privileged_access.revoked',
          review: 'privileged_access.break_glass_reviewed'
        }[action];
        record(securityTelemetry, event(eventType, severity, principal, req, requestId, data));
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId, { etag: etag(data.version) });
      }

      return sendJson(res, 404, {
        success: false,
        error: 'Privileged-access route not found.',
        code: 'NOT_FOUND',
        meta: meta(requestId, principal)
      }, requestId);
    } catch (error) {
      if (error instanceof PrivilegedAccessError
          || error instanceof PrivilegedAccessConflictError
          || error instanceof PrivilegedAccessStoreError) {
        record(securityTelemetry, {
          type: error.code === 'BREAK_GLASS_CONFIRMATION_REQUIRED'
            ? 'privileged_access.break_glass_denied'
            : 'privileged_access.operation_denied',
          severity: error instanceof PrivilegedAccessStoreError ? 'critical' : 'high',
          outcome: 'denied',
          requestId,
          subject: principal?.subject,
          tenantId: principal?.tenantId,
          method: req.method,
          route: url.pathname,
          details: { reason: error.code }
        });
        return sendJson(res, error.statusCode ?? 500, {
          success: false,
          error: error.message,
          code: error.code,
          details: error.details,
          meta: meta(requestId, principal)
        }, requestId, error.statusCode === 503 ? { 'retry-after': '30' } : {});
      }
      if (error?.code === 'INVALID_JSON') {
        return sendJson(res, 400, {
          success: false,
          error: error.message,
          code: error.code,
          meta: meta(requestId, principal)
        }, requestId);
      }
      if (error instanceof TypeError) {
        return sendJson(res, 400, {
          success: false,
          error: error.message,
          code: 'PRIVILEGED_ACCESS_INPUT_INVALID',
          meta: meta(requestId, principal)
        }, requestId);
      }
      throw error;
    }
  }

  return { matches, handle, health: () => publicStatus(registry.health()), prefix: PREFIX };
}

function ensureVisible(request, principal) {
  if (request.tenantId !== principal.tenantId) {
    throw new PrivilegedAccessError('Privileged-access requests are tenant isolated.', 'PRIVILEGED_ACCESS_TENANT_MISMATCH');
  }
  const canReviewAll = principal.permissions.includes('privileged:approve') || principal.permissions.includes('privileged:revoke');
  if (!canReviewAll && request.subject !== principal.subject) {
    throw new PrivilegedAccessError('This privileged-access request is not visible to the principal.', 'PRIVILEGED_ACCESS_READ_DENIED');
  }
}

function safeSubject(value) {
  if (value === null) return null;
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{1,255}$/.test(String(value))) {
    throw new PrivilegedAccessError('subject filter is invalid.', 'PRIVILEGED_ACCESS_INPUT_INVALID', { field: 'subject' }, 400);
  }
  return String(value);
}

function expectedVersion(value) {
  const raw = Array.isArray(value) ? value[0] : value;
  const match = String(raw ?? '').match(/^W\/"(\d+)"$|^"(\d+)"$|^(\d+)$/);
  if (!match) {
    throw new PrivilegedAccessError(
      'If-Match with the current request version is required.',
      'PRIVILEGED_ACCESS_PRECONDITION_REQUIRED',
      {},
      428
    );
  }
  return Number(match[1] ?? match[2] ?? match[3]);
}

function etag(version) { return `W/"${version}"`; }

async function readJson(req) {
  const contentType = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
  if (contentType && contentType !== 'application/json') {
    const error = new Error('Content-Type must be application/json.');
    error.code = 'INVALID_JSON';
    throw error;
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 64 * 1024) {
      const error = new Error('Privileged-access request body exceeds 64 KB.');
      error.code = 'INVALID_JSON';
      throw error;
    }
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); }
  catch {
    const error = new Error('Request body must be valid JSON.');
    error.code = 'INVALID_JSON';
    throw error;
  }
}

function positiveInteger(value, fallback, maximum) {
  if (value === null) return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1) {
    throw new PrivilegedAccessError('limit must be a positive integer.', 'PRIVILEGED_ACCESS_INPUT_INVALID', { field: 'limit' }, 400);
  }
  return Math.min(parsed, maximum);
}

function publicStatus(value) {
  if (!value || typeof value !== 'object') return value;
  const clone = structuredClone(value);
  delete clone.directory;
  delete clone.primaryKeyId;
  delete clone.configuredKeyIds;
  return clone;
}

function event(type, severity, principal, req, requestId, data) {
  return {
    type,
    severity,
    outcome: 'success',
    requestId,
    subject: principal.subject,
    tenantId: principal.tenantId,
    keyId: principal.keyId,
    method: req.method,
    route: new URL(req.url ?? '/', 'http://localhost').pathname,
    details: {
      privilegedRequestId: data.id,
      status: data.status,
      breakGlass: Boolean(data.breakGlass),
      permissions: data.permissions
    }
  };
}

function record(telemetry, input) {
  try { telemetry?.record?.(input); }
  catch (error) { console.error('Privileged-access telemetry record failed', error); }
}

function meta(requestId, principal) {
  return {
    requestId,
    tenantId: principal?.tenantId ?? null,
    keyId: principal?.keyId ?? null
  };
}

function sendJson(res, status, payload, requestId, additionalHeaders = {}) {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'x-request-id': requestId,
    ...additionalHeaders
  });
  res.end(JSON.stringify(payload));
}
