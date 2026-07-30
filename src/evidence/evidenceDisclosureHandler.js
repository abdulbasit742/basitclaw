import { randomUUID } from 'node:crypto';
import { AuthenticationError, AuthorizationError } from '../security/accessControl.js';
import { SecurityControlBusyError, SecurityControlUnavailableError } from '../security/fileMutex.js';
import { OidcUnavailableError } from '../security/oidcAuthenticator.js';
import { RateLimitStoreError } from '../security/sharedRateLimiter.js';
import {
  EvidenceConflictError,
  EvidenceIntegrityError,
  EvidenceStoreError,
  EvidenceValidationError
} from './evidenceRegistry.js';
import {
  EvidenceDisclosureApprovalError,
  EvidenceDisclosureIntegrityError,
  EvidenceDisclosureStoreError
} from './evidenceDisclosureStore.js';

const BASE_ROUTE = '/api/workforce-audit/evidence-disclosures';
const STATUS_ROUTE = `${BASE_ROUTE}/status`;
const VERIFY_ROUTE = `${BASE_ROUTE}/verify`;
const ITEM_ROUTE = /^\/api\/workforce-audit\/evidence-disclosures\/([^/]+)$/;
const ACTION_ROUTE = /^\/api\/workforce-audit\/evidence-disclosures\/([^/]+)\/(approve|reject|revoke)$/;
const PACKAGE_ROUTE = /^\/api\/workforce-audit\/evidence-disclosures\/([^/]+)\/package$/;
const EVENTS_ROUTE = /^\/api\/workforce-audit\/evidence-disclosures\/([^/]+)\/events$/;

export function createEvidenceDisclosureHandler({
  registry,
  authenticationGateway,
  rateLimiter = null,
  securityTelemetry = null
} = {}) {
  if (!registry || typeof registry.createEvidenceDisclosure !== 'function') {
    throw new TypeError('An evidence-disclosure-aware registry is required.');
  }
  if (!authenticationGateway || typeof authenticationGateway.authenticate !== 'function') {
    throw new TypeError('An authentication gateway is required.');
  }

  function matches(pathname) {
    return pathname === BASE_ROUTE || pathname === STATUS_ROUTE || pathname === VERIFY_ROUTE
      || ITEM_ROUTE.test(pathname) || ACTION_ROUTE.test(pathname)
      || PACKAGE_ROUTE.test(pathname) || EVENTS_ROUTE.test(pathname);
  }

  async function handle(req, res, requestId = randomUUID()) {
    const url = new URL(req.url ?? '/', 'http://localhost');
    const client = typeof rateLimiter?.clientAddress === 'function'
      ? rateLimiter.clientAddress(req)
      : 'unknown';
    let principal = null;
    try {
      const burst = rateLimiter?.consume?.(`client:${client}`, 'burst');
      if (burst) {
        applyRateHeaders(res, rateLimiter, burst);
        if (!burst.allowed) return rateLimited(res, requestId, burst, 'The client request burst limit has been exceeded.');
      }
      principal = await authenticationGateway.authenticate(req);
      const permission = permissionFor(req.method, url.pathname);
      authenticationGateway.authorise(principal, permission);
      const policy = req.method === 'GET' ? 'read' : permission === 'evidence:disclose:approve' ? 'sensitive' : 'write';
      const decision = rateLimiter?.consume?.(`credential:${principal.keyId ?? principal.subject}:evidence-disclosures`, policy);
      if (decision) {
        applyRateHeaders(res, rateLimiter, decision);
        if (!decision.allowed) return rateLimited(res, requestId, decision, 'The evidence disclosure rate limit has been exceeded.');
      }

      if (url.pathname === STATUS_ROUTE && req.method === 'GET') {
        return sendJson(res, 200, {
          success: true,
          data: registry.evidenceDisclosureStatus(principal.tenantId),
          meta: meta(requestId, principal)
        }, requestId);
      }
      if (url.pathname === VERIFY_ROUTE && req.method === 'POST') {
        const data = registry.verifyEvidenceDisclosures(principal.tenantId);
        audit(securityTelemetry, 'evidence_disclosure.verified', principal, req, url, requestId, {
          checkedRequests: data.checkedRequests,
          checkedPackages: data.checkedPackages
        });
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }
      if (url.pathname === BASE_ROUTE && req.method === 'GET') {
        const data = registry.evidenceDisclosures(principal.tenantId, {
          state: url.searchParams.get('state'),
          limit: positiveInteger(url.searchParams.get('limit'), 200, 2000)
        });
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }
      if (url.pathname === BASE_ROUTE && req.method === 'POST') {
        const input = await readJson(req, 262_144);
        const data = registry.createEvidenceDisclosure(principal.tenantId, input, {
          actor: principal.subject
        });
        audit(securityTelemetry, data.duplicate ? 'evidence_disclosure.duplicate' : 'evidence_disclosure.requested', principal, req, url, requestId, {
          requestId: data.request.requestId,
          recipientId: data.request.recipientId,
          evidenceCount: data.request.evidence.length
        });
        return sendJson(res, data.duplicate ? 200 : 201, {
          success: true,
          data,
          meta: meta(requestId, principal)
        }, requestId);
      }

      const action = url.pathname.match(ACTION_ROUTE);
      if (action && req.method === 'POST') {
        const requestIdValue = decodeSegment(action[1], 'requestId');
        const input = await readJson(req, 16_384);
        const method = action[2] === 'approve'
          ? 'approveEvidenceDisclosure'
          : action[2] === 'reject'
            ? 'rejectEvidenceDisclosure'
            : 'revokeEvidenceDisclosure';
        const data = registry[method](principal.tenantId, requestIdValue, input, {
          actor: principal.subject
        });
        audit(securityTelemetry, `evidence_disclosure.${action[2]}`, principal, req, url, requestId, {
          requestId: requestIdValue,
          state: data.request.state,
          packageId: data.request.packageId
        });
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }

      const packageMatch = url.pathname.match(PACKAGE_ROUTE);
      if (packageMatch && req.method === 'GET') {
        const requestIdValue = decodeSegment(packageMatch[1], 'requestId');
        const data = registry.evidenceDisclosurePackage(principal.tenantId, requestIdValue);
        audit(securityTelemetry, 'evidence_disclosure.sealed_package_read', principal, req, url, requestId, {
          requestId: requestIdValue,
          packageId: data.packageId
        });
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }

      const eventsMatch = url.pathname.match(EVENTS_ROUTE);
      if (eventsMatch && req.method === 'GET') {
        const requestIdValue = decodeSegment(eventsMatch[1], 'requestId');
        const data = registry.evidenceDisclosureEvents(principal.tenantId, requestIdValue, {
          limit: positiveInteger(url.searchParams.get('limit'), 500, 5000)
        });
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }

      const item = url.pathname.match(ITEM_ROUTE);
      if (item && req.method === 'GET') {
        const requestIdValue = decodeSegment(item[1], 'requestId');
        const data = registry.evidenceDisclosure(principal.tenantId, requestIdValue);
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }
      return notFound(res, requestId);
    } catch (error) {
      if (error instanceof AuthenticationError) {
        let failed;
        try {
          failed = rateLimiter?.consume?.(`authentication:${client}`, 'authFailure');
          if (failed) applyRateHeaders(res, rateLimiter, failed);
        } catch (storeError) {
          if (storeError instanceof RateLimitStoreError) return unavailable(res, requestId, storeError, principal);
          throw storeError;
        }
        audit(securityTelemetry, 'authentication.failed', principal, req, url, requestId, {
          reason: error.code,
          boundary: 'evidence-disclosures'
        }, 'high', 'denied');
        if (failed && !failed.allowed) return rateLimited(res, requestId, failed, 'Too many failed authentication attempts.');
        return sendJson(res, 401, {
          success: false,
          error: error.message,
          code: error.code,
          meta: { requestId }
        }, requestId, { 'www-authenticate': challenge(authenticationGateway.mode) });
      }
      if (error instanceof AuthorizationError) {
        audit(securityTelemetry, 'authorization.denied', principal, req, url, requestId, {
          reason: error.details?.reason,
          boundary: 'evidence-disclosures'
        }, 'high', 'denied');
        return sendJson(res, 403, {
          success: false,
          error: error.message,
          code: error.code,
          meta: meta(requestId, principal)
        }, requestId);
      }
      if (error instanceof RateLimitStoreError || error instanceof OidcUnavailableError || error?.code === 'OIDC_UNAVAILABLE') {
        return unavailable(res, requestId, error, principal);
      }
      if (error instanceof SecurityControlBusyError) {
        return sendJson(res, 423, {
          success: false,
          error: 'The evidence disclosure boundary is busy. Retry the request.',
          code: 'EVIDENCE_DISCLOSURE_BUSY',
          details: error.details,
          meta: meta(requestId, principal)
        }, requestId, {
          'retry-after': String(Math.max(1, Math.ceil((error.details?.retryAfterMs ?? 1000) / 1000)))
        });
      }
      if (error instanceof SecurityControlUnavailableError) {
        return unavailable(res, requestId, error, principal, 'EVIDENCE_DISCLOSURE_STORE_UNAVAILABLE');
      }
      if (error instanceof EvidenceValidationError || error instanceof EvidenceConflictError
          || error instanceof EvidenceIntegrityError || error instanceof EvidenceStoreError
          || error instanceof EvidenceDisclosureApprovalError
          || error instanceof EvidenceDisclosureIntegrityError
          || error instanceof EvidenceDisclosureStoreError) {
        audit(securityTelemetry, 'evidence_disclosure.denied', principal, req, url, requestId, {
          reason: error.code
        }, error instanceof EvidenceIntegrityError || error instanceof EvidenceStoreError ? 'critical' : 'high', 'denied');
        return sendJson(res, error.statusCode ?? 500, {
          success: false,
          error: error.message,
          code: error.code,
          details: error.details,
          meta: meta(requestId, principal)
        }, requestId, error.statusCode === 503 ? { 'retry-after': '30' } : {});
      }
      throw error;
    }
  }

  return Object.freeze({ matches, handle, baseRoute: BASE_ROUTE });
}

function permissionFor(method, pathname) {
  if (method === 'POST' && (ACTION_ROUTE.test(pathname) || pathname === VERIFY_ROUTE)) {
    return 'evidence:disclose:approve';
  }
  return 'evidence:disclose';
}

async function readJson(req, maximumBytes) {
  const contentType = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
  if (contentType !== 'application/json') {
    throw new EvidenceValidationError('Evidence disclosure requests require Content-Type application/json.', {
      field: 'content-type'
    });
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maximumBytes) {
      throw new EvidenceValidationError('The evidence disclosure request body is too large.', { field: 'body' });
    }
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
  } catch {
    throw new EvidenceValidationError('The evidence disclosure request body must be valid JSON.', { field: 'body' });
  }
}

function decodeSegment(value, field) {
  try {
    return decodeURIComponent(value);
  } catch {
    throw new EvidenceValidationError(`${field} contains invalid percent encoding.`, { field });
  }
}

function positiveInteger(value, fallback, maximum) {
  if (value === null) return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1) {
    throw new EvidenceValidationError('limit must be a positive integer.', { field: 'limit' });
  }
  return Math.min(parsed, maximum);
}

function meta(requestId, principal) {
  return {
    requestId,
    tenantId: principal?.tenantId ?? null,
    keyId: principal?.keyId ?? null
  };
}

function challenge(mode) {
  if (mode === 'api-key') return 'ApiKey realm="workforce-audit"';
  if (mode === 'oidc') return 'Bearer realm="workforce-audit"';
  return 'Bearer realm="workforce-audit", ApiKey realm="workforce-audit"';
}

function applyRateHeaders(res, limiter, decision) {
  const headers = typeof limiter?.headers === 'function' ? limiter.headers(decision) : {};
  for (const [name, value] of Object.entries(headers)) res.setHeader(name, value);
}

function rateLimited(res, requestId, decision, message) {
  return sendJson(res, 429, {
    success: false,
    error: message,
    code: 'RATE_LIMITED',
    details: decision,
    meta: { requestId }
  }, requestId, {
    'retry-after': String(decision.retryAfterSeconds ?? 1)
  });
}

function unavailable(res, requestId, error, principal, code = null) {
  return sendJson(res, 503, {
    success: false,
    error: error.message,
    code: code ?? error.code ?? 'UNAVAILABLE',
    details: error.details,
    meta: meta(requestId, principal)
  }, requestId, { 'retry-after': '30' });
}

function audit(telemetry, type, principal, req, url, requestId, details, severity = 'info', outcome = 'success') {
  try {
    telemetry?.record?.({
      type,
      severity,
      outcome,
      requestId,
      subject: principal?.subject,
      tenantId: principal?.tenantId,
      method: req.method,
      route: url.pathname,
      details
    });
  } catch (error) {
    console.error('Evidence disclosure telemetry failed', error);
  }
}

function notFound(res, requestId) {
  return sendJson(res, 404, {
    success: false,
    error: 'Evidence disclosure route not found.',
    code: 'NOT_FOUND',
    meta: { requestId }
  }, requestId);
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
