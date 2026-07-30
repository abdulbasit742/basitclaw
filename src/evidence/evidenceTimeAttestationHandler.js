import { randomUUID } from 'node:crypto';
import { AuthenticationError, AuthorizationError } from '../security/accessControl.js';
import { SecurityControlBusyError, SecurityControlUnavailableError } from '../security/fileMutex.js';
import { OidcUnavailableError } from '../security/oidcAuthenticator.js';
import { RateLimitStoreError } from '../security/sharedRateLimiter.js';
import {
  EvidenceConflictError,
  EvidenceIntegrityError,
  EvidenceNotFoundError,
  EvidenceStoreError,
  EvidenceValidationError
} from './evidenceRegistry.js';
import {
  EvidenceTimeAttestationAuthenticationError,
  EvidenceTimeAttestationIntegrityError,
  EvidenceTimeAttestationStoreError
} from './evidenceTimeAttestationStore.js';

const CALLBACK_ROUTE = '/api/workforce-audit/evidence-notary/attestations';
const STATUS_ROUTE = '/api/workforce-audit/evidence-notary/status';
const CHALLENGE_ROUTE = /^\/api\/workforce-audit\/evidence-preservation\/([^/]+)\/notary-challenge$/;
const ATTESTATIONS_ROUTE = /^\/api\/workforce-audit\/evidence-preservation\/([^/]+)\/time-attestations$/;
const VERIFY_ROUTE = /^\/api\/workforce-audit\/evidence-preservation\/([^/]+)\/time-attestations\/verify$/;

export function createEvidenceTimeAttestationHandler({
  registry,
  authenticationGateway,
  rateLimiter = null,
  securityTelemetry = null
} = {}) {
  if (!registry || typeof registry.recordTimeAttestation !== 'function') throw new TypeError('A time-attestation-aware evidence registry is required.');
  if (!authenticationGateway || typeof authenticationGateway.authenticate !== 'function') throw new TypeError('An authentication gateway is required.');

  function matches(pathname) {
    return pathname === CALLBACK_ROUTE || pathname === STATUS_ROUTE
      || CHALLENGE_ROUTE.test(pathname) || ATTESTATIONS_ROUTE.test(pathname) || VERIFY_ROUTE.test(pathname);
  }

  async function handle(req, res, requestId = randomUUID()) {
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (url.pathname === CALLBACK_ROUTE) return handleCallback(req, res, requestId, url);
    return handleGovernance(req, res, requestId, url);
  }

  async function handleCallback(req, res, requestId, url) {
    if (req.method !== 'POST') return notFound(res, requestId);
    const client = typeof rateLimiter?.clientAddress === 'function' ? rateLimiter.clientAddress(req) : 'unknown';
    try {
      const burst = rateLimiter?.consume?.(`evidence-notary:${client}`, 'burst');
      if (burst) {
        applyRateHeaders(res, rateLimiter, burst);
        if (!burst.allowed) return rateLimited(res, requestId, burst, 'The time-authority callback burst limit has been exceeded.');
      }
      const decision = rateLimiter?.consume?.(`evidence-notary:${client}`, 'write');
      if (decision) {
        applyRateHeaders(res, rateLimiter, decision);
        if (!decision.allowed) return rateLimited(res, requestId, decision, 'The time-authority callback rate limit has been exceeded.');
      }
      const input = await readJson(req, 32_768);
      const data = registry.recordTimeAttestation(input);
      record(securityTelemetry, {
        type: data.duplicate ? 'evidence_time_attestation.duplicate' : 'evidence_time_attestation.accepted',
        severity: 'info', outcome: data.duplicate ? 'duplicate' : 'success', requestId,
        method: req.method, route: url.pathname,
        details: {
          attestationId: data.attestation.attestationId,
          archiveId: data.attestation.archiveId,
          providerId: data.attestation.providerId,
          policyId: data.attestation.policyId
        }
      });
      return sendJson(res, data.duplicate ? 200 : 202, { success: true, data, meta: { requestId } }, requestId);
    } catch (error) {
      if (error instanceof EvidenceTimeAttestationAuthenticationError) {
        record(securityTelemetry, {
          type: 'evidence_time_attestation.authentication_failed', severity: 'critical', outcome: 'denied',
          requestId, method: req.method, route: url.pathname,
          details: { reason: error.details?.reason ?? error.code }
        });
        return sendJson(res, 401, {
          success: false, error: error.message, code: error.code,
          details: error.details, meta: { requestId }
        }, requestId, { 'www-authenticate': 'Signature realm="workforce-audit-evidence-notary"' });
      }
      return handleKnownError(error, res, requestId, null, req, url);
    }
  }

  async function handleGovernance(req, res, requestId, url) {
    const client = typeof rateLimiter?.clientAddress === 'function' ? rateLimiter.clientAddress(req) : 'unknown';
    let principal = null;
    try {
      const burst = rateLimiter?.consume?.(`client:${client}`, 'burst');
      if (burst) {
        applyRateHeaders(res, rateLimiter, burst);
        if (!burst.allowed) return rateLimited(res, requestId, burst, 'The client request burst limit has been exceeded.');
      }
      principal = await authenticationGateway.authenticate(req);
      authenticationGateway.authorise(principal, 'governance:read');
      const policy = req.method === 'POST' ? 'sensitive' : 'read';
      const decision = rateLimiter?.consume?.(`credential:${principal.keyId ?? principal.subject}:evidence-notary`, policy);
      if (decision) {
        applyRateHeaders(res, rateLimiter, decision);
        if (!decision.allowed) return rateLimited(res, requestId, decision, 'The evidence-notary governance rate limit has been exceeded.');
      }

      if (url.pathname === STATUS_ROUTE && req.method === 'GET') {
        return sendJson(res, 200, {
          success: true,
          data: registry.evidenceTimeAttestationStatus(principal.tenantId),
          meta: meta(requestId, principal)
        }, requestId);
      }
      const challenge = url.pathname.match(CHALLENGE_ROUTE);
      if (challenge && req.method === 'GET') {
        const archiveId = decodeSegment(challenge[1], 'archiveId');
        return sendJson(res, 200, {
          success: true,
          data: registry.timeAttestationChallenge(principal.tenantId, archiveId),
          meta: meta(requestId, principal)
        }, requestId);
      }
      const rows = url.pathname.match(ATTESTATIONS_ROUTE);
      if (rows && req.method === 'GET') {
        const archiveId = decodeSegment(rows[1], 'archiveId');
        const data = registry.evidenceTimeAttestations(principal.tenantId, archiveId, {
          limit: positiveInteger(url.searchParams.get('limit'), 500, 5000)
        });
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }
      const verify = url.pathname.match(VERIFY_ROUTE);
      if (verify && req.method === 'POST') {
        const archiveId = decodeSegment(verify[1], 'archiveId');
        const data = registry.verifyEvidenceTimeAttestations(principal.tenantId, archiveId);
        record(securityTelemetry, {
          type: 'evidence_time_attestation.verified', severity: 'info', outcome: 'success',
          requestId, subject: principal.subject, tenantId: principal.tenantId,
          method: req.method, route: url.pathname,
          details: { archiveId, distinctProviders: data.distinctProviders, quorumSatisfied: data.quorumSatisfied }
        });
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
        record(securityTelemetry, {
          type: 'authentication.failed', severity: 'high', outcome: 'denied', requestId,
          method: req.method, route: url.pathname,
          details: { reason: error.code, boundary: 'evidence-notary-governance' }
        });
        if (failed && !failed.allowed) return rateLimited(res, requestId, failed, 'Too many failed authentication attempts.');
        return sendJson(res, 401, { success: false, error: error.message, code: error.code, meta: { requestId } }, requestId, {
          'www-authenticate': challengeHeader(authenticationGateway.mode)
        });
      }
      if (error instanceof AuthorizationError) {
        return sendJson(res, 403, { success: false, error: error.message, code: error.code, meta: meta(requestId, principal) }, requestId);
      }
      return handleKnownError(error, res, requestId, principal, req, url);
    }
  }

  return Object.freeze({ matches, handle, callbackRoute: CALLBACK_ROUTE, statusRoute: STATUS_ROUTE });
}

function handleKnownError(error, res, requestId, principal, req, url) {
  if (error instanceof RateLimitStoreError || error instanceof OidcUnavailableError || error?.code === 'OIDC_UNAVAILABLE') {
    return unavailable(res, requestId, error, principal);
  }
  if (error instanceof SecurityControlBusyError) {
    return sendJson(res, 423, {
      success: false, error: 'The evidence time-attestation boundary is busy. Retry the request.',
      code: 'EVIDENCE_TIME_ATTESTATION_BUSY', details: error.details, meta: meta(requestId, principal)
    }, requestId, { 'retry-after': String(Math.max(1, Math.ceil((error.details?.retryAfterMs ?? 1000) / 1000))) });
  }
  if (error instanceof SecurityControlUnavailableError) {
    return unavailable(res, requestId, error, principal, 'EVIDENCE_TIME_ATTESTATION_STORE_UNAVAILABLE');
  }
  if (error instanceof EvidenceValidationError || error instanceof EvidenceNotFoundError
      || error instanceof EvidenceConflictError || error instanceof EvidenceIntegrityError
      || error instanceof EvidenceStoreError || error instanceof EvidenceTimeAttestationStoreError
      || error instanceof EvidenceTimeAttestationIntegrityError) {
    return sendJson(res, error.statusCode ?? 500, {
      success: false, error: error.message, code: error.code,
      details: error.details, meta: meta(requestId, principal)
    }, requestId, error.statusCode === 503 ? { 'retry-after': '30' } : {});
  }
  throw error;
}

async function readJson(req, maximumBytes) {
  const contentType = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
  if (contentType !== 'application/json') throw new EvidenceValidationError('Time-attestation callbacks require Content-Type application/json.', { field: 'content-type' });
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maximumBytes) throw new EvidenceValidationError('Time-attestation callback body is too large.', { field: 'body' });
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); }
  catch { throw new EvidenceValidationError('Time-attestation callback body must be valid JSON.', { field: 'body' }); }
}
function decodeSegment(value, field) { try { return decodeURIComponent(value); } catch { throw new EvidenceValidationError(`${field} contains invalid percent encoding.`, { field }); } }
function positiveInteger(value, fallback, maximum) { if (value === null) return fallback; const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < 1) throw new EvidenceValidationError('limit must be a positive integer.', { field: 'limit' }); return Math.min(parsed, maximum); }
function meta(requestId, principal) { return { requestId, tenantId: principal?.tenantId ?? null, keyId: principal?.keyId ?? null }; }
function challengeHeader(mode) { return mode === 'api-key' ? 'ApiKey realm="workforce-audit"' : mode === 'oidc' ? 'Bearer realm="workforce-audit"' : 'Bearer realm="workforce-audit", ApiKey realm="workforce-audit"'; }
function applyRateHeaders(res, limiter, decision) { const headers = typeof limiter?.headers === 'function' ? limiter.headers(decision) : {}; for (const [name, value] of Object.entries(headers)) res.setHeader(name, value); }
function rateLimited(res, requestId, decision, message) { return sendJson(res, 429, { success: false, error: message, code: 'RATE_LIMITED', details: decision, meta: { requestId } }, requestId, { 'retry-after': String(decision.retryAfterSeconds ?? 1) }); }
function unavailable(res, requestId, error, principal, code = null) { return sendJson(res, 503, { success: false, error: error.message, code: code ?? error.code ?? 'UNAVAILABLE', details: error.details, meta: meta(requestId, principal) }, requestId, { 'retry-after': '30' }); }
function record(telemetry, input) { try { telemetry?.record?.(input); } catch (error) { console.error('Evidence time-attestation telemetry failed', error); } }
function notFound(res, requestId) { return sendJson(res, 404, { success: false, error: 'Evidence time-attestation route not found.', code: 'NOT_FOUND', meta: { requestId } }, requestId); }
function sendJson(res, status, payload, requestId, additionalHeaders = {}) { res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'x-request-id': requestId, ...additionalHeaders }); res.end(JSON.stringify(payload)); }
