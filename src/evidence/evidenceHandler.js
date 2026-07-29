import { randomUUID } from 'node:crypto';
import { SecurityControlBusyError, SecurityControlUnavailableError } from '../security/fileMutex.js';
import { publicEvidenceHealth } from './evidenceHealthView.js';
import {
  EvidenceConflictError,
  EvidenceIntegrityError,
  EvidenceNotFoundError,
  EvidenceStoreError,
  EvidenceValidationError
} from './evidenceRegistry.js';

const PREFIX = '/api/workforce-audit/evidence';
const ITEM_ROUTE = new RegExp(`^${PREFIX}/([^/]+)$`);
const CONTENT_ROUTE = new RegExp(`^${PREFIX}/([^/]+)/content$`);
const VERSION_ROUTE = new RegExp(`^${PREFIX}/([^/]+)/versions$`);
const SCREENING_ROUTE = new RegExp(`^${PREFIX}/([^/]+)/screening$`);
const SCREENING_ACTION_ROUTE = new RegExp(`^${PREFIX}/([^/]+)/screening/(release|reject|events)$`);
const ACTION_ROUTE = new RegExp(`^${PREFIX}/([^/]+)/(verify|legal-hold|release-hold|dispose|events)$`);

export function createEvidenceHandler({ registry, auditRegistry, authenticationGateway, securityTelemetry = null } = {}) {
  if (!registry || typeof registry.tenantStatus !== 'function') throw new TypeError('An evidence registry is required.');
  if (!auditRegistry || typeof auditRegistry.forTenant !== 'function') throw new TypeError('A workforce-audit registry is required.');
  if (!authenticationGateway || typeof authenticationGateway.authorise !== 'function') throw new TypeError('An authentication gateway is required.');
  const bodyLimit = evidenceTransportLimit(registry.health?.().maxBytes);

  function matches(pathname) { return pathname === PREFIX || pathname.startsWith(`${PREFIX}/`); }

  async function handle(req, res, principal, requestId = randomUUID()) {
    const url = new URL(req.url ?? '/', 'http://localhost');
    try {
      if (req.method === 'GET' && url.pathname === `${PREFIX}/status`) {
        authenticationGateway.authorise(principal, 'audit:read');
        return sendJson(res, 200, { success: true, data: publicEvidenceHealth(registry.tenantStatus(principal.tenantId)), meta: meta(requestId, principal) }, requestId);
      }
      if (req.method === 'GET' && url.pathname === PREFIX) {
        authenticationGateway.authorise(principal, 'audit:read');
        const status = optionalEnum(url.searchParams.get('status'), ['active', 'quarantined', 'rejected', 'disposed']);
        const hold = optionalBoolean(url.searchParams.get('legalHold'));
        const data = registry.list(principal.tenantId, {
          status,
          legalHold: hold,
          limit: positiveInteger(url.searchParams.get('limit'), 100, 500)
        }).map((item) => withReferences(item, auditRegistry, principal.tenantId));
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }
      if (req.method === 'POST' && url.pathname === PREFIX) {
        authenticationGateway.authorise(principal, 'finding:write');
        const data = registry.ingest(principal.tenantId, await readJson(req, bodyLimit), { actor: principal.subject });
        record(securityTelemetry, event(
          data.status === 'quarantined' ? 'evidence.quarantined' : 'evidence.ingested',
          data.status === 'quarantined' ? 'high' : 'info', principal, req, requestId, data
        ));
        return sendJson(res, 201, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }

      const contentMatch = url.pathname.match(CONTENT_ROUTE);
      if (req.method === 'GET' && contentMatch) {
        authenticationGateway.authorise(principal, 'audit:read');
        const data = registry.readContent(principal.tenantId, decodeURIComponent(contentMatch[1]), {
          version: optionalPositiveInteger(url.searchParams.get('version'))
        });
        res.writeHead(200, {
          'content-type': data.mediaType,
          'content-length': String(data.content.length),
          'content-disposition': `attachment; filename*=UTF-8''${encodeURIComponent(data.filename)}`,
          'cache-control': 'no-store',
          'x-content-type-options': 'nosniff',
          'x-evidence-id': data.evidenceId,
          'x-evidence-version': String(data.version),
          'x-evidence-sha256': data.sha256,
          'x-request-id': requestId
        });
        return res.end(data.content);
      }

      const versionMatch = url.pathname.match(VERSION_ROUTE);
      if (req.method === 'POST' && versionMatch) {
        authenticationGateway.authorise(principal, 'finding:write');
        const data = registry.addVersion(principal.tenantId, decodeURIComponent(versionMatch[1]), await readJson(req, bodyLimit), { actor: principal.subject });
        record(securityTelemetry, event(
          data.status === 'quarantined' ? 'evidence.version_quarantined' : 'evidence.version_added',
          data.status === 'quarantined' ? 'high' : 'info', principal, req, requestId, data
        ));
        return sendJson(res, 201, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }

      const screeningActionMatch = url.pathname.match(SCREENING_ACTION_ROUTE);
      if (screeningActionMatch) {
        const evidenceId = decodeURIComponent(screeningActionMatch[1]);
        const action = screeningActionMatch[2];
        if (action === 'events') {
          if (req.method !== 'GET') return notFound(res, requestId, principal);
          authenticationGateway.authorise(principal, 'governance:read');
          const data = registry.screeningEvents(principal.tenantId, { evidenceId, limit: positiveInteger(url.searchParams.get('limit'), 100, 500) });
          return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
        }
        if (req.method !== 'POST') return notFound(res, requestId, principal);
        authenticationGateway.authorise(principal, 'backup:restore');
        const input = await readJson(req, 64 * 1024);
        const data = action === 'release'
          ? registry.releaseQuarantine(principal.tenantId, evidenceId, input, { actor: principal.subject })
          : registry.rejectQuarantine(principal.tenantId, evidenceId, input, { actor: principal.subject });
        record(securityTelemetry, event(
          action === 'release' ? 'evidence.quarantine_released' : 'evidence.quarantine_rejected',
          action === 'release' ? 'high' : 'critical', principal, req, requestId, data
        ));
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }

      const screeningMatch = url.pathname.match(SCREENING_ROUTE);
      if (req.method === 'GET' && screeningMatch) {
        authenticationGateway.authorise(principal, 'governance:read');
        const data = registry.screeningReport(principal.tenantId, decodeURIComponent(screeningMatch[1]), {
          version: optionalPositiveInteger(url.searchParams.get('version'))
        });
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }

      const itemMatch = url.pathname.match(ITEM_ROUTE);
      if (req.method === 'GET' && itemMatch) {
        authenticationGateway.authorise(principal, 'audit:read');
        const item = registry.get(principal.tenantId, decodeURIComponent(itemMatch[1]));
        return sendJson(res, 200, { success: true, data: withReferences(item, auditRegistry, principal.tenantId), meta: meta(requestId, principal) }, requestId);
      }

      const actionMatch = url.pathname.match(ACTION_ROUTE);
      if (actionMatch) {
        const evidenceId = decodeURIComponent(actionMatch[1]);
        const action = actionMatch[2];
        if (action === 'events') {
          if (req.method !== 'GET') return notFound(res, requestId, principal);
          authenticationGateway.authorise(principal, 'governance:read');
          const data = registry.events(principal.tenantId, { evidenceId, limit: positiveInteger(url.searchParams.get('limit'), 100, 500) });
          return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
        }
        if (req.method !== 'POST') return notFound(res, requestId, principal);
        if (action === 'verify') {
          authenticationGateway.authorise(principal, 'governance:read');
          const data = registry.verify(principal.tenantId, evidenceId);
          record(securityTelemetry, event('evidence.integrity_verified', 'info', principal, req, requestId, { evidenceId }));
          return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
        }
        authenticationGateway.authorise(principal, 'backup:restore');
        const input = await readJson(req, 64 * 1024);
        let data;
        if (action === 'legal-hold') {
          data = registry.placeLegalHold(principal.tenantId, evidenceId, input, { actor: principal.subject });
          record(securityTelemetry, event('evidence.legal_hold_placed', 'high', principal, req, requestId, data));
        } else if (action === 'release-hold') {
          data = registry.releaseLegalHold(principal.tenantId, evidenceId, input, { actor: principal.subject });
          record(securityTelemetry, event('evidence.legal_hold_released', 'high', principal, req, requestId, data));
        } else if (action === 'dispose') {
          const referencedBy = findingReferences(auditRegistry, principal.tenantId, evidenceId);
          data = registry.dispose(principal.tenantId, evidenceId, input, { actor: principal.subject, referencedBy });
          record(securityTelemetry, event('evidence.disposed', 'critical', principal, req, requestId, data));
        } else {
          return notFound(res, requestId, principal);
        }
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }
      return notFound(res, requestId, principal);
    } catch (error) {
      if (error instanceof SecurityControlBusyError) {
        return sendJson(res, 423, {
          success: false,
          error: 'The evidence store is busy. Retry the operation.',
          code: 'EVIDENCE_STORE_BUSY',
          details: error.details,
          meta: meta(requestId, principal)
        }, requestId, { 'retry-after': String(Math.max(1, Math.ceil((error.details?.retryAfterMs ?? 1000) / 1000))) });
      }
      if (error instanceof SecurityControlUnavailableError) {
        return sendJson(res, 503, {
          success: false,
          error: 'The evidence store coordination boundary is unavailable.',
          code: 'EVIDENCE_STORE_UNAVAILABLE',
          details: error.details,
          meta: meta(requestId, principal)
        }, requestId, { 'retry-after': '30' });
      }
      if (error instanceof EvidenceValidationError || error instanceof EvidenceNotFoundError
          || error instanceof EvidenceConflictError || error instanceof EvidenceIntegrityError
          || error instanceof EvidenceStoreError) {
        record(securityTelemetry, {
          type: error instanceof EvidenceStoreError ? 'evidence.store_unavailable' : 'evidence.operation_denied',
          severity: error instanceof EvidenceStoreError || error instanceof EvidenceIntegrityError ? 'critical' : 'high',
          outcome: 'denied', requestId, subject: principal?.subject, tenantId: principal?.tenantId,
          method: req.method, route: url.pathname, details: { reason: error.code }
        });
        return sendJson(res, error.statusCode ?? 500, {
          success: false, error: error.message, code: error.code, details: error.details, meta: meta(requestId, principal)
        }, requestId, error.statusCode === 503 ? { 'retry-after': '30' } : {});
      }
      if (error?.code === 'INVALID_JSON') {
        return sendJson(res, 400, { success: false, error: error.message, code: error.code, meta: meta(requestId, principal) }, requestId);
      }
      throw error;
    }
  }

  return { matches, handle, health: () => publicEvidenceHealth(registry.health()), prefix: PREFIX };
}

function withReferences(item, auditRegistry, tenantId) { return { ...item, referencedByFindings: findingReferences(auditRegistry, tenantId, item.evidenceId) }; }
function findingReferences(auditRegistry, tenantId, evidenceId) { return auditRegistry.forTenant(tenantId).getFindings().filter((finding) => finding.evidenceRefs?.includes(evidenceId)).map((finding) => finding.id); }
async function readJson(req, maximumBytes) {
  const contentType = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
  if (contentType && contentType !== 'application/json') return invalidJson('Content-Type must be application/json.');
  const chunks = [];
  let size = 0;
  for await (const chunk of req) { size += chunk.length; if (size > maximumBytes) return invalidJson(`Evidence request body exceeds the ${maximumBytes} byte transport limit.`); chunks.push(chunk); }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); } catch { return invalidJson('Request body must be valid JSON.'); }
}
function evidenceTransportLimit(maxBytes) { const decoded = Number(maxBytes); const safe = Number.isInteger(decoded) && decoded > 0 ? decoded : 10_000_000; return Math.min(140_000_000, Math.ceil(safe * 4 / 3) + 1_000_000); }
function invalidJson(message) { const error = new Error(message); error.code = 'INVALID_JSON'; throw error; }
function positiveInteger(value, fallback, maximum) { if (value === null) return fallback; const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < 1) throw new EvidenceValidationError('limit must be a positive integer.', { field: 'limit' }); return Math.min(parsed, maximum); }
function optionalPositiveInteger(value) { if (value === null) return null; const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < 1) throw new EvidenceValidationError('version must be a positive integer.', { field: 'version' }); return parsed; }
function optionalEnum(value, allowed) { if (value === null) return null; if (!allowed.includes(value)) throw new EvidenceValidationError('status filter is invalid.', { field: 'status', allowed }); return value; }
function optionalBoolean(value) { if (value === null) return null; if (value === 'true') return true; if (value === 'false') return false; throw new EvidenceValidationError('legalHold must be true or false.', { field: 'legalHold' }); }
function meta(requestId, principal) { return { requestId, tenantId: principal?.tenantId ?? null, keyId: principal?.keyId ?? null }; }
function event(type, severity, principal, req, requestId, data) { return { type, severity, outcome: 'success', requestId, subject: principal.subject, tenantId: principal.tenantId, keyId: principal.keyId, method: req.method, route: new URL(req.url ?? '/', 'http://localhost').pathname, details: { evidenceId: data.evidenceId, status: data.status, currentVersion: data.currentVersion } }; }
function record(telemetry, input) { try { telemetry?.record?.(input); } catch (error) { console.error('Evidence telemetry record failed', error); } }
function notFound(res, requestId, principal) { return sendJson(res, 404, { success: false, error: 'Evidence route not found.', code: 'NOT_FOUND', meta: meta(requestId, principal) }, requestId); }
function sendJson(res, status, payload, requestId, additionalHeaders = {}) { res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'x-request-id': requestId, ...additionalHeaders }); res.end(JSON.stringify(payload)); }
