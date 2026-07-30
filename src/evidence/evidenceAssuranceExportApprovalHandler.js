import { randomUUID } from 'node:crypto';
import { AuthenticationError, AuthorizationError } from '../security/accessControl.js';
import { SecurityControlBusyError, SecurityControlUnavailableError } from '../security/fileMutex.js';
import { OidcUnavailableError } from '../security/oidcAuthenticator.js';
import { RateLimitStoreError } from '../security/sharedRateLimiter.js';
import {
  EvidenceConflictError, EvidenceIntegrityError, EvidenceNotFoundError,
  EvidenceStoreError, EvidenceValidationError
} from './evidenceRegistry.js';
import { EvidenceAssuranceBundleStoreError } from './evidenceAssuranceBundleStore.js';
import {
  EvidenceAssuranceExportApprovalRequiredError,
  EvidenceAssuranceExportApprovalStoreError
} from './evidenceAssuranceExportApprovalStore.js';

const STATUS_ROUTE = '/api/workforce-audit/assurance-export-approvals/status';
const REQUESTS_ROUTE = /^\/api\/workforce-audit\/evidence\/([^/]+)\/assurance-export-requests$/;
const REQUEST_ROUTE = /^\/api\/workforce-audit\/assurance-export-requests\/([^/]+)$/;
const ACTION_ROUTE = /^\/api\/workforce-audit\/assurance-export-requests\/([^/]+)\/(approve|reject|cancel)$/;
const BUNDLE_ROUTE = /^\/api\/workforce-audit\/evidence\/([^/]+)\/assurance-bundles$/;

export function createEvidenceAssuranceExportApprovalHandler({ registry, authenticationGateway, rateLimiter = null, securityTelemetry = null } = {}) {
  if (!registry || typeof registry.requestAssuranceExport !== 'function') throw new TypeError('An assurance-export-approval-aware registry is required.');
  if (!authenticationGateway || typeof authenticationGateway.authenticate !== 'function') throw new TypeError('An authentication gateway is required.');

  function matches(pathname, method = 'GET') {
    return pathname === STATUS_ROUTE || REQUESTS_ROUTE.test(pathname) || REQUEST_ROUTE.test(pathname)
      || ACTION_ROUTE.test(pathname) || (method === 'POST' && BUNDLE_ROUTE.test(pathname));
  }

  async function handle(req, res, requestId = randomUUID()) {
    const url = new URL(req.url ?? '/', 'http://localhost');
    const client = typeof rateLimiter?.clientAddress === 'function' ? rateLimiter.clientAddress(req) : 'unknown';
    let principal = null;
    try {
      const burst = rateLimiter?.consume?.(`client:${client}`, 'burst');
      if (burst) { applyRateHeaders(res, rateLimiter, burst); if (!burst.allowed) return rateLimited(res, requestId, burst); }
      try { principal = await authenticationGateway.authenticate(req); }
      catch (error) {
        if (!(error instanceof AuthenticationError)) throw error;
        const failed = rateLimiter?.consume?.(`authentication:${client}`, 'authFailure');
        if (failed) { applyRateHeaders(res, rateLimiter, failed); if (!failed.allowed) return rateLimited(res, requestId, failed); }
        return sendJson(res, 401, { success: false, error: error.message, code: error.code, meta: { requestId } }, requestId, { 'www-authenticate': challenge(authenticationGateway.mode) });
      }

      const route = classify(url.pathname, req.method);
      if (!route) return notFound(res, requestId);
      authenticationGateway.authorise(principal, route.permission);
      const decision = rateLimiter?.consume?.(`credential:${principal.keyId ?? principal.subject}:assurance-export-approvals`, route.write ? 'privileged' : 'read');
      if (decision) { applyRateHeaders(res, rateLimiter, decision); if (!decision.allowed) return rateLimited(res, requestId, decision); }

      let data;
      if (route.kind === 'status') data = registry.assuranceExportApprovalStatus(principal.tenantId);
      else if (route.kind === 'list') data = registry.assuranceExportApprovals(principal.tenantId, { evidenceId: route.evidenceId, state: url.searchParams.get('state'), limit: positiveInteger(url.searchParams.get('limit'), 100, 5000) });
      else if (route.kind === 'get') data = registry.assuranceExportApproval(principal.tenantId, route.requestId);
      else if (route.kind === 'request') {
        const input = await readJson(req, 32_768, new Set(['version', 'recipientId', 'purpose', 'confirmation']));
        data = registry.requestAssuranceExport(principal.tenantId, route.evidenceId, input, { actor: principal.subject });
      } else if (route.kind === 'approve') data = registry.approveAssuranceExport(principal.tenantId, route.requestId, { actor: principal.subject });
      else if (route.kind === 'reject') {
        const input = await readJson(req, 16_384, new Set(['reason']));
        data = registry.rejectAssuranceExport(principal.tenantId, route.requestId, input.reason, { actor: principal.subject });
      } else if (route.kind === 'cancel') data = registry.cancelAssuranceExport(principal.tenantId, route.requestId, { actor: principal.subject });
      else if (route.kind === 'materialize') {
        const input = await readJson(req, 16_384, new Set(['approvalRequestId', 'confirmation']));
        data = registry.createAssuranceBundle(principal.tenantId, route.evidenceId, input, { actor: principal.subject });
      }

      record(securityTelemetry, {
        type: `assurance_export.${route.kind}`,
        severity: route.write ? 'high' : 'info', outcome: 'success', requestId,
        subject: principal.subject, tenantId: principal.tenantId, method: req.method, route: url.pathname,
        details: { requestId: route.requestId ?? data?.request?.requestId ?? data?.approval?.requestId ?? null, evidenceId: route.evidenceId ?? null }
      });
      return sendJson(res, route.kind === 'request' ? (data.duplicate ? 200 : 202) : 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
    } catch (error) {
      if (error instanceof AuthorizationError) return sendJson(res, 403, { success: false, error: error.message, code: error.code, meta: meta(requestId, principal) }, requestId);
      if (error instanceof RateLimitStoreError || error instanceof OidcUnavailableError || error?.code === 'OIDC_UNAVAILABLE') return unavailable(res, requestId, error, principal);
      if (error instanceof SecurityControlBusyError) return sendJson(res, 423, { success: false, error: 'The assurance export approval boundary is busy. Retry the request.', code: 'EVIDENCE_ASSURANCE_EXPORT_APPROVAL_BUSY', details: error.details, meta: meta(requestId, principal) }, requestId, { 'retry-after': String(Math.max(1, Math.ceil((error.details?.retryAfterMs ?? 1000) / 1000))) });
      if (error instanceof SecurityControlUnavailableError) return unavailable(res, requestId, error, principal);
      if (error instanceof EvidenceValidationError || error instanceof EvidenceConflictError || error instanceof EvidenceNotFoundError
          || error instanceof EvidenceIntegrityError || error instanceof EvidenceStoreError || error instanceof EvidenceAssuranceBundleStoreError
          || error instanceof EvidenceAssuranceExportApprovalRequiredError || error instanceof EvidenceAssuranceExportApprovalStoreError) {
        record(securityTelemetry, { type: 'assurance_export.denied', severity: error instanceof EvidenceIntegrityError || error instanceof EvidenceStoreError ? 'critical' : 'high', outcome: 'denied', requestId, subject: principal?.subject, tenantId: principal?.tenantId, method: req.method, route: url.pathname, details: { reason: error.code } });
        return sendJson(res, error.statusCode ?? 500, { success: false, error: error.message, code: error.code, details: error.details, meta: meta(requestId, principal) }, requestId, error.statusCode === 503 ? { 'retry-after': '30' } : {});
      }
      throw error;
    }
  }

  return Object.freeze({ matches, handle, statusRoute: STATUS_ROUTE });
}

function classify(pathname, method) {
  if (pathname === STATUS_ROUTE && method === 'GET') return { kind: 'status', permission: 'governance:read', write: false };
  let match = pathname.match(REQUESTS_ROUTE);
  if (match && method === 'GET') return { kind: 'list', evidenceId: decodeSegment(match[1], 'evidenceId'), permission: 'governance:read', write: false };
  if (match && method === 'POST') return { kind: 'request', evidenceId: decodeSegment(match[1], 'evidenceId'), permission: 'evidence:export-request', write: true };
  match = pathname.match(REQUEST_ROUTE);
  if (match && method === 'GET') return { kind: 'get', requestId: decodeSegment(match[1], 'requestId'), permission: 'governance:read', write: false };
  match = pathname.match(ACTION_ROUTE);
  if (match && method === 'POST') return { kind: match[2], requestId: decodeSegment(match[1], 'requestId'), permission: match[2] === 'cancel' ? 'evidence:export-request' : 'evidence:export-approve', write: true };
  match = pathname.match(BUNDLE_ROUTE);
  if (match && method === 'POST') return { kind: 'materialize', evidenceId: decodeSegment(match[1], 'evidenceId'), permission: 'evidence:export-materialize', write: true };
  return null;
}
async function readBody(req, max) { const contentType=String(req.headers['content-type']??'').split(';')[0].trim().toLowerCase(); if(contentType!=='application/json')throw new EvidenceValidationError('Assurance export approval requests require Content-Type application/json.',{field:'content-type'});const chunks=[];let size=0;for await(const chunk of req){size+=chunk.length;if(size>max)throw new EvidenceValidationError('The assurance export approval request body is too large.',{field:'body'});chunks.push(chunk);}return Buffer.concat(chunks); }
async function readJson(req,max,allowed){const bytes=await readBody(req,max);let input;try{input=JSON.parse(bytes.toString('utf8')||'{}');}catch{throw new EvidenceValidationError('The assurance export approval request must contain valid JSON.',{field:'body'});}if(!input||typeof input!=='object'||Array.isArray(input))throw new EvidenceValidationError('The assurance export approval request body must be an object.',{field:'body'});for(const key of Object.keys(input))if(!allowed.has(key))throw new EvidenceValidationError(`Unsupported assurance export approval field ${key}.`,{field:key});return input;}
function decodeSegment(value,field){try{return decodeURIComponent(value);}catch{throw new EvidenceValidationError(`${field} contains invalid percent encoding.`,{field});}}
function positiveInteger(value,fallback,max){if(value===null)return fallback;const parsed=Number(value);if(!Number.isInteger(parsed)||parsed<1)throw new EvidenceValidationError('limit must be a positive integer.',{field:'limit'});return Math.min(parsed,max);}
function meta(requestId,principal){return{requestId,tenantId:principal?.tenantId??null,keyId:principal?.keyId??null};}
function challenge(mode){return mode==='api-key'?'ApiKey realm="workforce-audit"':mode==='oidc'?'Bearer realm="workforce-audit"':'Bearer realm="workforce-audit", ApiKey realm="workforce-audit"';}
function applyRateHeaders(res,limiter,decision){const headers=typeof limiter?.headers==='function'?limiter.headers(decision):{};for(const[name,value]of Object.entries(headers))res.setHeader(name,value);}
function rateLimited(res,requestId,decision){return sendJson(res,429,{success:false,error:'The assurance export approval rate limit has been exceeded.',code:'RATE_LIMITED',details:decision,meta:{requestId}},requestId,{'retry-after':String(decision.retryAfterSeconds??1)});}
function unavailable(res,requestId,error,principal){return sendJson(res,503,{success:false,error:error.message,code:error.code??'EVIDENCE_ASSURANCE_EXPORT_APPROVAL_STORE_UNAVAILABLE',details:error.details,meta:meta(requestId,principal)},requestId,{'retry-after':'30'});}
function record(telemetry,input){try{telemetry?.record?.(input);}catch(error){console.error('Assurance export approval telemetry failed',error);}}
function notFound(res,requestId){return sendJson(res,404,{success:false,error:'Assurance export approval route not found.',code:'NOT_FOUND',meta:{requestId}},requestId);}
function sendJson(res,status,payload,requestId,extra={}){res.writeHead(status,{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff','x-request-id':requestId,...extra});res.end(JSON.stringify(payload));}
