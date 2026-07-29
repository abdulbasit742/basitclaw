import { randomUUID } from 'node:crypto';
import { deriveFederatedSubject } from './federatedIdentity.js';
import {
  IdentityEntitlementConflictError,
  IdentityEntitlementError,
  IdentityEntitlementStoreError
} from './identityEntitlementRegistry.js';
import { ScimAuthenticationError, ScimAuthorizationError } from './scimAccessController.js';
import { RateLimitStoreError } from './sharedRateLimiter.js';

const CORE_USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User';
const PATCH_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
const LIST_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:ListResponse';
const ERROR_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:Error';
export const WORKFORCE_EXTENSION = 'urn:basitclaw:params:scim:schemas:extension:workforce-audit:2.0:User';

export function createScimHandler({
  registry,
  accessController,
  issuer,
  rateLimiter = null,
  securityTelemetry = null
} = {}) {
  if (!registry || typeof registry.upsert !== 'function') throw new TypeError('A writable identity entitlement registry is required.');
  if (!accessController || typeof accessController.authenticate !== 'function') throw new TypeError('A SCIM access controller is required.');
  const expectedIssuer = exactIssuer(issuer);

  async function handle(req, res) {
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (!url.pathname.startsWith('/scim/v2/')) return false;
    const requestId = randomUUID();
    const clientAddress = rateLimiter?.clientAddress?.(req) ?? 'unknown';
    let principal = null;
    try {
      const burst = rateLimiter?.consume?.(`scim-client:${clientAddress}`, 'burst');
      if (burst) {
        applyRateDecision(res, rateLimiter, burst);
        if (!burst.allowed) return scimError(res, 429, 'tooMany', 'The SCIM request burst limit has been exceeded.', requestId, { 'retry-after': String(burst.retryAfterSeconds ?? 1) });
      }

      try { principal = accessController.authenticate(req); }
      catch (error) {
        if (error instanceof ScimAuthenticationError) {
          const failed = rateLimiter?.consume?.(`scim-authentication:${clientAddress}`, 'authFailure');
          if (failed) {
            applyRateDecision(res, rateLimiter, failed);
            if (!failed.allowed) return scimError(res, 429, 'tooMany', 'Too many failed SCIM authentication attempts.', requestId, { 'retry-after': String(failed.retryAfterSeconds ?? 1) });
          }
          record(securityTelemetry, {
            type: 'scim.authentication_failed', severity: 'high', outcome: 'denied', requestId,
            clientAddress, method: req.method, route: url.pathname, details: { reason: error.code }
          });
        }
        throw error;
      }

      const scope = req.method === 'GET' ? 'scim:read' : 'scim:write';
      accessController.authorise(principal, scope);
      const decision = rateLimiter?.consume?.(`scim-credential:${principal.keyId}:client:${clientAddress}`, req.method === 'GET' ? 'read' : 'write');
      if (decision) {
        applyRateDecision(res, rateLimiter, decision);
        if (!decision.allowed) return scimError(res, 429, 'tooMany', 'The SCIM credential rate limit has been exceeded.', requestId, { 'retry-after': String(decision.retryAfterSeconds ?? 1) });
      }

      if (req.method === 'GET' && url.pathname === '/scim/v2/ServiceProviderConfig') {
        return scimJson(res, 200, serviceProviderConfig(), requestId);
      }
      if (req.method === 'GET' && url.pathname === '/scim/v2/ResourceTypes') {
        return scimJson(res, 200, listResponse([resourceType()]), requestId);
      }
      if (req.method === 'GET' && url.pathname === '/scim/v2/Schemas') {
        return scimJson(res, 200, listResponse(schemas()), requestId);
      }
      if (req.method === 'GET' && url.pathname === '/scim/v2/Users') {
        const data = listUsers(url.searchParams);
        return scimJson(res, 200, {
          schemas: [LIST_SCHEMA], totalResults: data.totalResults,
          startIndex: data.startIndex, itemsPerPage: data.itemsPerPage,
          Resources: data.resources.map(toScimUser)
        }, requestId);
      }
      if (req.method === 'POST' && url.pathname === '/scim/v2/Users') {
        const body = await readJson(req);
        const recordValue = registry.upsert(provisioningInput(body, expectedIssuer, 0), { actor: principal.subject });
        record(securityTelemetry, event('identity.provisioned', recordValue, requestId, clientAddress, principal));
        return scimJson(res, 201, toScimUser(recordValue), requestId, resourceHeaders(recordValue));
      }

      const match = url.pathname.match(/^\/scim\/v2\/Users\/([^/]+)$/);
      if (!match) return scimError(res, 404, null, 'SCIM resource not found.', requestId);
      const id = decodeURIComponent(match[1]);

      if (req.method === 'GET') {
        const recordValue = registry.get(id);
        return scimJson(res, 200, toScimUser(recordValue), requestId, resourceHeaders(recordValue));
      }
      if (req.method === 'PUT') {
        const current = registry.get(id);
        const expectedVersion = requiredIfMatch(req, current.version);
        const body = await readJson(req);
        const target = provisioningInput(body, expectedIssuer, expectedVersion);
        const expectedSubject = deriveFederatedSubject(target.issuer, target.externalSubject).subject;
        if (expectedSubject !== current.subject) throw new TypeError('SCIM PUT cannot replace the external identity of an existing resource.');
        const updated = registry.upsert(target, { actor: principal.subject });
        record(securityTelemetry, event(updated.active ? 'identity.updated' : 'identity.suspended', updated, requestId, clientAddress, principal));
        return scimJson(res, 200, toScimUser(updated), requestId, resourceHeaders(updated));
      }
      if (req.method === 'PATCH') {
        const current = registry.get(id);
        const expectedVersion = requiredIfMatch(req, current.version);
        const changes = patchChanges(await readJson(req));
        const updated = registry.patch(id, { ...changes, expectedVersion }, { actor: principal.subject });
        record(securityTelemetry, event(updated.active ? 'identity.updated' : 'identity.suspended', updated, requestId, clientAddress, principal));
        return scimJson(res, 200, toScimUser(updated), requestId, resourceHeaders(updated));
      }
      if (req.method === 'DELETE') {
        const current = registry.get(id);
        const expectedVersion = requiredIfMatch(req, current.version);
        const reason = header(req, 'x-basitclaw-change-reason');
        const updated = registry.deactivate(id, { expectedVersion, reason }, { actor: principal.subject });
        record(securityTelemetry, event('identity.deprovisioned', updated, requestId, clientAddress, principal));
        res.writeHead(204, { 'cache-control': 'no-store', 'x-request-id': requestId });
        res.end();
        return true;
      }
      return scimError(res, 405, null, 'SCIM method not allowed.', requestId, { allow: 'GET, POST, PUT, PATCH, DELETE' });
    } catch (error) {
      if (error instanceof ScimAuthenticationError) {
        return scimError(res, 401, null, error.message, requestId, { 'www-authenticate': 'Bearer realm="basitclaw-scim"' });
      }
      if (error instanceof ScimAuthorizationError) return scimError(res, 403, null, error.message, requestId);
      if (error instanceof IdentityEntitlementConflictError) return scimError(res, 409, 'uniqueness', error.message, requestId);
      if (error instanceof IdentityEntitlementError && error.code === 'IDENTITY_ENTITLEMENT_NOT_FOUND') return scimError(res, 404, null, error.message, requestId);
      if (error instanceof IdentityEntitlementStoreError || error instanceof RateLimitStoreError) {
        record(securityTelemetry, {
          type: 'identity_lifecycle.unavailable', severity: 'critical', outcome: 'failed', requestId,
          clientAddress, keyId: principal?.keyId, method: req.method, route: url.pathname,
          details: { reason: error.code }
        });
        return scimError(res, 503, null, error.message, requestId, { 'retry-after': '30' });
      }
      if (error?.code === 'INVALID_JSON' || error instanceof TypeError) return scimError(res, 400, 'invalidValue', error.message, requestId);
      console.error('Unhandled SCIM error', { requestId, error });
      return scimError(res, 500, null, 'Internal server error.', requestId);
    }
  }

  function listUsers(searchParams) {
    const startIndex = numberParam(searchParams.get('startIndex'), 1, 1, Number.MAX_SAFE_INTEGER);
    const count = numberParam(searchParams.get('count'), 100, 1, 500);
    const filter = searchParams.get('filter');
    if (!filter) return registry.list({ startIndex, count });
    const idMatch = filter.match(/^id\s+eq\s+"([A-Za-z0-9._:-]{1,160})"$/i);
    if (idMatch) {
      try { const item = registry.get(idMatch[1]); return { totalResults: 1, startIndex: 1, itemsPerPage: 1, resources: [item] }; }
      catch (error) { if (error.code === 'IDENTITY_ENTITLEMENT_NOT_FOUND') return { totalResults: 0, startIndex: 1, itemsPerPage: 0, resources: [] }; throw error; }
    }
    const externalMatch = filter.match(/^externalId\s+eq\s+"([^"\\]{1,512})"$/i);
    if (externalMatch) {
      const subject = deriveFederatedSubject(expectedIssuer, externalMatch[1]).subject;
      const item = registry.getBySubject(subject);
      return { totalResults: item ? 1 : 0, startIndex: 1, itemsPerPage: item ? 1 : 0, resources: item ? [item] : [] };
    }
    const activeMatch = filter.match(/^active\s+eq\s+(true|false)$/i);
    if (activeMatch) return registry.list({ startIndex, count, active: activeMatch[1].toLowerCase() === 'true' });
    throw new TypeError('Only exact id, externalId, or active SCIM filters are supported.');
  }

  return { handle, health: () => ({ registry: registry.health(), credentials: accessController.health() }) };
}

function provisioningInput(body, issuer, expectedVersion) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new TypeError('SCIM User payload must be an object.');
  const extension = body[WORKFORCE_EXTENSION];
  if (!extension || typeof extension !== 'object' || Array.isArray(extension)) throw new TypeError(`SCIM User payload requires ${WORKFORCE_EXTENSION}.`);
  return {
    issuer,
    externalSubject: requiredText(body.externalId, 'externalId', 512),
    tenantId: extension.tenantId,
    role: extension.role,
    active: body.active !== false,
    displayName: body.displayName ?? body.name?.formatted ?? null,
    reviewBy: extension.reviewBy,
    reason: extension.reason,
    source: 'scim',
    expectedVersion
  };
}

function patchChanges(body) {
  if (!body || !Array.isArray(body.schemas) || !body.schemas.includes(PATCH_SCHEMA) || !Array.isArray(body.Operations)) {
    throw new TypeError('SCIM PATCH requires the PatchOp schema and Operations array.');
  }
  if (body.Operations.length < 1 || body.Operations.length > 20) throw new TypeError('SCIM PATCH must contain from 1 to 20 operations.');
  const changes = {};
  for (const operation of body.Operations) {
    if (String(operation.op ?? '').toLowerCase() !== 'replace') throw new TypeError('Only SCIM replace operations are supported.');
    if (operation.path) applyPatchValue(changes, operation.path, operation.value);
    else if (operation.value && typeof operation.value === 'object' && !Array.isArray(operation.value)) {
      for (const [path, value] of Object.entries(operation.value)) applyPatchValue(changes, path, value);
    } else throw new TypeError('SCIM replace operations require a path or object value.');
  }
  if (!changes.reason) throw new TypeError('SCIM PATCH requires a governance reason in the workforce extension.');
  return changes;
}

function applyPatchValue(changes, pathValue, value) {
  const path = String(pathValue).trim();
  if (path.toLowerCase() === 'active') { changes.active = Boolean(value); return; }
  if (path === WORKFORCE_EXTENSION) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('SCIM workforce extension replacement must be an object.');
    for (const [field, nestedValue] of Object.entries(value)) applyPatchValue(changes, `${WORKFORCE_EXTENSION}:${field}`, nestedValue);
    return;
  }
  const prefix = `${WORKFORCE_EXTENSION}:`;
  if (!path.startsWith(prefix)) throw new TypeError(`Unsupported SCIM PATCH path: ${path}`);
  const field = path.slice(prefix.length);
  if (!['tenantId', 'role', 'reviewBy', 'reason'].includes(field)) throw new TypeError(`Unsupported SCIM workforce extension path: ${field}`);
  changes[field] = value;
}

function toScimUser(record) {
  return {
    schemas: [CORE_USER_SCHEMA, WORKFORCE_EXTENSION],
    id: record.id,
    active: record.active,
    displayName: record.displayName ?? undefined,
    meta: {
      resourceType: 'User', created: record.createdAt, lastModified: record.updatedAt,
      version: `W/"${record.version}"`, location: `/scim/v2/Users/${encodeURIComponent(record.id)}`
    },
    [WORKFORCE_EXTENSION]: {
      tenantId: record.tenantId,
      role: record.role,
      reviewBy: record.reviewBy,
      entitlementStatus: record.active ? 'active' : 'suspended'
    }
  };
}

function serviceProviderConfig() {
  return {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
    patch: { supported: true }, bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
    filter: { supported: true, maxResults: 500 }, changePassword: { supported: false },
    sort: { supported: false }, etag: { supported: true },
    authenticationSchemes: [{ type: 'oauthbearertoken', name: 'Bearer Token', description: 'Lifecycle-managed SCIM bearer credential', primary: true }]
  };
}

function resourceType() {
  return {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'], id: 'User', name: 'User', endpoint: '/Users', schema: CORE_USER_SCHEMA,
    schemaExtensions: [{ schema: WORKFORCE_EXTENSION, required: true }]
  };
}

function schemas() {
  return [
    { schemas: ['urn:ietf:params:scim:schemas:core:2.0:Schema'], id: CORE_USER_SCHEMA, name: 'User', description: 'BasitClaw federated workforce identity', attributes: [] },
    { schemas: ['urn:ietf:params:scim:schemas:core:2.0:Schema'], id: WORKFORCE_EXTENSION, name: 'WorkforceAuditUser', description: 'Approved tenant, role, and review lifecycle', attributes: [] }
  ];
}

function listResponse(resources) { return { schemas: [LIST_SCHEMA], totalResults: resources.length, startIndex: 1, itemsPerPage: resources.length, Resources: resources }; }
function resourceHeaders(record) { return { etag: `W/"${record.version}"`, location: `/scim/v2/Users/${encodeURIComponent(record.id)}` }; }
function requiredIfMatch(req, actualVersion) {
  const value = header(req, 'if-match');
  if (!value) throw new IdentityEntitlementConflictError('SCIM updates require If-Match.', { actualVersion });
  const match = value.match(/^(?:W\/)?"(\d+)"$/);
  if (!match) throw new TypeError('If-Match must contain a SCIM resource version.');
  const expected = Number(match[1]);
  if (expected !== actualVersion) throw new IdentityEntitlementConflictError(undefined, { expectedVersion: expected, actualVersion });
  return expected;
}

async function readJson(req) {
  const contentType = String(req.headers?.['content-type'] ?? '').split(';')[0].trim().toLowerCase();
  if (contentType && !['application/json', 'application/scim+json'].includes(contentType)) {
    const error = new Error('SCIM requests must use application/scim+json or application/json.'); error.code = 'INVALID_JSON'; throw error;
  }
  const chunks = []; let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 1_000_000) { const error = new Error('SCIM request body exceeds the 1 MB limit.'); error.code = 'INVALID_JSON'; throw error; }
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); }
  catch { const error = new Error('SCIM request body must contain valid JSON.'); error.code = 'INVALID_JSON'; throw error; }
}

function event(type, recordValue, requestId, clientAddress, principal) {
  return { type, severity: type.includes('deprovisioned') || type.includes('suspended') ? 'high' : 'info', outcome: 'succeeded', requestId, clientAddress, keyId: principal.keyId, subject: recordValue.subject, tenantId: recordValue.tenantId, method: 'SCIM', route: '/scim/v2/Users', details: { entitlementId: recordValue.id, version: recordValue.version } };
}
function record(telemetry, value) { try { telemetry?.record?.(value); } catch (error) { console.error('SCIM telemetry record failed', error); } }
function scimJson(res, status, payload, requestId, additional = {}) { res.writeHead(status, { 'content-type': 'application/scim+json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'x-request-id': requestId, ...additional }); res.end(JSON.stringify(payload)); return true; }
function scimError(res, status, scimType, detail, requestId, additional = {}) { return scimJson(res, status, { schemas: [ERROR_SCHEMA], status: String(status), ...(scimType ? { scimType } : {}), detail }, requestId, additional); }
function applyRateDecision(res, limiter, decision) { for (const [name, value] of Object.entries(limiter?.headers?.(decision) ?? {})) res.setHeader(name, value); }
function header(req, name) { const value = req?.headers?.[name]; return Array.isArray(value) ? value[0]?.trim() ?? '' : typeof value === 'string' ? value.trim() : ''; }
function numberParam(value, fallback, min, max) { if (value === null) return fallback; const parsed = Number(value); if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) throw new TypeError(`SCIM numeric parameter must be from ${min} to ${max}.`); return parsed; }
function requiredText(value, field, max) { const text = String(value ?? '').trim(); if (!text || text.length > max) throw new TypeError(`${field} must contain from 1 to ${max} characters.`); return text; }
function exactIssuer(value) { let url; try { url = new URL(String(value ?? '')); } catch { throw new TypeError('SCIM issuer must be a valid URL.'); } if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.search) throw new TypeError('SCIM issuer must be an HTTPS URL without credentials, query, or fragment.'); return url.toString().replace(/\/$/, ''); }
