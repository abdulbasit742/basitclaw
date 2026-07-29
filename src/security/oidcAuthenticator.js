import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';

const ROLE_NAMES = new Set(['audit_viewer', 'auditor', 'audit_manager', 'compliance_admin']);
const DEFAULT_ALLOWED_ALGORITHMS = Object.freeze(['RS256']);

export class OidcAuthenticationError extends Error {
  constructor(message = 'A valid federated access token is required.', { code = 'OIDC_UNAUTHENTICATED', details = {} } = {}) {
    super(message);
    this.name = 'OidcAuthenticationError';
    this.code = code;
    this.details = details;
  }
}

export class OidcUnavailableError extends Error {
  constructor(message = 'The enterprise identity provider is unavailable.', details = {}) {
    super(message);
    this.name = 'OidcUnavailableError';
    this.code = 'OIDC_UNAVAILABLE';
    this.details = details;
  }
}

export function createOidcAuthenticator({
  issuer,
  audience,
  jwksUri,
  staticJwks = null,
  groupRoleMap,
  tenantClaim = 'tenant_id',
  groupsClaim = 'groups',
  allowedTenants = [],
  allowedAlgorithms = DEFAULT_ALLOWED_ALGORITHMS,
  requiredAcr = [],
  requiredAmr = [],
  clockSkewSeconds = 60,
  maximumTokenLifetimeSeconds = 3600,
  jwksCacheSeconds = 900,
  jwksStaleSeconds = 3600,
  jwksTimeoutMs = 5000,
  allowPrivateJwks = false,
  fetchImpl = globalThis.fetch,
  now = () => new Date()
} = {}) {
  const expectedIssuer = exactUrl(issuer, 'OIDC issuer');
  const expectedAudiences = normaliseStringList(audience, 'OIDC audience', 1, 20);
  const endpoint = staticJwks ? null : validateJwksUri(jwksUri, { allowPrivate: allowPrivateJwks });
  const roleMap = normaliseGroupRoleMap(groupRoleMap);
  const tenantClaimName = safeClaimName(tenantClaim, 'tenantClaim');
  const groupsClaimName = safeClaimName(groupsClaim, 'groupsClaim');
  const tenantAllowlist = new Set(normaliseStringList(allowedTenants, 'allowedTenants', 0, 1000));
  const algorithms = new Set(normaliseAlgorithms(allowedAlgorithms));
  const acrValues = new Set(normaliseStringList(requiredAcr, 'requiredAcr', 0, 20));
  const amrValues = new Set(normaliseStringList(requiredAmr, 'requiredAmr', 0, 20));
  const skewMs = integer(clockSkewSeconds, 'clockSkewSeconds', 0, 600) * 1000;
  const maxLifetime = integer(maximumTokenLifetimeSeconds, 'maximumTokenLifetimeSeconds', 60, 86_400);
  const cacheMs = integer(jwksCacheSeconds, 'jwksCacheSeconds', 30, 86_400) * 1000;
  const staleMs = integer(jwksStaleSeconds, 'jwksStaleSeconds', 0, 604_800) * 1000;
  const timeoutMs = integer(jwksTimeoutMs, 'jwksTimeoutMs', 500, 30_000);
  if (!staticJwks && typeof fetchImpl !== 'function') throw new TypeError('OIDC JWKS retrieval requires fetch support.');

  let cache = staticJwks
    ? buildJwksCache(staticJwks, now(), Number.POSITIVE_INFINITY, Number.POSITIVE_INFINITY)
    : { keys: new Map(), fetchedAt: null, expiresAt: 0, staleUntil: 0 };
  let lastError = null;
  let refreshPromise = null;

  async function authenticateToken(token) {
    const parsed = parseJwt(token);
    const current = now();
    if (!algorithms.has(parsed.header.alg)) {
      throw authError('The token signing algorithm is not allowed.', 'OIDC_ALGORITHM_NOT_ALLOWED', { algorithm: parsed.header.alg });
    }
    if (!parsed.header.kid) throw authError('The token signing key ID is missing.', 'OIDC_KEY_ID_REQUIRED');

    let key = await resolveKey(parsed.header.kid, current, false);
    if (!key) key = await resolveKey(parsed.header.kid, current, true);
    if (!key) throw authError('The token signing key is unknown.', 'OIDC_SIGNING_KEY_UNKNOWN', { keyId: parsed.header.kid });
    if (key.alg && key.alg !== parsed.header.alg) {
      throw authError('The token signing key algorithm does not match the token.', 'OIDC_KEY_ALGORITHM_MISMATCH', { keyId: parsed.header.kid });
    }
    verifyJwtSignature(parsed, key, parsed.header.alg);
    const claims = validateClaims(parsed.payload, current);
    const role = mapRole(claimValue(claims, groupsClaimName));
    const tenantId = mapTenant(claimValue(claims, tenantClaimName));
    validateAssuranceClaims(claims);

    const subjectClaim = String(claims.sub ?? '');
    const subjectHash = createHash('sha256').update(`${expectedIssuer}|${subjectClaim}`).digest('hex');
    const subject = `oidc-${subjectHash.slice(0, 24)}`;
    return Object.freeze({
      subject,
      externalSubjectHash: subjectHash.slice(0, 24),
      tenantId,
      role,
      issuer: expectedIssuer,
      audience: matchedAudience(claims.aud, expectedAudiences),
      authMethod: 'oidc',
      signingKeyId: safeIdentifier(parsed.header.kid, 'kid'),
      keyId: `oidc-${safeIdentifier(parsed.header.kid, 'kid')}-${subjectHash.slice(0, 12)}`,
      credentialStatus: 'federated',
      credentialExpiresAt: new Date(Number(claims.exp) * 1000).toISOString(),
      rotationRequired: false,
      authenticationContext: {
        acr: claims.acr ? String(claims.acr).slice(0, 128) : null,
        amr: normaliseClaimList(claims.amr).slice(0, 20)
      }
    });
  }

  function validateClaims(claims, current) {
    if (!claims || typeof claims !== 'object' || Array.isArray(claims)) throw authError('The token claims are invalid.', 'OIDC_CLAIMS_INVALID');
    if (claims.iss !== expectedIssuer) throw authError('The token issuer is invalid.', 'OIDC_ISSUER_INVALID');
    if (!audienceMatches(claims.aud, expectedAudiences)) throw authError('The token audience is invalid.', 'OIDC_AUDIENCE_INVALID');
    const sub = String(claims.sub ?? '');
    if (!sub || sub.length > 512) throw authError('The token subject is invalid.', 'OIDC_SUBJECT_INVALID');
    const exp = numericDate(claims.exp, 'exp', true);
    const iat = numericDate(claims.iat, 'iat', true);
    const nbf = numericDate(claims.nbf, 'nbf', false);
    const currentMs = current.getTime();
    if (currentMs >= exp * 1000 + skewMs) throw authError('The federated access token has expired.', 'OIDC_TOKEN_EXPIRED', { expiresAt: new Date(exp * 1000).toISOString() });
    if (nbf !== null && currentMs + skewMs < nbf * 1000) throw authError('The federated access token is not active yet.', 'OIDC_TOKEN_NOT_ACTIVE');
    if (iat * 1000 > currentMs + skewMs) throw authError('The federated access token was issued in the future.', 'OIDC_ISSUED_AT_INVALID');
    if (exp <= iat || exp - iat > maxLifetime) throw authError('The federated access token lifetime is not allowed.', 'OIDC_TOKEN_LIFETIME_INVALID');
    return claims;
  }

  function mapRole(value) {
    const groups = normaliseClaimList(value);
    if (groups.length > 500) throw authError('The identity contains too many group claims.', 'OIDC_GROUPS_INVALID');
    const roles = new Set(groups.map((group) => roleMap.get(group)).filter(Boolean));
    if (roles.size === 0) throw authError('No workforce-audit role is mapped for this identity.', 'OIDC_ROLE_NOT_MAPPED');
    if (roles.size > 1) throw authError('The identity maps to multiple workforce-audit roles.', 'OIDC_ROLE_AMBIGUOUS', { roles: [...roles].sort() });
    return [...roles][0];
  }

  function mapTenant(value) {
    const tenantId = safeIdentifier(value, tenantClaimName);
    if (tenantAllowlist.size > 0 && !tenantAllowlist.has(tenantId)) {
      throw authError('The federated tenant is not allowed.', 'OIDC_TENANT_NOT_ALLOWED', { tenantId });
    }
    return tenantId;
  }

  function validateAssuranceClaims(claims) {
    if (acrValues.size > 0 && !acrValues.has(String(claims.acr ?? ''))) {
      throw authError('The required authentication context was not satisfied.', 'OIDC_ACR_REQUIRED');
    }
    const methods = new Set(normaliseClaimList(claims.amr));
    for (const required of amrValues) {
      if (!methods.has(required)) throw authError('The required authentication method was not satisfied.', 'OIDC_AMR_REQUIRED', { required });
    }
  }

  async function resolveKey(kid, current, forceRefresh) {
    if (staticJwks) return cache.keys.get(kid) ?? null;
    if (!forceRefresh && cache.keys.has(kid) && current.getTime() < cache.expiresAt) return cache.keys.get(kid);
    if (forceRefresh || current.getTime() >= cache.expiresAt || !cache.keys.has(kid)) {
      try { await refreshKeys(forceRefresh); } catch (error) {
        if (cache.keys.has(kid) && current.getTime() <= cache.staleUntil) return cache.keys.get(kid);
        throw error;
      }
    }
    return cache.keys.get(kid) ?? null;
  }

  async function refreshKeys(forceRefresh = false) {
    if (refreshPromise) return refreshPromise;
    if (!forceRefresh && cache.fetchedAt && now().getTime() < cache.expiresAt) return cache;
    refreshPromise = (async () => {
      try {
        const response = await fetchImpl(endpoint, {
          method: 'GET',
          headers: { accept: 'application/json' },
          redirect: 'error',
          signal: AbortSignal.timeout(timeoutMs)
        });
        if (!response.ok) throw new Error(`JWKS endpoint returned HTTP ${response.status}.`);
        const body = await readJsonResponse(response);
        const current = now();
        const responseTtl = cacheControlMaxAge(response.headers?.get?.('cache-control'));
        const effectiveCacheMs = responseTtl === null ? cacheMs : Math.min(cacheMs, responseTtl * 1000);
        cache = buildJwksCache(body, current, effectiveCacheMs, effectiveCacheMs + staleMs);
        lastError = null;
        return cache;
      } catch (error) {
        lastError = error.message;
        throw new OidcUnavailableError('The identity provider signing keys could not be refreshed.', { cause: error.message });
      } finally {
        refreshPromise = null;
      }
    })();
    return refreshPromise;
  }

  function health() {
    const currentMs = now().getTime();
    const cachedKeys = cache.keys.size;
    const stale = cache.fetchedAt && currentMs > cache.expiresAt;
    const unavailable = lastError && (!cachedKeys || currentMs > cache.staleUntil);
    return {
      status: unavailable ? 'unavailable' : 'ready',
      enabled: true,
      mode: 'oidc-jwks-bearer',
      issuerOrigin: new URL(expectedIssuer).origin,
      audienceCount: expectedAudiences.length,
      allowedAlgorithms: [...algorithms],
      cachedKeys,
      cacheState: staticJwks ? 'static' : !cache.fetchedAt ? 'cold' : stale ? 'stale' : 'fresh',
      fetchedAt: cache.fetchedAt?.toISOString() ?? null,
      expiresAt: Number.isFinite(cache.expiresAt) ? new Date(cache.expiresAt).toISOString() : null,
      staleUntil: Number.isFinite(cache.staleUntil) ? new Date(cache.staleUntil).toISOString() : null,
      allowedTenants: tenantAllowlist.size,
      mappedGroups: roleMap.size,
      requiredAcrCount: acrValues.size,
      requiredAmrCount: amrValues.size,
      lastError
    };
  }

  return { authenticateToken, health, refresh: () => refreshKeys(true), issuer: expectedIssuer };
}

export function createOidcAuthenticatorFromEnvironment(env = process.env, options = {}) {
  const allowedTenants = parseJsonOrCsv(env.WORKFORCE_AUDIT_OIDC_ALLOWED_TENANTS);
  const allowAnyTenant = String(env.WORKFORCE_AUDIT_OIDC_ALLOW_ANY_TENANT ?? 'false') === 'true';
  if (env.NODE_ENV === 'production' && allowedTenants.length === 0 && !allowAnyTenant) {
    throw new TypeError('WORKFORCE_AUDIT_OIDC_ALLOWED_TENANTS is required in production unless WORKFORCE_AUDIT_OIDC_ALLOW_ANY_TENANT=true.');
  }
  return createOidcAuthenticator({
    issuer: env.WORKFORCE_AUDIT_OIDC_ISSUER,
    audience: parseJsonOrCsv(env.WORKFORCE_AUDIT_OIDC_AUDIENCE),
    jwksUri: env.WORKFORCE_AUDIT_OIDC_JWKS_URI,
    staticJwks: parseOptionalJson(env.WORKFORCE_AUDIT_OIDC_STATIC_JWKS, 'WORKFORCE_AUDIT_OIDC_STATIC_JWKS'),
    groupRoleMap: parseRequiredJson(env.WORKFORCE_AUDIT_OIDC_GROUP_ROLE_MAP, 'WORKFORCE_AUDIT_OIDC_GROUP_ROLE_MAP'),
    tenantClaim: env.WORKFORCE_AUDIT_OIDC_TENANT_CLAIM ?? 'tenant_id',
    groupsClaim: env.WORKFORCE_AUDIT_OIDC_GROUPS_CLAIM ?? 'groups',
    allowedTenants,
    allowedAlgorithms: parseJsonOrCsv(env.WORKFORCE_AUDIT_OIDC_ALLOWED_ALGORITHMS ?? 'RS256'),
    requiredAcr: parseJsonOrCsv(env.WORKFORCE_AUDIT_OIDC_REQUIRED_ACR),
    requiredAmr: parseJsonOrCsv(env.WORKFORCE_AUDIT_OIDC_REQUIRED_AMR),
    clockSkewSeconds: Number(env.WORKFORCE_AUDIT_OIDC_CLOCK_SKEW_SECONDS ?? 60),
    maximumTokenLifetimeSeconds: Number(env.WORKFORCE_AUDIT_OIDC_MAX_TOKEN_LIFETIME_SECONDS ?? 3600),
    jwksCacheSeconds: Number(env.WORKFORCE_AUDIT_OIDC_JWKS_CACHE_SECONDS ?? 900),
    jwksStaleSeconds: Number(env.WORKFORCE_AUDIT_OIDC_JWKS_STALE_SECONDS ?? 3600),
    jwksTimeoutMs: Number(env.WORKFORCE_AUDIT_OIDC_JWKS_TIMEOUT_MS ?? 5000),
    allowPrivateJwks: String(env.WORKFORCE_AUDIT_OIDC_ALLOW_PRIVATE_JWKS ?? 'false') === 'true',
    ...options
  });
}

export function parseJwt(token) {
  const raw = String(token ?? '').trim();
  if (raw.length === 0 || raw.length > 16_384) throw authError('The federated access token is malformed.', 'OIDC_TOKEN_MALFORMED');
  const parts = raw.split('.');
  if (parts.length !== 3 || parts.some((part) => !part)) throw authError('The federated access token is malformed.', 'OIDC_TOKEN_MALFORMED');
  let header;
  let payload;
  try {
    header = JSON.parse(decodeBase64Url(parts[0]).toString('utf8'));
    payload = JSON.parse(decodeBase64Url(parts[1]).toString('utf8'));
  } catch {
    throw authError('The federated access token could not be decoded.', 'OIDC_TOKEN_MALFORMED');
  }
  if (!header || typeof header !== 'object' || Array.isArray(header)) throw authError('The token header is invalid.', 'OIDC_TOKEN_MALFORMED');
  if (header.crit !== undefined) throw authError('Critical JWT extensions are not supported.', 'OIDC_CRITICAL_HEADER_UNSUPPORTED');
  if (header.jku !== undefined || header.jwk !== undefined || header.x5u !== undefined) throw authError('JWT header-supplied signing keys are not allowed.', 'OIDC_HEADER_KEY_REFERENCE_FORBIDDEN');
  if (header.typ !== undefined && !['JWT', 'at+jwt'].includes(String(header.typ))) throw authError('The JWT type is not allowed.', 'OIDC_TOKEN_TYPE_INVALID');
  const alg = String(header.alg ?? '');
  if (!alg || alg.toLowerCase() === 'none' || alg.startsWith('HS')) throw authError('The token signing algorithm is not allowed.', 'OIDC_ALGORITHM_NOT_ALLOWED');
  const signature = decodeBase64Url(parts[2]);
  const kid = header.kid ? safeIdentifier(header.kid, 'kid') : null;
  return { raw, parts, header: { ...header, alg, kid }, payload, signature, signingInput: Buffer.from(`${parts[0]}.${parts[1]}`, 'ascii') };
}

function verifyJwtSignature(parsed, jwk, algorithm) {
  if (algorithm === 'RS256' && jwk.kty !== 'RSA') throw authError('The token signing key type is invalid.', 'OIDC_SIGNING_KEY_INVALID', { keyId: parsed.header.kid });
  if (algorithm === 'ES256' && (jwk.kty !== 'EC' || jwk.crv !== 'P-256')) {
    throw authError('The token signing key type is invalid.', 'OIDC_SIGNING_KEY_INVALID', { keyId: parsed.header.kid });
  }
  let key;
  try {
    key = createPublicKey({ key: jwk, format: 'jwk' });
    if (algorithm === 'RS256' && Number(key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) {
      throw new Error('RSA key is too small.');
    }
    const options = algorithm === 'ES256' ? { key, dsaEncoding: 'ieee-p1363' } : key;
    const verifier = algorithm === 'RS256' ? 'RSA-SHA256' : algorithm === 'ES256' ? 'sha256' : null;
    if (!verifier || !verifySignature(verifier, parsed.signingInput, options, parsed.signature)) {
      throw authError('The federated access token signature is invalid.', 'OIDC_SIGNATURE_INVALID', { keyId: parsed.header.kid });
    }
  } catch (error) {
    if (error instanceof OidcAuthenticationError) throw error;
    throw authError('The token signing key is invalid.', 'OIDC_SIGNING_KEY_INVALID', { keyId: parsed.header.kid });
  }
}

function buildJwksCache(value, current, expiresInMs, staleInMs) {
  const keys = normaliseJwks(value);
  return {
    keys,
    fetchedAt: current,
    expiresAt: Number.isFinite(expiresInMs) ? current.getTime() + expiresInMs : Number.POSITIVE_INFINITY,
    staleUntil: Number.isFinite(staleInMs) ? current.getTime() + staleInMs : Number.POSITIVE_INFINITY
  };
}

function normaliseJwks(value) {
  if (!value || typeof value !== 'object' || !Array.isArray(value.keys)) throw new TypeError('OIDC JWKS must contain a keys array.');
  const output = new Map();
  for (const jwk of value.keys) {
    if (!jwk || typeof jwk !== 'object' || Array.isArray(jwk)) continue;
    if (jwk.use && jwk.use !== 'sig') continue;
    if (Array.isArray(jwk.key_ops) && !jwk.key_ops.includes('verify')) continue;
    if (!['RSA', 'EC'].includes(jwk.kty)) continue;
    const kid = safeIdentifier(jwk.kid, 'kid');
    if (output.has(kid)) throw new TypeError('OIDC JWKS contains duplicate key IDs.');
    output.set(kid, structuredClone(jwk));
  }
  if (output.size === 0) throw new TypeError('OIDC JWKS contains no usable signing keys.');
  return output;
}

function normaliseGroupRoleMap(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('OIDC group-to-role mapping must be an object.');
  const map = new Map();
  for (const [group, roleValue] of Object.entries(value)) {
    const safeGroup = String(group).trim();
    if (!safeGroup || safeGroup.length > 256) throw new TypeError('OIDC group names must be non-empty and at most 256 characters.');
    const role = String(roleValue);
    if (!ROLE_NAMES.has(role)) throw new TypeError(`Unsupported workforce-audit role in OIDC mapping: ${role}`);
    map.set(safeGroup, role);
  }
  if (map.size === 0) throw new TypeError('At least one OIDC group-to-role mapping is required.');
  return map;
}

function normaliseAlgorithms(value) {
  const algorithms = normaliseStringList(value, 'allowedAlgorithms', 1, 10);
  for (const algorithm of algorithms) {
    if (!['RS256', 'ES256'].includes(algorithm)) throw new TypeError(`Unsupported OIDC signing algorithm: ${algorithm}`);
  }
  return algorithms;
}

function normaliseStringList(value, field, minimum, maximum) {
  if (value === undefined || value === null || value === '') value = [];
  if (typeof value === 'string') value = value.split(',');
  if (!Array.isArray(value)) throw new TypeError(`${field} must be an array or comma-separated string.`);
  const output = [...new Set(value.map((item) => String(item).trim()).filter(Boolean))];
  if (output.length < minimum || output.length > maximum) throw new TypeError(`${field} must contain from ${minimum} to ${maximum} values.`);
  return output;
}

function normaliseClaimList(value) {
  if (Array.isArray(value)) return value.map((item) => String(item)).filter(Boolean);
  if (typeof value === 'string') return value.split(/[ ,]+/).map((item) => item.trim()).filter(Boolean);
  return [];
}

function audienceMatches(value, expected) {
  const actual = new Set(normaliseClaimList(value));
  return expected.some((audience) => actual.has(audience));
}

function matchedAudience(value, expected) {
  const actual = new Set(normaliseClaimList(value));
  return expected.find((audience) => actual.has(audience)) ?? null;
}

function numericDate(value, field, required) {
  if (value === undefined || value === null) {
    if (required) throw authError(`The token ${field} claim is required.`, `OIDC_${field.toUpperCase()}_REQUIRED`);
    return null;
  }
  const number = Number(value);
  if (!Number.isInteger(number) || number < 0) throw authError(`The token ${field} claim is invalid.`, `OIDC_${field.toUpperCase()}_INVALID`);
  return number;
}

function authError(message, code, details = {}) {
  return new OidcAuthenticationError(message, { code, details });
}

function decodeBase64Url(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('invalid base64url');
  return Buffer.from(value, 'base64url');
}

function exactUrl(value, field) {
  let url;
  try { url = new URL(String(value ?? '')); } catch { throw new TypeError(`${field} must be a valid URL.`); }
  if (url.protocol !== 'https:') throw new TypeError(`${field} must use HTTPS.`);
  if (url.username || url.password || url.hash || url.search) throw new TypeError(`${field} must not contain user information, query parameters, or fragments.`);
  return url.toString().replace(/\/$/, '');
}

function validateJwksUri(value, { allowPrivate = false } = {}) {
  const url = exactUrl(value, 'OIDC JWKS URI');
  const hostname = new URL(url).hostname.toLowerCase();
  if (!allowPrivate && isPrivateHostname(hostname)) throw new TypeError('OIDC JWKS URI must not target a private or local address.');
  return url;
}

function isPrivateHostname(hostname) {
  if (hostname === 'localhost' || hostname.endsWith('.localhost') || hostname.endsWith('.local') || hostname === '::1' || hostname === '[::1]') return true;
  const ipv4 = hostname.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!ipv4) return false;
  const [a, b] = ipv4.slice(1).map(Number);
  return a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

function safeClaimName(value, field) {
  const name = String(value ?? '').trim();
  if (!/^[A-Za-z_][A-Za-z0-9_.:-]{0,127}$/.test(name)) throw new TypeError(`${field} must be a safe claim name.`);
  return name;
}

function safeIdentifier(value, field) {
  const identifier = String(value ?? '').trim();
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/.test(identifier)) throw new TypeError(`${field} must be a safe identifier.`);
  return identifier;
}

function integer(value, field, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) throw new TypeError(`${field} must be an integer from ${minimum} to ${maximum}.`);
  return parsed;
}

function cacheControlMaxAge(value) {
  const match = String(value ?? '').match(/(?:^|,)\s*max-age=(\d+)\s*(?:,|$)/i);
  return match ? Number(match[1]) : null;
}

function claimValue(claims, path) {
  let current = claims;
  for (const segment of String(path).split('.')) {
    if (['__proto__', 'prototype', 'constructor'].includes(segment)) throw authError('The configured claim path is unsafe.', 'OIDC_CLAIM_PATH_INVALID');
    if (!current || typeof current !== 'object' || Array.isArray(current) || !Object.prototype.hasOwnProperty.call(current, segment)) return undefined;
    current = current[segment];
  }
  return current;
}

async function readJsonResponse(response) {
  if (typeof response.text === 'function') {
    const text = await response.text();
    if (Buffer.byteLength(text, 'utf8') > 1_000_000) throw new Error('JWKS response exceeds the 1 MB limit.');
    try { return JSON.parse(text); } catch { throw new Error('JWKS endpoint returned invalid JSON.'); }
  }
  if (typeof response.json === 'function') return response.json();
  throw new Error('JWKS endpoint returned an unreadable response.');
}

function parseOptionalJson(raw, field) {
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { throw new TypeError(`${field} must contain valid JSON.`); }
}

function parseRequiredJson(raw, field) {
  const value = parseOptionalJson(raw, field);
  if (!value) throw new TypeError(`${field} is required when OIDC authentication is enabled.`);
  return value;
}

function parseJsonOrCsv(raw) {
  if (!raw) return [];
  const value = String(raw).trim();
  if (value.startsWith('[')) return parseOptionalJson(value, 'OIDC list configuration');
  return value.split(',').map((item) => item.trim()).filter(Boolean);
}
