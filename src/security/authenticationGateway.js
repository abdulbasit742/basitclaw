import {
  AuthenticationError,
  AuthorizationError,
  createAccessController,
  permissionsForRole
} from './accessControl.js';
import {
  OidcAuthenticationError,
  createOidcAuthenticatorFromEnvironment
} from './oidcAuthenticator.js';
import {
  createDisabledIdentityEntitlementRegistry,
  createIdentityEntitlementRegistryFromEnvironment
} from './identityEntitlementRegistry.js';

const AUTH_MODES = new Set(['api-key', 'oidc', 'hybrid']);

export function createAuthenticationGateway({
  mode = 'api-key',
  apiKeyController = null,
  oidcAuthenticator = null,
  oidcAllowedTenants = [],
  entitlementRegistry = null
} = {}) {
  const authenticationMode = String(mode);
  if (!AUTH_MODES.has(authenticationMode)) throw new TypeError('Authentication mode must be api-key, oidc, or hybrid.');
  if (authenticationMode !== 'oidc' && !apiKeyController) throw new TypeError('API-key authentication is required by the configured authentication mode.');
  if (authenticationMode !== 'api-key' && !oidcAuthenticator) throw new TypeError('OIDC authentication is required by the configured authentication mode.');
  const knownOidcTenants = new Set(oidcAllowedTenants.map((value) => String(value).trim()).filter(Boolean));
  const entitlements = entitlementRegistry ?? createDisabledIdentityEntitlementRegistry();

  async function authenticate(req) {
    const apiKey = headerValue(req.headers?.['x-api-key']);
    const bearer = bearerToken(req.headers?.authorization);
    if (apiKey && bearer) {
      throw new AuthenticationError('Exactly one authentication method must be supplied.', {
        code: 'AMBIGUOUS_CREDENTIALS',
        details: { reason: 'multiple_authentication_methods' }
      });
    }

    if (bearer) {
      if (authenticationMode === 'api-key') throw methodDisabled('oidc');
      let principal;
      try { principal = await oidcAuthenticator.authenticateToken(bearer, req); } catch (error) {
        if (error instanceof OidcAuthenticationError) {
          throw new AuthenticationError(error.message, { code: error.code, details: error.details });
        }
        throw error;
      }
      enforceTenantHeader(req, principal);
      const entitled = entitlements.enforce(principal);
      return Object.freeze({
        ...entitled,
        keyId: stableFederatedKeyId(entitled),
        permissions: permissionsForRole(entitled.role)
      });
    }

    if (apiKey) {
      if (authenticationMode === 'oidc') throw methodDisabled('api-key');
      const principal = await apiKeyController.authenticate(req);
      return Object.freeze({ ...principal, authMethod: principal.authMethod ?? 'api_key' });
    }

    throw new AuthenticationError(authenticationMode === 'oidc'
      ? 'A valid OIDC bearer token is required.'
      : authenticationMode === 'hybrid'
        ? 'A valid API key or OIDC bearer token is required.'
        : 'A valid API key is required.');
  }

  function authorise(principal, permission) {
    if (!principal?.permissions?.includes(permission)) {
      throw new AuthorizationError(undefined, {
        reason: 'permission_denied',
        keyId: principal?.keyId ?? null,
        permission
      });
    }
    return principal;
  }

  function tenantIds() {
    const apiTenants = typeof apiKeyController?.tenantIds === 'function' ? apiKeyController.tenantIds() : [];
    const provisionedTenants = typeof entitlements.tenantIds === 'function' ? entitlements.tenantIds() : [];
    return [...new Set([...apiTenants, ...knownOidcTenants, ...provisionedTenants])];
  }

  function credentialHealth() {
    const apiKeys = apiKeyController?.credentialHealth?.() ?? disabledApiKeyHealth();
    const oidc = oidcAuthenticator?.health?.() ?? disabledOidcHealth();
    const identityEntitlements = entitlements.health?.() ?? { status: 'disabled', enabled: false, required: false, mode: 'disabled' };
    const enabledHealth = [
      ...(authenticationMode !== 'oidc' ? [apiKeys.status] : []),
      ...(authenticationMode !== 'api-key' ? [oidc.status] : []),
      ...(identityEntitlements.required ? [identityEntitlements.status] : [])
    ];
    const status = enabledHealth.every((value) => value === 'ready') ? 'ready' : 'unavailable';
    return {
      ...apiKeys,
      status,
      authenticationMode,
      apiKeys,
      oidc,
      identityEntitlements
    };
  }

  return {
    authenticate,
    authorise,
    tenantIds,
    credentialHealth,
    principalCount: apiKeyController?.principalCount ?? 0,
    mode: authenticationMode,
    apiKeyController,
    oidcAuthenticator,
    entitlementRegistry: entitlements
  };
}

export function createAuthenticationGatewayFromEnvironment(env = process.env, options = {}) {
  const mode = String(env.WORKFORCE_AUDIT_AUTH_MODE ?? 'api-key');
  if (!AUTH_MODES.has(mode)) throw new TypeError('WORKFORCE_AUDIT_AUTH_MODE must be api-key, oidc, or hybrid.');
  const apiKeyController = mode === 'oidc' ? null : (options.apiKeyController ?? createAccessController({
    principals: loadApiPrincipals(env),
    allowLegacyPlaintext: env.NODE_ENV !== 'production',
    rotationWarningDays: Number(env.WORKFORCE_AUDIT_CREDENTIAL_WARNING_DAYS ?? 14)
  }));
  const oidcAllowedTenants = parseJsonOrCsv(env.WORKFORCE_AUDIT_OIDC_ALLOWED_TENANTS);
  const oidcAuthenticator = mode === 'api-key' ? null : (options.oidcAuthenticator ?? createOidcAuthenticatorFromEnvironment(env, options.oidcOptions));
  const entitlementRegistry = options.entitlementRegistry ?? createIdentityEntitlementRegistryFromEnvironment(env, options.entitlementOptions);
  return createAuthenticationGateway({ mode, apiKeyController, oidcAuthenticator, oidcAllowedTenants, entitlementRegistry });
}

function loadApiPrincipals(env) {
  const raw = env.WORKFORCE_AUDIT_API_KEYS;
  if (!raw) {
    if (env.NODE_ENV === 'production') throw new Error('WORKFORCE_AUDIT_API_KEYS is required when API-key authentication is enabled in production.');
    return [{ apiKey: 'local-development-key', subject: 'local-admin', tenantId: 'tenant-demo', role: 'compliance_admin' }];
  }
  try { return JSON.parse(raw); } catch { throw new Error('WORKFORCE_AUDIT_API_KEYS must be valid JSON.'); }
}

function stableFederatedKeyId(principal) {
  const externalSubjectHash = String(principal?.externalSubjectHash ?? '').trim();
  if (/^[a-f0-9]{24,64}$/.test(externalSubjectHash)) return `oidc-${externalSubjectHash.slice(0, 24)}`;
  const existing = String(principal?.keyId ?? '').trim();
  if (/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/.test(existing)) return existing;
  throw new AuthenticationError('The federated identity key is invalid.', {
    code: 'OIDC_SUBJECT_INVALID',
    details: { reason: 'invalid_federated_key' }
  });
}

function enforceTenantHeader(req, principal) {
  const requestedTenant = headerValue(req.headers?.['x-tenant-id']);
  if (requestedTenant && requestedTenant !== principal.tenantId) {
    throw new AuthorizationError('Tenant selection is controlled by the authenticated principal.', {
      reason: 'tenant_override',
      keyId: principal.keyId,
      requestedTenant
    });
  }
}

function methodDisabled(method) {
  return new AuthenticationError('The supplied authentication method is disabled.', {
    code: 'AUTHENTICATION_METHOD_DISABLED',
    details: { reason: 'method_disabled', method }
  });
}

function bearerToken(value) {
  const header = headerValue(value);
  if (!header) return '';
  const match = header.match(/^Bearer\s+([^\s]+)$/i);
  if (!match) {
    throw new AuthenticationError('The Authorization header must contain one Bearer token.', {
      code: 'OIDC_AUTHORIZATION_HEADER_INVALID',
      details: { reason: 'invalid_authorization_header' }
    });
  }
  return match[1];
}

function headerValue(value) {
  if (Array.isArray(value)) return value[0]?.trim() ?? '';
  return typeof value === 'string' ? value.trim() : '';
}

function parseJsonOrCsv(raw) {
  if (!raw) return [];
  const value = String(raw).trim();
  if (value.startsWith('[')) {
    try { return JSON.parse(value); } catch { throw new TypeError('OIDC allowed tenants must contain valid JSON or CSV.'); }
  }
  return value.split(',').map((item) => item.trim()).filter(Boolean);
}

function disabledApiKeyHealth() {
  return {
    status: 'disabled', generatedAt: new Date().toISOString(), total: 0, usable: 0,
    active: 0, retiring: 0, revoked: 0, expired: 0, notYetActive: 0,
    legacyPlaintext: 0, rotationRequired: 0, rotationWarningDays: 0, nextExpiryAt: null
  };
}

function disabledOidcHealth() {
  return { status: 'disabled', enabled: false, mode: 'disabled' };
}
