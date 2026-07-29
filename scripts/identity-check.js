import { fileURLToPath } from 'node:url';
import { createAuthenticationGatewayFromEnvironment } from '../src/security/authenticationGateway.js';
import { createIdentityEntitlementRegistryFromEnvironment } from '../src/security/identityEntitlementRegistry.js';
import { createScimAccessControllerFromEnvironment } from '../src/security/scimAccessController.js';

export async function runIdentityCheck(env = process.env, options = {}) {
  const entitlementRegistry = options.entitlementRegistry ?? createIdentityEntitlementRegistryFromEnvironment(env, options.entitlementOptions);
  const gateway = options.authenticationGateway ?? createAuthenticationGatewayFromEnvironment(env, { ...options, entitlementRegistry });
  const oidc = gateway.oidcAuthenticator;
  if (oidc && oidc.health().cacheState !== 'static') await oidc.refresh();
  const health = gateway.credentialHealth();
  const scimEnabled = String(env.WORKFORCE_AUDIT_SCIM_ENABLED ?? 'false') === 'true';
  const scim = scimEnabled
    ? (options.scimAccessController ?? createScimAccessControllerFromEnvironment(env)).health()
    : { status: 'disabled', enabled: false };
  const status = health.status === 'ready'
    && (!scimEnabled || scim.status === 'ready')
    ? 'ready'
    : 'unavailable';
  return {
    status,
    authenticationMode: gateway.mode,
    apiKeys: health.apiKeys,
    oidc: health.oidc,
    identityEntitlements: health.identityEntitlements,
    scim
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  runIdentityCheck().then((result) => {
    console.log(JSON.stringify(result, null, 2));
    if (result.status !== 'ready') process.exitCode = 1;
  }).catch((error) => {
    console.error(JSON.stringify({
      success: false,
      code: error.code ?? 'IDENTITY_CHECK_FAILED',
      error: error.message
    }));
    process.exitCode = 1;
  });
}
