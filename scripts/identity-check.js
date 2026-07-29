import { fileURLToPath } from 'node:url';
import { createAuthenticationGatewayFromEnvironment } from '../src/security/authenticationGateway.js';

export async function runIdentityCheck(env = process.env, options = {}) {
  const gateway = options.authenticationGateway ?? createAuthenticationGatewayFromEnvironment(env, options);
  const oidc = gateway.oidcAuthenticator;
  if (oidc && oidc.health().cacheState !== 'static') await oidc.refresh();
  const health = gateway.credentialHealth();
  return {
    status: health.status,
    authenticationMode: gateway.mode,
    apiKeys: health.apiKeys,
    oidc: health.oidc
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
