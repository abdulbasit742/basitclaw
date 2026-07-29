import { fileURLToPath } from 'node:url';
import { createFederatedApp } from './federatedServer.js';

export async function prepareIdentityProvider({
  authenticationGateway,
  env = process.env,
  logger = console
} = {}) {
  const oidc = authenticationGateway?.oidcAuthenticator;
  const health = oidc?.health?.() ?? { status: 'disabled', enabled: false, cacheState: 'disabled' };
  if (!oidc || health.cacheState === 'static') return { health, refreshTimer: null };

  const mode = String(env.WORKFORCE_AUDIT_AUTH_MODE ?? 'api-key');
  const startupRequired = env.WORKFORCE_AUDIT_OIDC_STARTUP_REQUIRED === undefined
    ? env.NODE_ENV === 'production' && mode === 'oidc'
    : String(env.WORKFORCE_AUDIT_OIDC_STARTUP_REQUIRED) === 'true';
  try {
    await oidc.refresh();
  } catch (error) {
    if (startupRequired) throw error;
    logger.error?.('OIDC JWKS warm-up failed; runtime will remain degraded until refresh succeeds.', { error: error.message });
  }

  const intervalSeconds = integer(env.WORKFORCE_AUDIT_OIDC_REFRESH_SECONDS ?? 300, 'WORKFORCE_AUDIT_OIDC_REFRESH_SECONDS', 30, 86_400);
  let running = false;
  const refreshTimer = setInterval(async () => {
    if (running) return;
    running = true;
    try { await oidc.refresh(); } catch (error) {
      logger.error?.('OIDC JWKS refresh failed.', { error: error.message });
    } finally { running = false; }
  }, intervalSeconds * 1000);
  refreshTimer.unref?.();
  return { health: oidc.health(), refreshTimer };
}

export function prepareIdentityLifecycle({ app, env = process.env } = {}) {
  const entitlementHealth = app?.identityEntitlements?.health?.() ?? { status: 'disabled', enabled: false, required: false };
  if (entitlementHealth.required && entitlementHealth.status === 'unavailable') {
    const error = new Error('The required identity entitlement lifecycle is not ready.');
    error.code = 'IDENTITY_ENTITLEMENT_STORE_UNAVAILABLE';
    error.details = entitlementHealth;
    throw error;
  }
  const scimHealth = app?.scimHandler?.health?.() ?? { registry: entitlementHealth, credentials: { status: 'disabled', enabled: false } };
  const scimEnabled = String(env.WORKFORCE_AUDIT_SCIM_ENABLED ?? 'false') === 'true';
  const registryReady = ['ready', 'attention', 'degraded'].includes(scimHealth.registry?.status);
  if (scimEnabled && (!registryReady || scimHealth.credentials?.status !== 'ready')) {
    const error = new Error('The SCIM provisioning boundary is not ready.');
    error.code = 'SCIM_UNAVAILABLE';
    error.details = scimHealth;
    throw error;
  }
  return { entitlementHealth, scimHealth };
}

export async function startRuntime({
  env = process.env,
  app = createFederatedApp({ env }),
  logger = console
} = {}) {
  const identity = await prepareIdentityProvider({ authenticationGateway: app.authenticationGateway, env, logger });
  prepareIdentityLifecycle({ app, env });
  if (identity.refreshTimer) app.once('close', () => clearInterval(identity.refreshTimer));
  const port = integer(env.PORT ?? 3000, 'PORT', 1, 65_535);
  await new Promise((resolve, reject) => {
    const onError = (error) => { app.off('listening', onListening); reject(error); };
    const onListening = () => { app.off('error', onError); resolve(); };
    app.once('error', onError);
    app.once('listening', onListening);
    app.listen(port);
  });
  logger.log?.(`BasitClaw listening on http://localhost:${port}`);
  return app;
}

function integer(value, field, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new TypeError(`${field} must be an integer from ${minimum} to ${maximum}.`);
  }
  return parsed;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  startRuntime().catch((error) => {
    console.error('BasitClaw startup failed.', { code: error.code, error: error.message });
    process.exitCode = 1;
  });
}
