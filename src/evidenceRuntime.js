import { fileURLToPath } from 'node:url';
import { prepareEvidenceLifecycle } from './evidence/evidenceServer.js';
import { createEvidenceVerificationBundleAwareApp } from './evidence/evidenceVerificationBundleServer.js';
import { prepareIdentityLifecycle, prepareIdentityProvider } from './runtime.js';

export async function startEvidenceRuntime({
  env = process.env,
  app = createEvidenceVerificationBundleAwareApp({ env }),
  logger = console
} = {}) {
  const identity = await prepareIdentityProvider({ authenticationGateway: app.authenticationGateway, env, logger });
  const cleanupRefresh = once(() => {
    if (identity.refreshTimer) clearInterval(identity.refreshTimer);
  });
  try {
    prepareIdentityLifecycle({ app, env });
    prepareEvidenceLifecycle({ app });
    if (identity.refreshTimer) app.once('close', cleanupRefresh);
    const port = integer(envValue(env.PORT) ?? 3000, 'PORT', 1, 65_535);
    await new Promise((resolve, reject) => {
      const onError = (error) => { app.off('listening', onListening); reject(error); };
      const onListening = () => { app.off('error', onError); resolve(); };
      app.once('error', onError);
      app.once('listening', onListening);
      app.listen(port);
    });
    logger.log?.(`BasitClaw listening on http://localhost:${port}`);
    return app;
  } catch (error) {
    cleanupRefresh();
    throw error;
  }
}

function envValue(value) {
  const clean = typeof value === 'string' ? value.trim() : value;
  return clean === '' || clean === undefined || clean === null ? undefined : clean;
}
function once(operation) { let completed = false; return () => { if (completed) return; completed = true; operation(); }; }
function integer(value, field, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new TypeError(`${field} must be an integer from ${minimum} to ${maximum}.`);
  }
  return parsed;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  startEvidenceRuntime().catch((error) => {
    console.error('BasitClaw startup failed.', { code: error.code, error: error.message });
    process.exitCode = 1;
  });
}
