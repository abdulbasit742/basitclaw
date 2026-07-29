import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { startEvidenceRuntime } from '../src/evidenceRuntime.js';

function failingApp() {
  const app = new EventEmitter();
  app.authenticationGateway = {
    oidcAuthenticator: {
      health: () => ({ status: 'ready', enabled: true, cacheState: 'dynamic' }),
      refresh: async () => {}
    }
  };
  app.identityEntitlements = { health: () => ({ status: 'disabled', enabled: false, required: false }) };
  app.privilegedAccess = { health: () => ({ status: 'disabled', enabled: false, required: false }) };
  app.scimHandler = {
    health: () => ({
      registry: { status: 'disabled', enabled: false, required: false },
      credentials: { status: 'disabled', enabled: false }
    })
  };
  app.evidenceRegistry = { health: () => ({ status: 'ready', enabled: true, required: true }) };
  app.listen = () => { throw new Error('listen failed'); };
  return app;
}

test('startup failure clears the OIDC refresh timer exactly once', async () => {
  const app = failingApp();
  const originalClearInterval = globalThis.clearInterval;
  let clears = 0;
  globalThis.clearInterval = (timer) => {
    clears += 1;
    return originalClearInterval(timer);
  };
  try {
    await assert.rejects(
      startEvidenceRuntime({
        app,
        env: {
          PORT: '3000',
          WORKFORCE_AUDIT_AUTH_MODE: 'hybrid',
          WORKFORCE_AUDIT_OIDC_REFRESH_SECONDS: '30',
          WORKFORCE_AUDIT_SCIM_ENABLED: 'false'
        },
        logger: { log() {}, error() {} }
      }),
      /listen failed/
    );
    assert.equal(clears, 1);
    app.emit('close');
    assert.equal(clears, 1);
  } finally {
    globalThis.clearInterval = originalClearInterval;
  }
});

test('blank PORT falls back to the configured default before listening', async () => {
  const app = failingApp();
  let listenedPort = null;
  app.listen = (port) => {
    listenedPort = port;
    queueMicrotask(() => app.emit('listening'));
  };
  const running = await startEvidenceRuntime({
    app,
    env: {
      PORT: ' ',
      WORKFORCE_AUDIT_AUTH_MODE: 'hybrid',
      WORKFORCE_AUDIT_OIDC_REFRESH_SECONDS: '30',
      WORKFORCE_AUDIT_SCIM_ENABLED: 'false'
    },
    logger: { log() {}, error() {} }
  });
  assert.equal(running, app);
  assert.equal(listenedPort, 3000);
  app.emit('close');
});
