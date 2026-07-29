import test from 'node:test';
import assert from 'node:assert/strict';
import { prepareIdentityProvider } from '../src/runtime.js';
import { runIdentityCheck } from '../scripts/identity-check.js';

test('OIDC-only production fails startup when JWKS warm-up fails', async () => {
  const gateway = {
    oidcAuthenticator: {
      health: () => ({ status: 'unavailable', enabled: true, cacheState: 'cold' }),
      refresh: async () => { throw new Error('jwks offline'); }
    }
  };
  await assert.rejects(prepareIdentityProvider({
    authenticationGateway: gateway,
    env: { NODE_ENV: 'production', WORKFORCE_AUDIT_AUTH_MODE: 'oidc' },
    logger: { error() {} }
  }), /jwks offline/);
});

test('hybrid mode stays running in degraded state and schedules refresh', async () => {
  let calls = 0;
  const errors = [];
  const gateway = {
    oidcAuthenticator: {
      health: () => ({ status: calls > 1 ? 'ready' : 'unavailable', enabled: true, cacheState: 'cold' }),
      refresh: async () => { calls += 1; if (calls === 1) throw new Error('temporary'); }
    }
  };
  const result = await prepareIdentityProvider({
    authenticationGateway: gateway,
    env: { NODE_ENV: 'production', WORKFORCE_AUDIT_AUTH_MODE: 'hybrid', WORKFORCE_AUDIT_OIDC_REFRESH_SECONDS: '30' },
    logger: { error: (...args) => errors.push(args) }
  });
  assert.equal(calls, 1);
  assert.equal(errors.length, 1);
  assert.ok(result.refreshTimer);
  clearInterval(result.refreshTimer);
});

test('identity check refreshes remote JWKS and returns safe health', async () => {
  let refreshed = false;
  const gateway = {
    mode: 'oidc',
    oidcAuthenticator: {
      health: () => ({ status: 'ready', enabled: true, cacheState: refreshed ? 'fresh' : 'cold', cachedKeys: refreshed ? 2 : 0 }),
      refresh: async () => { refreshed = true; }
    },
    credentialHealth: () => ({ status: refreshed ? 'ready' : 'unavailable', apiKeys: { status: 'disabled' }, oidc: { status: refreshed ? 'ready' : 'unavailable', cachedKeys: refreshed ? 2 : 0 } })
  };
  const result = await runIdentityCheck({}, { authenticationGateway: gateway });
  assert.equal(result.status, 'ready');
  assert.equal(result.oidc.cachedKeys, 2);
  assert.equal(JSON.stringify(result).includes('secret'), false);
});
