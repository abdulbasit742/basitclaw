import test from 'node:test';
import assert from 'node:assert/strict';
import { prepareIdentityLifecycle } from '../src/runtime.js';

test('identity lifecycle startup accepts disabled, ready, or review-attention controls', () => {
  const disabled = prepareIdentityLifecycle({ app: {}, env: {} });
  assert.equal(disabled.entitlementHealth.status, 'disabled');

  const ready = prepareIdentityLifecycle({
    app: {
      identityEntitlements: { health: () => ({ status: 'ready', enabled: true, required: true, mode: 'enforce' }) },
      scimHandler: { health: () => ({ registry: { status: 'ready' }, credentials: { status: 'ready' } }) }
    },
    env: { WORKFORCE_AUDIT_SCIM_ENABLED: 'true' }
  });
  assert.equal(ready.scimHealth.credentials.status, 'ready');

  const attention = prepareIdentityLifecycle({
    app: { identityEntitlements: { health: () => ({ status: 'attention', enabled: true, required: true, mode: 'enforce', overdue: 1 }) } },
    env: {}
  });
  assert.equal(attention.entitlementHealth.status, 'attention');
});

test('required entitlement storage fails startup closed', () => {
  assert.throws(() => prepareIdentityLifecycle({
    app: { identityEntitlements: { health: () => ({ status: 'unavailable', enabled: true, required: true, mode: 'enforce' }) } },
    env: {}
  }), (error) => error.code === 'IDENTITY_ENTITLEMENT_STORE_UNAVAILABLE');
});

test('enabled SCIM requires a ready registry and usable credentials', () => {
  const entitlementHealth = { status: 'ready', enabled: true, required: true, mode: 'enforce' };
  for (const scimHealth of [
    { registry: { status: 'ready' }, credentials: { status: 'unavailable' } },
    { registry: { status: 'disabled' }, credentials: { status: 'ready' } },
    { registry: { status: 'unavailable' }, credentials: { status: 'ready' } }
  ]) {
    assert.throws(() => prepareIdentityLifecycle({
      app: {
        identityEntitlements: { health: () => entitlementHealth },
        scimHandler: { health: () => scimHealth }
      },
      env: { WORKFORCE_AUDIT_SCIM_ENABLED: 'true' }
    }), (error) => error.code === 'SCIM_UNAVAILABLE');
  }
});
