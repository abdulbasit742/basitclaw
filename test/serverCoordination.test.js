import test from 'node:test';
import assert from 'node:assert/strict';
import { CoordinationBusyError } from '../src/coordination/fileLeaseCoordinator.js';
import { createAccessController } from '../src/security/accessControl.js';
import { createApp } from '../src/server.js';

const managerKey = 'manager-key-123456789';

function createRegistry() {
  const service = {
    getOverview: () => ({}),
    getUniverse: () => [],
    getEngagements: () => [],
    getFindings: () => [],
    getProviders: () => [],
    createEngagement: () => {
      throw new CoordinationBusyError(undefined, {
        tenantId: 'tenant-a',
        ownerId: 'instance-b',
        fencingToken: 9,
        retryAfterMs: 2500
      });
    },
    addFieldworkPlaceholder: () => null,
    createFinding: () => null
  };
  return {
    forTenant: () => service,
    getPersistenceHealth: () => ({
      status: 'ready',
      backups: { status: 'ready' },
      replicas: { enabled: false, required: false, status: 'disabled' },
      coordination: { enabled: true, status: 'ready' }
    }),
    getCoordinationStatus: () => ({
      enabled: true,
      status: 'ready',
      mode: 'file-lease-fencing',
      latestFencingToken: 9,
      tenant: { status: 'available', tenantId: 'tenant-a', owner: null }
    })
  };
}

function scheduler() {
  return {
    start: () => ({}),
    stop: () => ({}),
    status: () => ({ enabled: false, active: false, drillMaxAgeDays: 30, intervalMinutes: 0 })
  };
}

async function start(t) {
  const accessController = createAccessController({ principals: [
    { apiKey: managerKey, subject: 'manager.one', tenantId: 'tenant-a', role: 'audit_manager' }
  ] });
  const server = createApp({ registry: createRegistry(), accessController, resilienceScheduler: scheduler() });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  return `http://127.0.0.1:${server.address().port}`;
}

test('coordination status is available to audit managers', async (t) => {
  const base = await start(t);
  const response = await fetch(`${base}/api/workforce-audit/coordination-status`, {
    headers: { 'x-api-key': managerKey }
  });
  const payload = await response.json();
  assert.equal(response.status, 200);
  assert.equal(payload.data.mode, 'file-lease-fencing');
  assert.equal(payload.data.latestFencingToken, 9);
});

test('busy tenant writes return 423 and Retry-After', async (t) => {
  const base = await start(t);
  const response = await fetch(`${base}/api/workforce-audit/engagements`, {
    method: 'POST',
    headers: { 'x-api-key': managerKey, 'content-type': 'application/json' },
    body: '{}'
  });
  const payload = await response.json();
  assert.equal(response.status, 423);
  assert.equal(payload.code, 'WRITE_COORDINATION_BUSY');
  assert.equal(response.headers.get('retry-after'), '3');
});
