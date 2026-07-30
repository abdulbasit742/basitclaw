import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createRegulatoryCaseAwareApp } from '../src/regulatory/regulatoryCaseServer.js';

function baseAppFixture() {
  const calls = [];
  const baseApp = createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ success: true, base: true }));
  });
  baseApp.authenticationGateway = {
    mode: 'api-key',
    async authenticate() { return { subject: 'manager', tenantId: 'tenant-a' }; },
    authorise(_principal, permission) { calls.push(permission); return true; }
  };
  baseApp.apiSecurity = { securityTelemetry: { record() {} } };
  baseApp.resilienceScheduler = { start() {}, stop() {} };
  baseApp.evidenceRegistry = {};
  baseApp.evidenceHandler = {};
  baseApp.evidenceReferenceMutex = {};
  baseApp.externalScanCallbackHandler = {};
  baseApp.externalScanManagementHandler = {};
  baseApp.externalScanJobGovernanceHandler = {};
  baseApp.externalScanJobDeliveryHandler = {};
  baseApp.evidencePreservationHandler = {};
  baseApp.evidenceTimeAttestationHandler = {};
  baseApp.evidenceTimeAttestationGovernanceHandler = {};
  baseApp.auditRegistry = {};
  return { baseApp, calls };
}

test('regulatory runtime preserves the composed evidence stack and maps governed permissions', () => {
  const { baseApp, calls } = baseAppFixture();
  const store = {
    createCase() {},
    tenantStatus() { return { status: 'ready' }; },
    verifyTenant() { return { valid: true }; },
    list() { return []; },
    get() { return {}; },
    events() { return []; },
    addEvidence() {},
    submitResponse() {},
    approveResponse() {},
    closeCase() {},
    cancelCase() {}
  };
  const app = createRegulatoryCaseAwareApp({
    baseApp,
    regulatoryCaseStore: store,
    rateLimiter: null
  });
  const principal = { subject: 'manager', tenantId: 'tenant-a' };
  app.regulatoryAuthenticationGateway.authorise(principal, 'regulatory:case');
  app.regulatoryAuthenticationGateway.authorise(principal, 'regulatory:case:approve');
  assert.deepEqual(calls, ['governance:read', 'backup:restore']);
  assert.equal(app.evidenceTimeAttestationGovernanceHandler, baseApp.evidenceTimeAttestationGovernanceHandler);
  assert.equal(app.evidenceRegistry, baseApp.evidenceRegistry);
  assert.equal(app.regulatoryCaseStore, store);
  app.close();
  baseApp.close();
});
