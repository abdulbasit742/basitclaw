import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createEvidenceAssuranceBundleAwareApp } from '../src/evidence/evidenceAssuranceBundleServer.js';

test('enabled assurance bundles cannot start without encrypted evidence custody', () => {
  const baseApp = createServer((_req, res) => res.end());
  baseApp.authenticationGateway = {};
  assert.throws(() => createEvidenceAssuranceBundleAwareApp({
    evidenceRegistry: {
      assuranceBundleEnabled: true,
      enabled: false
    },
    baseApp,
    rateLimiter: null,
    assuranceBundleHandler: { matches() { return false; }, handle() {} }
  }), /require enabled encrypted evidence custody/);
  baseApp.close();
});
