import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createEvidenceDisclosureAwareApp } from '../src/evidence/evidenceDisclosureServer.js';

test('enabled disclosure cannot start without preservation and independent time attestations', () => {
  const baseApp = createServer((_req, res) => res.end());
  baseApp.authenticationGateway = {
    mode: 'api-key',
    authenticate() {},
    authorise() {}
  };
  assert.throws(() => createEvidenceDisclosureAwareApp({
    evidenceRegistry: {
      evidenceDisclosureEnabled: true,
      evidencePreservationEnabled: false,
      evidenceTimeAttestationEnabled: false
    },
    baseApp,
    disclosureHandler: { matches: () => false, handle() {} }
  }), /requires enabled preservation and independent time attestations/);
  baseApp.close();
});
