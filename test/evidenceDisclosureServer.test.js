import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createEvidenceDisclosureAwareApp } from '../src/evidence/evidenceDisclosureServer.js';

test('enabled disclosure cannot start without preservation, time attestations and notary governance', () => {
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
      evidenceTimeAttestationEnabled: false,
      evidenceTimeAttestationGovernanceEnabled: false
    },
    baseApp,
    disclosureHandler: { matches: () => false, handle() {} }
  }), /requires enabled preservation, independent time attestations and notary governance/);
});
