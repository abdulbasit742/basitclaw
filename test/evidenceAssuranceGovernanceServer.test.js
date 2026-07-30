import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createEvidenceAssuranceGovernanceAwareApp } from '../src/evidence/evidenceAssuranceGovernanceServer.js';

test('enabled assurance governance cannot start without bundle delivery', () => {
  const baseApp = createServer((_req, res) => res.end());
  baseApp.authenticationGateway = { mode: 'api-key', authenticate() {}, authorise() {} };
  assert.throws(() => createEvidenceAssuranceGovernanceAwareApp({
    evidenceRegistry: {
      assuranceGovernanceEnabled: true,
      assuranceBundleEnabled: false
    },
    baseApp,
    assuranceGovernanceHandler: { matches: () => false, handle() {} }
  }), /requires enabled assurance bundle delivery/);
});
