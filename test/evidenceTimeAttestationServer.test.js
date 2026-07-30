import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createEvidenceTimeAttestationAwareApp } from '../src/evidence/evidenceTimeAttestationServer.js';

test('enabled time attestations cannot start without immutable preservation', () => {
  const baseApp = createServer((_req, res) => res.end());
  baseApp.authenticationGateway = {};
  assert.throws(() => createEvidenceTimeAttestationAwareApp({
    evidenceRegistry: {
      evidenceTimeAttestationEnabled: true,
      evidencePreservationEnabled: false
    },
    rateLimiter: {},
    baseApp,
    timeAttestationHandler: { matches() { return false; }, handle() {} }
  }), /require enabled immutable evidence preservation/);
  baseApp.close();
});
