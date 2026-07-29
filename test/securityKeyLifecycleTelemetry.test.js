import test from 'node:test';
import assert from 'node:assert/strict';
import { createSecurityTelemetry } from '../src/security/securityTelemetry.js';

function disabledArchive() {
  return {
    enabled: false,
    health: () => ({ status: 'disabled', enabled: false, required: false, mode: 'disabled' })
  };
}

test('security telemetry exposes rotation counts without key identifiers', () => {
  const keyLifecycle = {
    status: () => ({
      archive: {
        status: 'ready',
        mode: 'keyring',
        configuredKeyIds: ['archive-current-secret-id', 'archive-old-secret-id'],
        configuredKeyCount: 2,
        retainedHistoricalKeyIds: ['archive-old-secret-id'],
        retirementSafeKeyIds: [],
        missingKeyIds: [],
        rotationReady: true
      },
      alertSigning: {
        status: 'ready',
        mode: 'keyring',
        configuredKeyIds: ['alert-current-secret-id', 'alert-old-secret-id'],
        configuredKeyCount: 2,
        rotationReady: true,
        receiverOverlapRequired: true
      }
    })
  };
  const telemetry = createSecurityTelemetry({
    pepper: 'telemetry-pepper-123456789',
    archive: disabledArchive(),
    keyLifecycle
  });
  const lifecycle = telemetry.summary().keyLifecycle;
  assert.equal(lifecycle.archive.configuredKeyCount, 2);
  assert.equal(lifecycle.archive.retainedHistoricalKeyCount, 1);
  assert.equal(lifecycle.alertSigning.receiverOverlapRequired, true);
  assert.doesNotMatch(JSON.stringify(lifecycle), /archive-current-secret-id|archive-old-secret-id|alert-current-secret-id/);
});
