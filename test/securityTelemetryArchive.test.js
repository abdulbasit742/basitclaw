import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createSecurityEventArchive } from '../src/security/securityEventArchive.js';
import { createSecurityTelemetry } from '../src/security/securityTelemetry.js';

const key = Buffer.alloc(32, 41).toString('base64');

test('telemetry mirrors redacted events into the durable archive', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'basitclaw-telemetry-archive-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const archive = createSecurityEventArchive({ directory: root, encryptionKey: key, required: true });
  const telemetry = createSecurityTelemetry({ pepper: 'telemetry-pepper-123456789', maxEvents: 100, archive });
  telemetry.record({
    type: 'authentication.failed', severity: 'warning', outcome: 'denied',
    clientAddress: '203.0.113.10', details: { apiKey: 'never-store', reason: 'invalid_key' }
  });
  const status = telemetry.summary();
  assert.equal(status.durable, true);
  assert.equal(status.distributed, true);
  assert.equal(status.archive.status, 'ready');
  const archived = telemetry.listArchived({ limit: 10 });
  assert.equal(archived.events.length, 1);
  assert.doesNotMatch(JSON.stringify(archived), /203\.0\.113\.10|never-store/);
});
