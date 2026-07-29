import test from 'node:test';
import assert from 'node:assert/strict';
import { PersistenceError } from '../src/persistence/encryptedSnapshotStore.js';
import { createGovernanceLedger } from '../src/services/governanceLedger.js';
import { createWorkforceAuditService } from '../src/services/workforceAuditService.js';

const now = () => new Date('2026-07-29T11:00:00.000Z');

test('persisted governance events can be imported and verified after restart', () => {
  const first = createGovernanceLedger({ now });
  first.append({ tenantId: 'tenant-a', actor: 'auditor.one', action: 'engagement.created', entityType: 'engagement', entityId: 'ENG-1' });
  const restored = createGovernanceLedger({ now });
  restored.importTenant('tenant-a', first.exportTenant('tenant-a'));
  assert.equal(restored.verify('tenant-a').valid, true);
  assert.equal(restored.list('tenant-a').length, 1);
});

test('persistence failure rolls back business state and governance history', () => {
  const ledger = createGovernanceLedger({ now });
  const service = createWorkforceAuditService({
    now,
    tenantId: 'tenant-a',
    ledger,
    persist: () => { throw new PersistenceError('disk unavailable'); }
  });
  assert.throws(() => service.addFieldworkPlaceholder('ENG-2026-004', {
    title: 'Awaiting confirmation', reason: 'Third-party response pending', owner: 'Audit Manager', expiresAt: '2026-08-15'
  }, { actor: 'auditor.one' }), PersistenceError);
  assert.equal(service.getEngagements()[0].fieldworkPlaceholders.length, 0);
  assert.equal(ledger.list('tenant-a').length, 0);
});
