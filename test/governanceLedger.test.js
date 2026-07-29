import test from 'node:test';
import assert from 'node:assert/strict';
import { createGovernanceLedger } from '../src/services/governanceLedger.js';

const fixedNow = () => new Date('2026-07-29T11:00:00.000Z');

test('governance events form tenant-scoped SHA-256 chains', () => {
  const ledger = createGovernanceLedger({ now: fixedNow });
  const first = ledger.append({ tenantId: 'tenant-a', actor: 'auditor.one', action: 'engagement.created', entityType: 'engagement', entityId: 'ENG-1' });
  const second = ledger.append({ tenantId: 'tenant-a', actor: 'auditor.one', action: 'finding.created', entityType: 'finding', entityId: 'FND-1' });
  const otherTenant = ledger.append({ tenantId: 'tenant-b', actor: 'auditor.two', action: 'engagement.created', entityType: 'engagement', entityId: 'ENG-1' });

  assert.equal(first.previousHash, null);
  assert.equal(second.previousHash, first.hash);
  assert.equal(otherTenant.previousHash, null);
  assert.equal(ledger.verify('tenant-a').valid, true);
  assert.equal(ledger.list('tenant-a').length, 2);
  assert.equal(ledger.list('tenant-b').length, 1);
});
