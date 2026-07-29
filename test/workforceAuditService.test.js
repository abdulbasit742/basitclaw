import test from 'node:test';
import assert from 'node:assert/strict';
import { assessProviderReadiness, createWorkforceAuditService, ValidationError } from '../src/services/workforceAuditService.js';

const fixedNow = () => new Date('2026-07-29T11:00:00.000Z');

test('overview exposes governance readiness counts', () => {
  const service = createWorkforceAuditService({ now: fixedNow });
  const overview = service.getOverview();
  assert.equal(overview.universe.total, 3);
  assert.equal(overview.providers.total, 2);
  assert.equal(overview.providers.ready, 1);
  assert.equal(overview.findings.criticalOrHigh, 1);
});

test('engagement planning blocks missing management approval', () => {
  const service = createWorkforceAuditService({ now: fixedNow });
  assert.throws(() => service.createEngagement({
    universeItemId: 'HIRING-02',
    objective: 'Review hiring governance',
    scope: ['screening'],
    leadAuditor: 'Audit Lead',
    startDate: '2026-09-01',
    endDate: '2026-09-15',
    managementApproved: false
  }), ValidationError);
});

test('fieldwork placeholder has an expiry and replacement-evidence boundary', () => {
  const service = createWorkforceAuditService({ now: fixedNow });
  const placeholder = service.addFieldworkPlaceholder('ENG-2026-004', {
    title: 'Awaiting bank confirmation',
    reason: 'Independent confirmation has not arrived',
    owner: 'Audit Manager',
    expiresAt: '2026-08-15'
  });
  assert.equal(placeholder.replacementEvidenceRequired, true);
  assert.equal(placeholder.status, 'open');
});

test('placeholder evidence cannot close a finding', () => {
  const service = createWorkforceAuditService({ now: fixedNow });
  assert.throws(() => service.createFinding({
    engagementId: 'ENG-2026-004',
    title: 'Unsupported control conclusion',
    severity: 'high',
    owner: 'Payroll Controls Manager',
    dueDate: '2026-09-30',
    evidenceRefs: ['PLH-ENG-2026-004-01'],
    status: 'closed'
  }), /Placeholder evidence cannot support finding closure/);
});

test('provider readiness reports all blockers', () => {
  const result = assessProviderReadiness({
    independenceConfirmed: false,
    securityReviewStatus: 'pending',
    dataProcessingAgreement: false,
    capacityStatus: 'limited',
    lastDueDiligenceAt: '2024-01-01'
  }, fixedNow());
  assert.equal(result.readiness, 'blocked');
  assert.equal(result.blockers.length, 5);
});
