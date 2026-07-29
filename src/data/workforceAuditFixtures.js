export const auditUniverse = [
  {
    id: 'PAYROLL-01',
    name: 'Payroll processing and statutory deductions',
    owner: 'Head of Payroll',
    riskTier: 'critical',
    lastReviewedAt: '2026-02-10',
    evidenceCoverage: 92,
    controlCoverage: 88,
    openFindings: 1,
    status: 'ready'
  },
  {
    id: 'HIRING-02',
    name: 'Recruitment, screening, and offer governance',
    owner: 'Talent Acquisition Director',
    riskTier: 'high',
    lastReviewedAt: '2025-07-18',
    evidenceCoverage: 61,
    controlCoverage: 70,
    openFindings: 3,
    status: 'attention'
  },
  {
    id: 'ACCESS-03',
    name: 'Joiner, mover, and leaver access controls',
    owner: 'HR Operations Lead',
    riskTier: 'critical',
    lastReviewedAt: '2026-04-05',
    evidenceCoverage: 77,
    controlCoverage: 81,
    openFindings: 2,
    status: 'attention'
  }
];

export const auditEngagements = [
  {
    id: 'ENG-2026-004',
    universeItemId: 'PAYROLL-01',
    objective: 'Validate payroll change controls and statutory deduction accuracy.',
    scope: ['employee-master changes', 'pay-run approvals', 'statutory remittances'],
    leadAuditor: 'Internal Audit',
    startDate: '2026-08-03',
    endDate: '2026-08-28',
    managementApproved: true,
    status: 'planned',
    fieldworkPlaceholders: []
  }
];

export const auditFindings = [
  {
    id: 'FND-2026-011',
    engagementId: 'ENG-2026-004',
    title: 'Late independent review of payroll master changes',
    severity: 'high',
    owner: 'Payroll Controls Manager',
    dueDate: '2026-09-15',
    evidenceRefs: ['EV-PR-104', 'EV-PR-107'],
    managementResponseRequired: true,
    status: 'draft'
  }
];

export const auditProviders = [
  {
    id: 'PROV-001',
    name: 'Independent Workforce Assurance Ltd',
    independenceConfirmed: true,
    securityReviewStatus: 'approved',
    dataProcessingAgreement: true,
    capacityStatus: 'available',
    lastDueDiligenceAt: '2026-01-15'
  },
  {
    id: 'PROV-002',
    name: 'People Controls Advisory',
    independenceConfirmed: false,
    securityReviewStatus: 'pending',
    dataProcessingAgreement: false,
    capacityStatus: 'limited',
    lastDueDiligenceAt: '2024-11-20'
  }
];
