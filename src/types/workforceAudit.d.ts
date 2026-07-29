export type RiskTier = 'low' | 'medium' | 'high' | 'critical';
export type FindingStatus = 'draft' | 'open' | 'management-response' | 'verified' | 'closed';
export type AuditRole = 'audit_viewer' | 'auditor' | 'audit_manager' | 'compliance_admin';

export interface AuditPrincipal {
  subject: string;
  tenantId: string;
  role: AuditRole;
  permissions: string[];
}

export interface AuditUniverseItem {
  id: string;
  name: string;
  owner: string;
  riskTier: RiskTier;
  lastReviewedAt: string;
  evidenceCoverage: number;
  controlCoverage: number;
  openFindings: number;
  status: 'ready' | 'attention';
}

export interface AuditEngagement {
  id: string;
  universeItemId: string;
  objective: string;
  scope: string[];
  exclusions?: string[];
  leadAuditor: string;
  startDate: string;
  endDate: string;
  managementApproved: boolean;
  status: 'planned' | 'fieldwork' | 'reporting' | 'closed' | 'cancelled';
  fieldworkPlaceholders: FieldworkPlaceholder[];
}

export interface FieldworkPlaceholder {
  id: string;
  title: string;
  reason: string;
  owner: string;
  expiresAt: string;
  replacementEvidenceRequired: true;
  status: 'open' | 'replaced' | 'expired';
}

export interface AuditFinding {
  id: string;
  engagementId: string;
  title: string;
  severity: RiskTier;
  owner: string;
  dueDate: string;
  evidenceRefs: string[];
  managementResponseRequired: boolean;
  status: FindingStatus;
}

export interface GovernanceEvent {
  id: string;
  sequence: number;
  tenantId: string;
  actor: string;
  action: string;
  entityType: string;
  entityId: string;
  occurredAt: string;
  metadata: Record<string, unknown>;
  previousHash: string | null;
  hash: string;
}
