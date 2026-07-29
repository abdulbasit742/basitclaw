export type RiskTier = 'low' | 'medium' | 'high' | 'critical';
export type FindingStatus = 'draft' | 'open' | 'management-response' | 'verified' | 'closed';
export type AuditRole = 'audit_viewer' | 'auditor' | 'audit_manager' | 'compliance_admin';

export interface AuditPrincipal {
  subject: string;
  tenantId: string;
  role: AuditRole;
  permissions: string[];
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

export interface WorkforceAuditSnapshot {
  schemaVersion: 1;
  tenantId: string;
  savedAt: string;
  state: {
    engagements: AuditEngagement[];
    findings: AuditFinding[];
  };
  governanceEvents: GovernanceEvent[];
}

export interface PersistenceHealth {
  status: 'ready' | 'unavailable';
  mode: 'encrypted-file';
  directory: string;
  primaryKeyId: string;
  configuredKeyIds: string[];
  persistedTenantCount: number;
  error?: string;
}
