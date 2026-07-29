export type RiskTier = 'low' | 'medium' | 'high' | 'critical';
export type FindingStatus = 'draft' | 'open' | 'management-response' | 'verified' | 'closed';
export type AuditRole = 'audit_viewer' | 'auditor' | 'audit_manager' | 'compliance_admin';
export type BackupKind = 'manual' | 'scheduled' | 'safety';

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

export interface BackupManifest {
  format: 'basitclaw-workforce-audit-backup';
  version: 1;
  backupId: string;
  tenantHash: string;
  createdAt: string;
  createdOrder: number;
  snapshotWrittenAt: string;
  keyId: string;
  checksumSha256: string;
  sizeBytes: number;
  kind: BackupKind;
  prunedBackupIds?: string[];
}

export interface BackupVerification extends BackupManifest {
  valid: true;
  summary: {
    engagementCount: number;
    findingCount: number;
    governanceEventCount: number;
    governanceHeadHash: string | null;
  };
}

export interface RestorePreview {
  dryRun: true;
  backup: BackupVerification;
  current: {
    engagementCount: number;
    findingCount: number;
    governanceEventCount: number;
    governanceHeadHash: string | null;
  };
}

export interface BackupHealth {
  status: 'ready' | 'unavailable';
  mode: 'encrypted-file-backup';
  directory: string;
  retention: number;
  tenantDirectoryCount: number;
  error?: string;
}

export interface PersistenceHealth {
  status: 'ready' | 'unavailable';
  mode: 'encrypted-file';
  directory: string;
  primaryKeyId: string;
  configuredKeyIds: string[];
  persistedTenantCount: number;
  backups: BackupHealth;
  error?: string;
}
