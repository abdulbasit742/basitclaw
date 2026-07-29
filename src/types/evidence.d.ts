export type EvidenceStatus = 'active' | 'quarantine' | 'rejected' | 'disposed';
export type EvidenceSourceType = 'uploaded' | 'system_export' | 'email' | 'interview' | 'observation' | 'external_provider';
export type EvidenceScreeningDecision = 'clean' | 'quarantine' | 'rejected';
export type EvidenceScreeningSeverity = 'medium' | 'high' | 'critical';

export interface EvidenceScreeningFinding {
  ruleId: string;
  severity: EvidenceScreeningSeverity;
  category: 'malware' | 'dlp' | 'content-validation' | 'uninspectable-container' | 'active-content';
}

export interface EvidenceScreeningSummary {
  reportId: string;
  engineVersion: string;
  mode: 'disabled' | 'observe' | 'enforce';
  decision: EvidenceScreeningDecision;
  accessDecision: EvidenceScreeningDecision;
  wouldQuarantine: boolean;
  scannedAt: string;
  contentSha256: string;
  sizeBytes: number;
  version: number;
  findings: EvidenceScreeningFinding[];
  reviewedAt: string | null;
  reviewAction: 'released' | 'rejected' | null;
}

export interface EvidenceVersion {
  version: number;
  sha256: string;
  sizeBytes: number;
  createdAt: string;
  filename: string;
  mediaType: string;
}

export interface EvidenceLegalHoldSummary {
  active: boolean;
  placedAt: string;
  reviewAt: string | null;
  releasedAt: string | null;
}

export interface EvidenceItem {
  evidenceId: string;
  filename: string;
  mediaType: string;
  description: string;
  sourceType: EvidenceSourceType;
  sourceSystem: string | null;
  collectedAt: string;
  ingestedAt: string;
  ingestedBy: string;
  retentionUntil: string;
  status: EvidenceStatus;
  currentVersion: number;
  versions: EvidenceVersion[];
  screening?: EvidenceScreeningSummary | { status: 'not-applicable' };
  legalHold: EvidenceLegalHoldSummary | null;
  disposedAt: string | null;
  disposedBy: string | null;
  purgePending: boolean;
  referencedByFindings?: string[];
}

export interface EvidenceCustodyEvent {
  eventId: string;
  sequence: number;
  occurredAt: string;
  actor: string;
  action: string;
  evidenceId: string;
  metadata: Record<string, unknown>;
  previousHash: string | null;
  hash: string;
}

export interface EvidenceScreeningEvent {
  eventId: string;
  sequence: number;
  occurredAt: string;
  action: string;
  evidenceId: string;
  metadata: Record<string, unknown>;
  previousHash: string | null;
  hash: string;
}

export interface EvidenceIntegrityResult {
  valid: true;
  tenantId: string;
  evidenceId: string | null;
  checkedItems: number;
  checkedVersions: number;
  eventCount: number;
  headSequence: number;
  headHash: string | null;
  anchorSequence: number;
  screening?: {
    valid: true;
    checkedRecords: number;
    checkedVersions: number;
    headSequence: number;
    headHash: string | null;
    anchorSequence: number;
  };
}

export interface EvidenceScreeningHealth {
  status: 'ready' | 'unavailable' | 'disabled';
  enabled?: boolean;
  required?: boolean;
  mode: 'disabled' | 'observe' | 'enforce';
  engineVersion?: string;
  deterministic?: boolean;
  externalScanner?: boolean;
  quarantined?: number;
  rejected?: number;
  clean?: number;
  totalReports?: number;
  headSequence?: number;
  headHash?: string | null;
  anchorSequence?: number;
  error?: string;
}

export interface EvidenceHealth {
  status: 'ready' | 'attention' | 'unavailable' | 'disabled';
  enabled: boolean;
  required: boolean;
  mode: 'shared-file-encrypted-evidence' | 'disabled';
  durable?: boolean;
  distributed?: boolean;
  encrypted?: boolean;
  maxBytes?: number;
  defaultRetentionDays?: number;
  eventRetention?: number;
  tenantDirectoryCount?: number;
  total?: number;
  active?: number;
  disposed?: number;
  legalHolds?: number;
  retentionDue?: number;
  holdReviewsOverdue?: number;
  purgePending?: number;
  headSequence?: number;
  headHash?: string | null;
  anchorSequence?: number;
  screening?: EvidenceScreeningHealth;
  error?: string;
}
