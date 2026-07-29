export type EvidenceStatus = 'active' | 'disposed';
export type EvidenceSourceType = 'uploaded' | 'system_export' | 'email' | 'interview' | 'observation' | 'external_provider';

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
  error?: string;
}
