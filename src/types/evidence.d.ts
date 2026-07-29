export type EvidenceStatus = 'active' | 'quarantine' | 'rejected' | 'disposed';
export type EvidenceSourceType = 'uploaded' | 'system_export' | 'email' | 'interview' | 'observation' | 'external_provider';
export type EvidenceScreeningDecision = 'clean' | 'quarantine' | 'rejected';
export type EvidenceScreeningSeverity = 'medium' | 'high' | 'critical';
export type ExternalScanVerdict = 'clean' | 'suspicious' | 'malicious' | 'error';
export type ExternalScanJobState = 'pending' | 'inflight' | 'delivered' | 'completed' | 'dead-letter';

export interface EvidenceScreeningFinding {
  ruleId: string;
  severity: EvidenceScreeningSeverity;
  category: 'malware' | 'dlp' | 'content-validation' | 'uninspectable-container' | 'active-content';
}

export interface ExternalScanFinding {
  ruleId: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  category: string;
}

export interface ExternalScanAttestation {
  receiptId: string;
  attestationId: string;
  providerId: string;
  keyId: string;
  evidenceId: string;
  version: number;
  contentSha256: string;
  verdict: ExternalScanVerdict;
  scannedAt: string;
  receivedAt: string;
  engine: string;
  engineVersion: string | null;
  definitionsVersion: string | null;
  findings: ExternalScanFinding[];
  sequence: number;
  previousHash: string | null;
  hash: string;
}

export interface ExternalScanJobSummary {
  jobId: string;
  providerId: string;
  deliveryKeyId: string;
  state: ExternalScanJobState;
  evidenceId: string;
  evidenceVersion: number;
  contentSha256: string;
  sizeBytes: number;
  createdAt: string;
  updatedAt: string;
  expiresAt: string;
  attempts: number;
  deliveredAt: string | null;
  completedAt: string | null;
  deadLetteredAt: string | null;
  result: Record<string, unknown> | null;
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
  externalScan?: ExternalScanAttestation | null;
  externalScanJob?: ExternalScanJobSummary | null;
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
  externalScan?: ExternalScanAttestation | null;
  externalScanJob?: ExternalScanJobSummary | null;
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

export interface ExternalScanStatus {
  status: 'ready' | 'attention' | 'unavailable' | 'disabled';
  mode: 'disabled' | 'observe' | 'enforce';
  requiredForRelease: boolean;
  totalAttestations?: number;
  clean?: number;
  suspicious?: number;
  malicious?: number;
  errors?: number;
  headSequence?: number;
  headHash?: string | null;
  error?: string;
}

export interface ExternalScanDeliveryStatus {
  status: 'ready' | 'attention' | 'unavailable' | 'disabled';
  enabled: boolean;
  required: boolean;
  mode: 'disabled' | 'pull';
  total?: number;
  pending?: number;
  inflight?: number;
  delivered?: number;
  completed?: number;
  deadLetters?: number;
  error?: string;
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
  externalScan?: {
    valid: true;
    tenantId: string;
    records: number;
    headSequence: number;
    headHash: string | null;
  };
  externalScanJobs?: {
    valid: true;
    tenantId: string;
    checkedJobs: number;
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

export interface ExternalScanHealth {
  status: 'ready' | 'unavailable' | 'disabled';
  enabled: boolean;
  mode: 'disabled' | 'observe' | 'enforce';
  requiredForRelease: boolean;
  durable?: boolean;
  distributed?: boolean;
  encrypted?: boolean;
  providerCount?: number;
  maxAttestationAgeMinutes?: number;
  clockSkewSeconds?: number;
  eventRetention?: number;
  maxRecords?: number;
  error?: string;
}

export interface ExternalScanDeliveryHealth {
  status: 'ready' | 'degraded' | 'unavailable' | 'disabled';
  enabled: boolean;
  required: boolean;
  mode: 'disabled' | 'pull';
  durable?: boolean;
  distributed?: boolean;
  encryptedRecords?: boolean;
  plaintextQueued?: false;
  publicKeySealed?: boolean;
  requestReplayProtected?: boolean;
  expiryEnforced?: boolean;
  providerCount?: number;
  jobTtlMinutes?: number;
  claimLeaseMs?: number;
  maxAttempts?: number;
  maxClaimBytes?: number;
  estimatedMaximumPackageBytes?: number;
  maximumClaimJobs?: number;
  maintenance?: {
    reconciled: number;
    expiredPending: number;
    expiredDelivered: number;
  };
  counts?: Record<ExternalScanJobState, number>;
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
  externalScan?: ExternalScanHealth;
  externalScanDelivery?: ExternalScanDeliveryHealth | ExternalScanDeliveryStatus;
  error?: string;
}
