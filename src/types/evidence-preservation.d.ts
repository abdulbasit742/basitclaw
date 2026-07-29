export interface EvidencePreservationReceipt {
  receiptId: string;
  archiveId: string;
  evidenceId: string;
  evidenceVersion: number;
  contentSha256: string;
  sizeBytes: number;
  objectEnvelopeSha256: string;
  retentionUntil: string;
  legalHoldActive: boolean;
  archivedAt: string;
  archivedBy: string;
  purpose: string;
  immutabilityMode: 'application-write-once' | 'backend-confirmed-write-once';
  signingKeyId: string;
  signature: string;
}

export interface EvidencePreservationResult {
  archived: boolean;
  duplicate: boolean;
  recoveredReceipt: boolean;
  receipt: EvidencePreservationReceipt;
}

export interface EvidencePreservationVerification {
  valid: true;
  archiveId: string;
  receipt: EvidencePreservationReceipt;
  object: {
    contentSha256: string;
    sizeBytes: number;
    encryptionKeyId: string;
  };
}

export interface EvidencePreservationStatus {
  status: 'ready' | 'attention' | 'unavailable' | 'disabled';
  enabled: boolean;
  requiredForDisposition: boolean;
  immutableBackendConfirmed: boolean;
  archives?: number;
  orphanObjects?: number;
  totalVersions?: number;
  preservedVersions?: number;
  unpreservedVersions?: number;
  dispositionReady?: boolean;
  error?: string;
}

export interface EvidencePreservationHealth {
  status: 'ready' | 'attention' | 'unavailable' | 'disabled';
  enabled: boolean;
  requiredForDisposition: boolean;
  mode: 'shared-file-write-once-preservation' | 'disabled';
  durable?: boolean;
  encrypted?: boolean;
  signedReceipts?: boolean;
  createOnly?: boolean;
  deletionApi?: false;
  immutableBackendConfirmed?: boolean;
  tenantDirectoryCount?: number;
  error?: string;
}

export interface EvidencePreservationSummary {
  enabled: boolean;
  requiredForDisposition: boolean;
  totalReceipts: number;
  preservedVersions: number;
  totalVersions: number;
  dispositionReady: boolean;
  latestReceipt: EvidencePreservationReceipt | null;
}
