export type EvidenceTimeAuthorityAlgorithm = 'ed25519' | 'rsa-pss-sha256';

export interface EvidenceTimeAttestationChallenge {
  tenantId: string;
  archiveId: string;
  receiptSha256: string;
  objectEnvelopeSha256: string;
  archivedAt: string;
  retentionUntil: string;
}

export interface EvidenceTimeAttestationSubmission {
  tenantId: string;
  archiveId: string;
  providerId: string;
  keyId: string;
  receiptSha256: string;
  objectEnvelopeSha256: string;
  timestamp: string;
  policyId: string;
  nonce: string;
  signature: string;
}

export interface EvidenceTimeAttestationRecord {
  attestationId: string;
  archiveId: string;
  providerId: string;
  keyId: string;
  receiptSha256: string;
  objectEnvelopeSha256: string;
  timestamp: string;
  policyId: string;
  nonce: string;
  sequence: number;
  receivedAt: string;
  previousHash: string | null;
  hash: string;
}

export interface EvidenceTimeAttestationReceipt {
  accepted: boolean;
  duplicate: boolean;
  attestation: EvidenceTimeAttestationRecord;
}

export interface EvidenceTimeAttestationVerification {
  valid: true;
  tenantId: string;
  archiveId: string;
  attestationCount: number;
  distinctProviders: number;
  minimumProviders: number;
  quorumSatisfied: boolean;
  providerIds: string[];
}

export interface EvidenceTimeAttestationStatus {
  status: 'ready' | 'attention' | 'unavailable' | 'disabled';
  enabled: boolean;
  requiredForDisposition: boolean;
  minimumProviders: number;
  attestations?: number;
  archives?: number;
  quorumArchives?: number;
  preservedVersions?: number;
  quorumVersions?: number;
  missingPreservationCount?: number;
  missingQuorumCount?: number;
  dispositionReady?: boolean;
  headSequence?: number;
  headHash?: string | null;
  error?: string;
}

export interface EvidenceTimeAttestationStoreHealth {
  status: 'ready' | 'unavailable' | 'disabled';
  enabled: boolean;
  requiredForDisposition: boolean;
  mode: string;
  encrypted?: boolean;
  asymmetricSignatures?: boolean;
  replayProtected?: boolean;
  minimumProviders: number;
  configuredProviders?: number;
  clockSkewSeconds?: number;
  maximumDelayMinutes?: number;
  maxRecords?: number;
  tenantDirectoryCount?: number;
  error?: string;
}
