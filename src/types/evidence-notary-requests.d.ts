export type EvidenceNotaryRequestState =
  | 'pending'
  | 'inflight'
  | 'delivered'
  | 'completed'
  | 'dead-letter';

export interface EvidenceNotaryChallenge {
  tenantId: string;
  archiveId: string;
  receiptSha256: string;
  objectEnvelopeSha256: string;
  archivedAt: string;
  retentionUntil: string;
}

export interface EvidenceNotaryRequestJob {
  jobId: string;
  providerId: string;
  archiveId: string;
  state: EvidenceNotaryRequestState;
  createdAt: string;
  updatedAt: string;
  expiresAt: string;
  attempts: number;
  nextAttemptAt: string;
  claimedAt: string | null;
  claimExpiresAt: string | null;
  deliveredAt: string | null;
  completedAt: string | null;
  deadLetteredAt: string | null;
  queuedBy: string;
  purpose: string;
  result: Record<string, unknown> | null;
  hash: string;
}

export interface EvidenceNotaryRequestClaim {
  jobId: string;
  claimToken: string;
  claimExpiresAt: string;
  challenge: EvidenceNotaryChallenge;
}

export interface EvidenceNotaryRequestStatus {
  status: 'disabled' | 'ready' | 'attention' | 'degraded' | 'unavailable';
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

export interface EvidenceNotaryRequestHealth extends EvidenceNotaryRequestStatus {
  durable?: boolean;
  encryptedRecords?: boolean;
  plaintextEvidenceQueued?: false;
  evidenceBytesQueued?: false;
  arbitraryOutboundUrls?: false;
  asymmetricRequestAuthentication?: boolean;
  requestReplayProtected?: boolean;
  providerPartitioned?: boolean;
  transitionHashChain?: boolean;
  providerCount?: number;
  jobTtlMinutes?: number;
  claimLeaseMs?: number;
  maxAttempts?: number;
  totalJobs?: number;
  replayEntries?: number;
}

export interface SignedEvidenceNotaryRequestBase {
  action: 'claim' | 'acknowledge' | 'fail';
  providerId: string;
  keyId: string;
  timestamp: string;
  nonce: string;
  signature: string;
}

export interface SignedEvidenceNotaryClaimRequest extends SignedEvidenceNotaryRequestBase {
  action: 'claim';
  limit?: number;
}

export interface SignedEvidenceNotaryAcknowledgeRequest extends SignedEvidenceNotaryRequestBase {
  action: 'acknowledge';
  jobId: string;
  claimToken: string;
}

export interface SignedEvidenceNotaryFailureRequest extends SignedEvidenceNotaryRequestBase {
  action: 'fail';
  jobId: string;
  claimToken: string;
  retryable: boolean;
  reasonCode: string;
}
