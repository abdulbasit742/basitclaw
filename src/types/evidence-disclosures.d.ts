export type EvidenceDisclosureState = 'pending' | 'packaged' | 'rejected' | 'revoked' | 'expired';

export interface EvidenceDisclosureSelection {
  evidenceId: string;
  version: number;
  contentSha256: string;
  sizeBytes: number;
  preservationArchiveId: string | null;
  preservationReceiptSha256: string | null;
  timeAttestationProviders: string[];
}

export interface EvidenceDisclosureApproval {
  actor: string;
  reason: string;
  approvedAt: string;
}

export interface EvidenceDisclosureRequest {
  requestId: string;
  state: EvidenceDisclosureState;
  requestedBy: string;
  requestedAt: string;
  expiresAt: string;
  recipientId: string;
  recipientKeyId: string;
  recipientKeyFingerprint: string;
  caseReference: string;
  purpose: string;
  evidence: EvidenceDisclosureSelection[];
  approvals: EvidenceDisclosureApproval[];
  minimumApprovers: number;
  packageId: string | null;
  packagedAt: string | null;
  rejectedAt: string | null;
  rejectedBy: string | null;
  rejectionReason: string | null;
  revokedAt: string | null;
  revokedBy: string | null;
  revocationReason: string | null;
}

export interface EvidenceDisclosurePackage {
  format: 'basitclaw-evidence-disclosure-package';
  version: 1;
  packageId: string;
  requestId: string;
  algorithm: 'RSA-OAEP-SHA256+A256GCM';
  recipientKeyId: string;
  recipientKeyFingerprint: string;
  aad: string;
  wrappedKey: string;
  iv: string;
  authTag: string;
  ciphertext: string;
  plaintextSha256: string;
  evidenceCount: number;
  sealedAt: string;
  expiresAt: string;
}

export interface EvidenceDisclosureStatus {
  status: 'disabled' | 'ready' | 'unavailable';
  enabled: boolean;
  minimumApprovers?: number;
  total?: number;
  pending?: number;
  packaged?: number;
  rejected?: number;
  revoked?: number;
  expired?: number;
  headSequence?: number;
  headHash?: string | null;
  error?: string;
}

export interface EvidenceDisclosureEvent {
  eventId: string;
  sequence: number;
  previousHash: string | null;
  hash: string;
  type: string;
  requestId: string;
  actor: string;
  occurredAt: string;
  details: Record<string, unknown>;
}
