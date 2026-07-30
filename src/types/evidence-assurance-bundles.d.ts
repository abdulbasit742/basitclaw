export type AssuranceBundleState = 'pending' | 'claimed' | 'delivered' | 'expired';

export interface EvidenceAssuranceBundleRecord {
  bundleId: string;
  evidenceId: string;
  evidenceVersion: number;
  contentSha256: string;
  recipientId: string;
  recipientPublicKeyId: string;
  purpose: string;
  requestedBy: string;
  createdAt: string;
  expiresAt: string;
  state: AssuranceBundleState;
  claimedAt: string | null;
  claimExpiresAt: string | null;
  deliveredAt: string | null;
  packageSha256: string;
}

export interface SealedAssuranceBundlePackage {
  format: 'basitclaw-recipient-sealed-assurance-bundle';
  version: 1;
  algorithm: 'RSA-OAEP-SHA256+A256GCM';
  recipientPublicKeyId: string;
  iv: string;
  tag: string;
  aad: string;
  wrappedKey: string;
  ciphertext: string;
  plaintextSha256: string;
}

export interface ClaimedAssuranceBundle {
  bundleId: string;
  claimToken: string;
  expiresAt: string;
  packageSha256: string;
  sealedPackage: SealedAssuranceBundlePackage;
}

export interface EvidenceAssuranceBundleStatus {
  status: 'ready' | 'attention' | 'unavailable' | 'disabled';
  enabled: boolean;
  required: boolean;
  total?: number;
  pending?: number;
  claimed?: number;
  delivered?: number;
  expired?: number;
}

export interface CreateEvidenceAssuranceBundleRequest {
  version?: number;
  recipientId: string;
  purpose: string;
  confirmation: string;
}
