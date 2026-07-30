export type EvidenceVerificationBundleProfile = 'minimal' | 'audit';
export type EvidenceVerificationBundleAlgorithm = 'ed25519' | 'rsa-pss-sha256';

export interface EvidenceVerificationBundleSignature {
  keyId: string;
  algorithm: EvidenceVerificationBundleAlgorithm;
  publicKeySha256: string;
  value: string;
}

export interface EvidenceVerificationBundleProof {
  evidence: {
    evidenceId: string;
    version: number;
    contentSha256: string;
    sizeBytes: number;
    mediaType: string;
    retentionUntil: string;
    status: string;
    screeningStatus: string | null;
  };
  preservation: Record<string, unknown>;
  timeAttestations: {
    valid: boolean;
    quorumSatisfied: boolean;
    minimumProviders: number;
    distinctProviders: number;
    providerIds: string[];
    records: Array<Record<string, unknown>>;
  };
  auditContext?: Record<string, unknown>;
}

export interface EvidenceVerificationBundle {
  format: 'basitclaw-portable-evidence-verification-bundle';
  version: 1;
  bundleId: string;
  tenantRef: string;
  evidenceId: string;
  evidenceVersion: number;
  archiveId: string;
  profile: EvidenceVerificationBundleProfile;
  generatedAt: string;
  expiresAt: string;
  recipientRef: string;
  purposeDigest: string;
  actorRef: string;
  proofSha256: string;
  proof: EvidenceVerificationBundleProof;
  signature: EvidenceVerificationBundleSignature;
}

export interface EvidenceVerificationBundleSummary {
  bundleId: string;
  evidenceId: string;
  evidenceVersion: number;
  archiveId: string;
  profile: EvidenceVerificationBundleProfile;
  recipientRef: string;
  generatedAt: string;
  expiresAt: string;
  proofSha256: string;
  signingKeyId: string;
  signingAlgorithm: EvidenceVerificationBundleAlgorithm;
  publicKeySha256: string;
}

export interface EvidenceVerificationBundleVerification {
  valid: true;
  bundleId: string;
  evidenceId: string;
  evidenceVersion: number;
  archiveId: string;
  profile: EvidenceVerificationBundleProfile;
  recipientRef: string;
  generatedAt: string;
  expiresAt: string;
  proofSha256: string;
  signingKeyId: string;
  signingAlgorithm: EvidenceVerificationBundleAlgorithm;
  publicKeySha256: string;
  expired: boolean;
}

export interface EvidenceVerificationBundleHealth {
  status: 'ready' | 'disabled' | 'unavailable';
  enabled: boolean;
  mode: string;
  stateless?: boolean;
  rawEvidenceContentIncluded: false;
  requireTimeQuorum?: boolean;
  maximumAgeDays?: number;
  profiles?: EvidenceVerificationBundleProfile[];
  signingKeyCount?: number;
  primarySigningKeyId?: string;
  publicSigningKeys?: Record<string, {
    algorithm: EvidenceVerificationBundleAlgorithm;
    publicKeyPem: string;
    publicKeySha256: string;
  }>;
  error?: string;
}
