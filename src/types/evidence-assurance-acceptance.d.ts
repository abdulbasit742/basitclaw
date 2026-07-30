export type EvidenceAssuranceAcceptanceMode = 'disabled' | 'enforce';

export interface AssuranceBundleVerificationReport {
  claimToken: string;
  packageSha256: string;
  plaintextSha256: string;
  bundleDigest: string;
  sectionDigestsSha256: string;
  verifiedAt: string;
  verifierVersion: string;
}

export interface AssuranceAcceptanceReceipt {
  format: 'basitclaw-assurance-acceptance-receipt';
  version: 1;
  acceptanceId: string;
  bundleId: string;
  evidenceId: string;
  evidenceVersion: number;
  recipientId: string;
  recipientHmacKeyId: string;
  recipientPublicKeyId: string;
  packageSha256: string;
  plaintextSha256: string;
  bundleDigest: string;
  sectionDigestsSha256: string;
  contentSha256: string;
  verifiedAt: string;
  verifierVersion: string;
  verificationOutcome: 'verified';
  recipientRequestBodySha256: string;
  acknowledgedAt: string;
  recordedAt: string;
  signingAlgorithm: 'ed25519';
  signingKeyId: string;
  signingKeyFingerprint: string;
  signature: string;
}

export interface AssuranceAcceptanceResult {
  duplicate: boolean;
  bundle: {
    bundleId: string;
    evidenceId: string;
    evidenceVersion: number;
    recipientId: string;
    state: 'delivered';
    acceptanceStatus: 'verified';
    deliveredAt?: string;
  };
  acceptanceReceipt: AssuranceAcceptanceReceipt;
}

export interface AssuranceBundleVerificationResult {
  valid: true;
  bundleId: string;
  tenantId: string;
  evidenceId: string;
  evidenceVersion: number;
  recipientId: string;
  operationallyAcceptable: boolean;
  packageSha256: string;
  plaintextSha256: string;
  bundleDigest: string;
  sectionDigestsSha256: string;
  evidenceContentSha256: string;
  evidenceSizeBytes: number;
  acceptanceRequest: AssuranceBundleVerificationReport;
}

export interface AssuranceAcceptanceHealth {
  verifiedAcceptanceRequired: boolean;
  signedAcceptanceReceipts?: boolean;
  acceptanceSigningAlgorithm?: 'ed25519';
  acceptanceSigningKeyId?: string;
  acceptanceSigningKeyFingerprint?: string;
  acceptanceRecordEncryption?: 'aes-256-gcm';
  acceptanceRecordCount?: number;
  verifiedAcceptances?: number;
  deliveredUnverified?: number;
}
