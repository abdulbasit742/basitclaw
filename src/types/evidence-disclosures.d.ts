export type EvidenceDisclosureSigningAlgorithm = 'ed25519' | 'rsa-pss-sha256';

export interface EvidenceDisclosurePackage {
  format: 'basitclaw-assurance-disclosure-package-v1';
  version: 1;
  bundleId: string;
  recipientKeyId: string;
  wrappingAlgorithm: 'rsa-oaep-sha256';
  contentAlgorithm: 'aes-256-gcm';
  signingAlgorithm: EvidenceDisclosureSigningAlgorithm;
  signingKeyId: string;
  createdAt: string;
  expiresAt: string;
  payloadSha256: string;
  ciphertextSha256: string;
  wrappedKey: string;
  iv: string;
  tag: string;
  ciphertext: string;
  signature: string;
}

export interface EvidenceDisclosureBundleRecord {
  bundleId: string;
  evidenceId: string;
  recipientId: string;
  recipientKeyId: string;
  signingKeyId: string;
  createdAt: string;
  expiresAt: string;
  purpose: string;
  actor: string;
  manifestSha256: string;
  payloadSha256: string;
  ciphertextSha256: string;
  versionCount: number;
  rawEvidenceIncluded: false;
}

export interface EvidenceDisclosureVerification {
  valid: true;
  sealed: true;
  metadataOnly: true;
  bundleId: string;
  evidenceId: string;
  recipientId: string;
  signingKeyId: string;
  createdAt: string;
  expiresAt: string;
  manifestSha256: string;
  ciphertextSha256: string;
}

export interface EvidenceDisclosureStatus {
  status: 'disabled' | 'ready' | 'unavailable';
  enabled: boolean;
  bundleCount?: number;
  activeBundles?: number;
  expiredBundles?: number;
  orphanPackageCount?: number;
  orphanRecordCount?: number;
  metadataOnly?: true;
  offlineVerificationSupported?: true;
  operationalNotaryGovernanceRequired?: true;
  rawEvidenceIncluded: false;
  error?: string;
}

export interface CreateEvidenceDisclosureRequest {
  recipientId: string;
  idempotencyKey: string;
  purpose: string;
  expiresAt?: string;
  versions?: number[];
  includeFilenames?: boolean;
  confirmation: string;
}

export interface DisclosureTimeAttestationDecision {
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
  governance: {
    cryptographicallyValid: boolean;
    operationallyAcceptable: boolean;
    status: string;
    reasonCodes: string[];
  };
}

export interface DecryptedEvidenceDisclosurePayload {
  format: 'basitclaw-assurance-disclosure-payload-v1';
  version: 1;
  bundleId: string;
  createdAt: string;
  expiresAt: string;
  generatedBy: string;
  purpose: string;
  tenantReference: string;
  policy: {
    rawEvidenceIncluded: false;
    metadataOnly: true;
    recipientRestricted: true;
    offlineVerificationSupported: true;
  };
  evidence: {
    evidenceReference: string;
    status: string;
    currentVersion: number;
    retentionUntil: string;
    legalHoldActive: boolean;
    filenameIncluded: boolean;
    versions: Array<{
      version: number;
      filename: string | null;
      mediaType: string | null;
      sizeBytes: number;
      contentSha256: string;
      createdAt: string | null;
      screening: unknown;
      externalScans: unknown[];
      preservationReceipt: unknown;
      timeAttestations: DisclosureTimeAttestationDecision[];
      timeAttestationVerification: unknown;
    }>;
  };
  integrity: {
    registryVerification: unknown;
    versionCount: number;
    allVersionsPreserved: true;
    allVersionsTimeAttested: true;
    allVersionsOperationallyAcceptable: true;
    notaryGovernanceEvaluated: true;
    rawEvidenceIncluded: false;
  };
  manifestSha256: string;
}
