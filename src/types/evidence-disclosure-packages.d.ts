export type EvidenceDisclosureMode = 'disabled' | 'shared-file';

export interface EvidenceDisclosureRequest {
  versions?: number[];
  purpose: string;
  confirmation: string;
  includeContent?: boolean;
  recipientId?: string;
}

export interface EvidenceDisclosureSigningIdentity {
  algorithm: 'ed25519';
  keyId: string;
  publicKeyFingerprint: string;
}

export interface EvidenceDisclosureSealedContent {
  format: 'basitclaw-evidence-disclosure-sealed-content';
  version: 1;
  algorithm: 'rsa-oaep-sha256+aes-256-gcm';
  evidenceVersion: number;
  contentSha256: string;
  sizeBytes: number;
  recipientId: string;
  recipientKeyId: string;
  recipientKeyFingerprint: string;
  aad: string;
  wrappedKey: string;
  iv: string;
  tag: string;
  ciphertext: string;
  ciphertextSha256: string;
}

export interface EvidenceDisclosureNotaryGovernance {
  archiveId: string;
  evidenceVersion: number;
  effectiveVerification: {
    cryptographicallyValid: boolean;
    governanceEnabled: boolean;
    operationallyAcceptable: boolean;
    operationalQuorumSatisfied: boolean;
    acceptableAttestations: number;
    acceptableDistinctProviders: number;
    acceptableProviderIds: string[];
    rejectedAttestations: number;
    governanceEvaluatedAt?: string;
    governanceEventsConsidered?: number;
    attestationDecisions: Array<Record<string, unknown> & {
      governance: {
        cryptographicallyValid: boolean;
        operationallyAcceptable: boolean;
        status: 'acceptable' | 'revoked' | 'superseded';
        reasons: Array<Record<string, unknown>>;
      };
    }>;
  };
}

export interface EvidenceDisclosureManifest {
  format: 'basitclaw-evidence-disclosure-manifest';
  version: 1;
  evidence: {
    evidenceId: string;
    filename: string;
    mediaType: string;
    description: string;
    sourceType: string;
    sourceSystem: string | null;
    collectedAt: string;
    ingestedAt: string;
    retentionUntil: string;
    status: string;
    currentVersion: number;
    selectedVersions: Array<{
      version: number;
      sha256: string;
      sizeBytes: number;
      createdAt?: string;
      filename: string;
      mediaType: string;
    }>;
    legalHold: null | {
      active: boolean;
      placedAt: string | null;
      reviewAt: string | null;
      releasedAt: string | null;
    };
  };
  trust: {
    custody: Record<string, unknown>;
    screeningReports: Array<Record<string, unknown>>;
    externalScanAttestations: Array<Record<string, unknown>>;
    preservationReceipts: Array<Record<string, unknown>>;
    timeAttestationGovernance: EvidenceDisclosureNotaryGovernance[];
  };
  disclosurePolicy: {
    metadataOnlyDefault: true;
    contentRequiresApprovedRecipient: true;
    arbitraryRecipientKeysAccepted: false;
    plaintextPackagePersisted: false;
    revokedOrSupersededAttestationsExcludedFromOperationalQuorum: true;
  };
}

export interface EvidenceDisclosurePackage {
  format: 'basitclaw-evidence-disclosure-package';
  version: 1;
  packageId: string;
  generatedAt: string;
  tenantId: string;
  evidenceId: string;
  purpose: string;
  disclosure: {
    includeContent: boolean;
    recipientId: string | null;
    recipientKeyId: string | null;
    recipientKeyFingerprint: string | null;
  };
  manifest: EvidenceDisclosureManifest;
  sealedContents: EvidenceDisclosureSealedContent[];
  signing: EvidenceDisclosureSigningIdentity;
  signature: string;
}

export interface EvidenceDisclosureReceipt {
  packageId: string;
  evidenceId: string;
  evidenceVersions: number[];
  generatedAt: string;
  generatedBy: string;
  purpose: string;
  includeContent: boolean;
  recipientId: string | null;
  recipientKeyId: string | null;
  recipientKeyFingerprint: string | null;
  signingKeyId: string;
  signingKeyFingerprint: string;
  manifestSha256: string;
  packageSha256: string;
  sequence: number;
  previousHash: string | null;
  hash: string;
}

export interface EvidenceDisclosureGenerationResult {
  package: EvidenceDisclosurePackage;
  receipt: EvidenceDisclosureReceipt;
}

export interface EvidenceDisclosureStatus {
  status: 'disabled' | 'ready' | 'unavailable';
  enabled: boolean;
  receipts?: number;
  contentPackages?: number;
  metadataOnlyPackages?: number;
  configuredRecipients?: number;
  headSequence?: number;
  headHash?: string | null;
  error?: string;
}

export interface OfflineDisclosureVerification {
  valid: true;
  packageId: string;
  packageSha256: string;
  manifestSha256: string;
  signingKeyFingerprint: string;
  sealedContentCount: number;
  contentDecryptionPerformed: boolean;
  decryptedContents: Array<{
    evidenceVersion: number;
    filename: string;
    mediaType: string;
    contentSha256: string;
    sizeBytes: number;
    contentBase64: string;
  }>;
}
