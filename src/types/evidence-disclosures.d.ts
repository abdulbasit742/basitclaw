export type EvidenceDisclosureState = 'active' | 'expired' | 'revoked' | 'download-limit-reached';

export interface EvidenceDisclosureSelection {
  evidenceId: string;
  version: number;
}

export interface EvidenceDisclosureCreateRequest {
  recipientKeyId: string;
  recipientPublicKeyPem: string;
  expiresAt: string;
  maximumDownloads?: number;
  purpose: string;
  items: EvidenceDisclosureSelection[];
  confirmation: string;
}

export interface EvidenceDisclosureMetadata {
  packageId: string;
  createdAt: string;
  createdBy: string;
  expiresAt: string;
  maximumDownloads: number;
  downloadCount: number;
  lastDownloadedAt: string | null;
  recipientKeyId: string;
  recipientKeyFingerprint: string;
  signingKeyId: string;
  signingPublicKeyFingerprint: string;
  payloadSha256: string;
  payloadSizeBytes: number;
  packageSha256: string;
  purpose: string;
  itemCount: number;
  revokedAt: string | null;
  revokedBy: string | null;
  revocationReason: string | null;
}

export interface EvidenceDisclosurePackage {
  format: 'basitclaw-evidence-disclosure-v1';
  version: 1;
  packageId: string;
  createdAt: string;
  expiresAt: string;
  maximumDownloads: number;
  recipientKeyId: string;
  recipientKeyFingerprint: string;
  keyWrapAlgorithm: 'rsa-oaep-sha256';
  contentEncryptionAlgorithm: 'aes-256-gcm';
  signingAlgorithm: 'ed25519';
  signingKeyId: string;
  signingPublicKeyPem: string;
  signingPublicKeyFingerprint: string;
  payloadSha256: string;
  payloadSizeBytes: number;
  wrappedKey: string;
  iv: string;
  tag: string;
  ciphertext: string;
  signature: string;
}

export interface EvidenceDisclosureDownload {
  disclosure: EvidenceDisclosureMetadata;
  package: EvidenceDisclosurePackage;
}

export interface EvidenceDisclosureVerification {
  valid: true;
  disclosure: EvidenceDisclosureMetadata;
  package: {
    packageId: string;
    format: string;
    version: number;
    createdAt: string;
    expiresAt: string;
    recipientKeyId: string;
    recipientKeyFingerprint: string;
    payloadSha256: string;
    payloadSizeBytes: number;
    signingKeyId: string;
    signingPublicKeyFingerprint: string;
  };
}

export interface EvidenceDisclosureStatus {
  status: 'ready' | 'unavailable' | 'disabled';
  enabled: boolean;
  requireNotaryQuorum?: boolean;
  total?: number;
  active?: number;
  expired?: number;
  revoked?: number;
  exhausted?: number;
  error?: string;
}
