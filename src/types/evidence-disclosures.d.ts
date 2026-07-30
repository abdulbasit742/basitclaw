export type EvidenceDisclosureState =
  | 'requested'
  | 'approved'
  | 'sealed'
  | 'claimed'
  | 'acknowledged'
  | 'revoked'
  | 'expired'
  | 'dead_letter';

export interface EvidenceDisclosureApproval {
  actor: string;
  role: string;
  approvedAt: string;
}

export interface EvidenceDisclosureRecord {
  disclosureId: string;
  evidenceId: string;
  evidenceVersion: number;
  contentSha256: string;
  sizeBytes: number;
  recipientId: string;
  residencyZone: string;
  purpose: string;
  requestedBy: string;
  requestedByRole: string;
  requestedAt: string;
  expiresAt: string;
  state: EvidenceDisclosureState;
  approvals: EvidenceDisclosureApproval[];
  sealedAt: string | null;
  claimedAt: string | null;
  acknowledgedAt: string | null;
  revokedAt: string | null;
  chainHead: string | null;
  eventCount: number;
}

export interface RecipientSealedEvidencePackage {
  format: 'basitclaw-recipient-sealed-evidence-v1';
  disclosureId: string;
  tenantId: string;
  evidenceId: string;
  evidenceVersion: number;
  contentSha256: string;
  sizeBytes: number;
  recipientId: string;
  residencyZone: string;
  purpose: string;
  filename: string;
  mediaType: string;
  sealedAt: string;
  expiresAt: string;
  algorithm: 'aes-256-gcm+rsa-oaep-sha256';
  publicKeyId: string;
  iv: string;
  tag: string;
  ciphertext: string;
  wrappedKey: string;
}

export interface EvidenceDisclosureClaim extends EvidenceDisclosureRecord {
  claimToken: string;
  package: RecipientSealedEvidencePackage;
}

export interface EvidenceDisclosureReport {
  total: number;
  byState: Record<EvidenceDisclosureState, number>;
  byRecipient: Record<string, number>;
  byResidencyZone: Record<string, number>;
  approvalQuorum: number;
}

export interface EvidenceDisclosureHealth {
  status: 'disabled' | 'ready' | 'attention' | 'unavailable';
  enabled: boolean;
  mode: 'disabled' | 'shared-file-governed-disclosure';
  encryptedRecords?: boolean;
  recipientSealedPackages?: boolean;
  dualApproval?: boolean;
  approvalQuorum: number;
  recipients?: number;
  maximumPackageBytes?: number;
  error?: string;
}
