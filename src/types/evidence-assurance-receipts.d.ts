export type AssuranceReceiptAlgorithm = 'ed25519' | 'rsa-pss-sha256';

export interface AssuranceDeliveryReceiptInput {
  receivedAt: string;
  keyId: string;
  signature: string;
}

export interface AssuranceBundleAcknowledgement {
  claimToken: string;
  packageSha256: string;
  receipt: AssuranceDeliveryReceiptInput;
}

export interface AssuranceDeliveryReceipt {
  receiptId: string;
  recipientId: string;
  bundleId: string;
  packageSha256: string;
  receivedAt: string;
  acknowledgedAt: string;
  keyId: string;
  algorithm: AssuranceReceiptAlgorithm;
  publicKeyFingerprint: string;
  signature: string;
  sequence: number;
  previousHash: string | null;
  recordHash: string;
}

export interface AssuranceDeliveryReceiptVerification {
  valid: true;
  tenantId: string;
  checkedReceipts: number;
  chainHead: string | null;
}

export interface AssuranceDeliveryReceiptStatus {
  status: 'ready' | 'unavailable' | 'disabled';
  enabled: boolean;
  required: boolean;
  receipts?: number;
  chainHead?: string | null;
  error?: string;
}

export interface AssuranceBundleDeliveryMetadata {
  bundleId: string;
  state: 'pending' | 'claimed' | 'delivered' | 'expired';
  packageSha256: string;
  deliveryReceiptId: string | null;
  deliveryReceiptRecordHash: string | null;
}
