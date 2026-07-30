import { access, readFile } from 'node:fs/promises';

const requiredFiles = [
  'src/evidence/evidenceAssuranceReceiptStore.js',
  'src/evidence/evidenceAssuranceBundleStore.js',
  'src/evidence/evidenceAssuranceBundleRegistry.js',
  'src/evidence/evidenceAssuranceBundleHandler.js',
  'src/types/evidence-assurance-receipts.d.ts',
  'test/evidenceAssuranceReceiptStore.test.js',
  'test/evidenceAssuranceReceiptIntegration.test.js',
  'docs/assurance-delivery-receipts.md',
  'docs/evidence-assurance-bundles.md',
  'config/evidence-screening.production.env.example'
];
for (const file of requiredFiles) await access(new URL(`../${file}`, import.meta.url));

async function requireMarkers(path, label, markers) {
  const content = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');
  for (const marker of markers) {
    if (!content.includes(marker)) throw new Error(`${label} build verification failed: missing ${marker}.`);
  }
}

await requireMarkers('src/evidence/evidenceAssuranceReceiptStore.js', 'Assurance receipt store', [
  'basitclaw-assurance-delivery-receipt-v1',
  'encrypted-recipient-signed-delivery-receipts',
  'ed25519',
  'rsa-pss-sha256',
  'RSA_PKCS1_PSS_PADDING',
  'receipt_time_window',
  'signature_mismatch',
  'previousHash',
  'recordHash',
  'hashChained: true',
  'appendOnly: true',
  'missing_receipt_keys',
  'missing_recipients'
]);
await requireMarkers('src/evidence/evidenceAssuranceBundleStore.js', 'Receipt-before-delete ordering', [
  "new Set(['claimToken', 'packageSha256', 'receipt'])",
  'A recipient-signed delivery receipt is required.',
  'deliveryReceipts.verifyAndRecord',
  "record.state = 'delivered'",
  'record.sealedPackage = null',
  'deliveryReceiptId',
  'deliveryReceiptRecordHash',
  'createEvidenceAssuranceReceiptStoreFromEnvironment'
]);
await requireMarkers('src/evidence/evidenceAssuranceBundleRegistry.js', 'Receipt governance registry', [
  'assuranceDeliveryReceipts',
  'assuranceDeliveryReceipt',
  'verifyAssuranceDeliveryReceipts',
  'assuranceDeliveryReceiptEnabled'
]);
await requireMarkers('src/evidence/evidenceAssuranceBundleHandler.js', 'Receipt governance API', [
  '/api/workforce-audit/assurance-delivery-receipts',
  '/verify',
  'assurance_receipt.signature_failed',
  'chain_verified',
  'deliveryReceiptId'
]);
await requireMarkers('test/evidenceAssuranceReceiptIntegration.test.js', 'Receipt ordering regressions', [
  'required recipient signature is committed before sealed package deletion',
  'missing required receipt leaves the claimed bundle undelivered',
  'invalid recipient signature never marks the bundle delivered',
  'receipt journal commit survives an interrupted bundle update'
]);
await requireMarkers('docs/assurance-delivery-receipts.md', 'Receipt runbook', [
  'committed before the sealed package is removed',
  'basitclaw-assurance-delivery-receipt-v1',
  'RSA-PSS-SHA256',
  'There is no receipt deletion API',
  'qualified electronic signature'
]);
await requireMarkers('config/evidence-screening.production.env.example', 'Receipt production configuration', [
  'WORKFORCE_AUDIT_ASSURANCE_RECEIPT_MODE=shared-file',
  'WORKFORCE_AUDIT_ASSURANCE_RECEIPT_REQUIRED=true',
  'WORKFORCE_AUDIT_ASSURANCE_RECEIPT_KEYS=',
  'receiptKeys',
  'Fail closed: a valid asymmetric receipt is committed before sealed package deletion.'
]);

console.log('Assurance recipient-signed delivery receipt build verification passed.');
