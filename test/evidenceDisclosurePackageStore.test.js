import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  EvidenceDisclosureIntegrityError,
  createEvidenceDisclosurePackageStore,
  createEvidenceDisclosurePackageStoreFromEnvironment,
  verifyEvidenceDisclosurePackage
} from '../src/evidence/evidenceDisclosurePackageStore.js';
import { createEvidenceDisclosurePackageRegistry } from '../src/evidence/evidenceDisclosurePackageRegistry.js';
import { decryptSealedContents } from '../scripts/verify-evidence-disclosure-package.js';
import { sha256 } from '../src/evidence/evidenceCrypto.js';

const tenantId = 'tenant-disclosure';
const evidenceId = `EVD-${'a'.repeat(32)}`;
const storageKey = Buffer.alloc(32, 111).toString('base64');

function keys() {
  const signing = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  const recipient = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  return { signing, recipient };
}

function fixture() {
  const keyPairs = keys();
  const directory = mkdtempSync(join(tmpdir(), 'evidence-disclosure-'));
  const store = createEvidenceDisclosurePackageStore({
    mode: 'shared-file',
    directory,
    encryptionKeys: { d1: storageKey },
    encryptionPrimaryKeyId: 'd1',
    signingKeys: { s1: keyPairs.signing.privateKey },
    signingPrimaryKeyId: 's1',
    recipients: {
      regulator: {
        primaryKeyId: 'r1',
        publicKeys: { r1: keyPairs.recipient.publicKey }
      }
    },
    maxPackageBytes: 1_000_000,
    maxRecords: 100
  });
  return { store, directory, ...keyPairs };
}

function manifest() {
  return {
    format: 'basitclaw-evidence-disclosure-manifest',
    version: 1,
    evidence: {
      evidenceId,
      selectedVersions: [{ version: 1, sha256: sha256('version one'), sizeBytes: 11 }]
    },
    trust: { custody: { valid: true, headHash: 'b'.repeat(64) } }
  };
}

function issueInput(overrides = {}) {
  return {
    tenantId,
    evidenceId,
    versions: [1],
    actor: 'manager.one',
    purpose: 'External regulator evidence disclosure',
    includeContent: false,
    recipientId: null,
    manifest: manifest(),
    contents: [],
    ...overrides
  };
}

function filesUnder(directory) {
  const rows = [];
  const walk = (path) => {
    for (const entry of readdirSync(path, { withFileTypes: true })) {
      const child = join(path, entry.name);
      entry.isDirectory() ? walk(child) : rows.push(child);
    }
  };
  walk(directory);
  return rows;
}

test('metadata-only packages are Ed25519 signed and only encrypted receipts persist', () => {
  const { store, directory, signing } = fixture();
  const result = store.issue(issueInput());
  assert.equal(result.package.disclosure.includeContent, false);
  assert.deepEqual(result.package.sealedContents, []);
  assert.equal(verifyEvidenceDisclosurePackage(result.package, signing.publicKey).valid, true);
  const raw = filesUnder(directory).map((path) => readFileSync(path, 'utf8')).join('\n');
  assert.equal(raw.includes(tenantId), false);
  assert.equal(raw.includes(evidenceId), false);
  assert.equal(raw.includes('External regulator evidence disclosure'), false);
  assert.equal(raw.includes(result.package.packageId), false);
  assert.equal(store.list(tenantId, { evidenceId }).length, 1);
});

test('content packages decrypt only with the configured recipient RSA private key', () => {
  const { store, signing, recipient } = fixture();
  const content = Buffer.from('version one');
  const result = store.issue(issueInput({
    includeContent: true,
    recipientId: 'regulator',
    contents: [{
      version: 1,
      filename: 'evidence.txt',
      mediaType: 'text/plain',
      sha256: sha256(content),
      sizeBytes: content.length,
      content
    }]
  }));
  assert.equal(verifyEvidenceDisclosurePackage(result.package, signing.publicKey).valid, true);
  const decrypted = decryptSealedContents(result.package, recipient.privateKey);
  assert.equal(decrypted.length, 1);
  assert.equal(Buffer.from(decrypted[0].contentBase64, 'base64').toString('utf8'), 'version one');
  const wrongRecipient = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  assert.throws(() => decryptSealedContents(result.package, wrongRecipient.privateKey), EvidenceDisclosureIntegrityError);
});

test('content inclusion rejects unapproved recipients', () => {
  const { store } = fixture();
  const content = Buffer.from('version one');
  assert.throws(() => store.issue(issueInput({
    includeContent: true,
    recipientId: 'unknown-recipient',
    contents: [{ version: 1, filename: 'a.txt', mediaType: 'text/plain', sha256: sha256(content), sizeBytes: content.length, content }]
  })), /approved disclosure recipient/);
});

test('package tampering and encrypted receipt-index tampering fail closed', () => {
  const { store, directory, signing } = fixture();
  const result = store.issue(issueInput());
  const tampered = structuredClone(result.package);
  tampered.purpose = 'Changed after signing';
  assert.throws(() => verifyEvidenceDisclosurePackage(tampered, signing.publicKey), EvidenceDisclosureIntegrityError);
  const indexPath = filesUnder(directory).find((path) => path.endsWith('disclosure-receipts.evidence'));
  const envelope = JSON.parse(readFileSync(indexPath, 'utf8'));
  envelope.ciphertext = envelope.ciphertext.replace(/^./, envelope.ciphertext[0] === 'A' ? 'B' : 'A');
  writeFileSync(indexPath, JSON.stringify(envelope));
  assert.throws(() => store.verifyTenant(tenantId), EvidenceDisclosureIntegrityError);
});

test('enabled environment configuration requires dedicated disclosure keys', () => {
  assert.throws(() => createEvidenceDisclosurePackageStoreFromEnvironment({
    env: { WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_MODE: 'shared-file' }
  }), (error) => error.details.reason === 'missing_disclosure_configuration');
});

test('registry defaults to current-version metadata, uses guarded reads, and exports operationally acceptable notary decisions', () => {
  const { store } = fixture();
  const content = Buffer.from('version two');
  let reads = 0;
  const archiveId = `ARC-${'d'.repeat(32)}`;
  const item = {
    evidenceId,
    filename: 'evidence.txt', mediaType: 'text/plain', description: 'Evidence',
    sourceType: 'uploaded', sourceSystem: null, collectedAt: '2026-07-30T00:00:00.000Z',
    ingestedAt: '2026-07-30T00:00:01.000Z', retentionUntil: '2033-07-30T00:00:00.000Z',
    status: 'active', currentVersion: 2,
    versions: [
      { version: 1, sha256: sha256('version one'), sizeBytes: 11, filename: 'evidence.txt', mediaType: 'text/plain' },
      { version: 2, sha256: sha256(content), sizeBytes: content.length, filename: 'evidence.txt', mediaType: 'text/plain' }
    ],
    legalHold: null
  };
  const base = {
    enabled: true,
    get() { return structuredClone(item); },
    readContent(_tenant, _evidence, { version }) {
      reads += 1;
      assert.equal(version, 2);
      return { evidenceId, version, filename: 'evidence.txt', mediaType: 'text/plain', sha256: sha256(content), sizeBytes: content.length, content };
    },
    verify() { return { valid: true, headSequence: 2, headHash: 'c'.repeat(64), timeAttestationGovernance: { valid: true } }; },
    screeningReport(_tenant, _evidence, { version }) { return { version, contentSha256: item.versions[version - 1].sha256, accessDecision: 'allow' }; },
    externalScanAttestations() { return []; },
    evidencePreservationReceipts() {
      return [{ archiveId, evidenceId, evidenceVersion: 2, contentSha256: sha256(content), retentionUntil: item.retentionUntil }];
    },
    effectiveArchiveVerification() {
      return {
        valid: true,
        cryptographicallyValid: true,
        governanceEnabled: true,
        operationallyAcceptable: false,
        operationalQuorumSatisfied: false,
        minimumProviders: 1,
        acceptableDistinctProviders: 0,
        rejectedAttestations: 1,
        attestationDecisions: [{
          attestationId: `TSA-${'e'.repeat(32)}`,
          providerId: 'revoked-authority',
          governance: {
            cryptographicallyValid: true,
            operationallyAcceptable: false,
            status: 'revoked',
            reasons: [{ eventType: 'provider_revoked', reasonCode: 'authority_compromise' }]
          }
        }]
      };
    },
    health() { return { status: 'ready' }; },
    tenantStatus() { return { status: 'ready' }; }
  };
  const registry = createEvidenceDisclosurePackageRegistry({ registry: base, disclosures: store });
  const metadata = registry.generateEvidenceDisclosurePackage(tenantId, evidenceId, {
    purpose: 'Metadata package for audit committee',
    confirmation: `EXPORT ${evidenceId}`
  }, { actor: 'manager.one' });
  assert.deepEqual(metadata.receipt.evidenceVersions, [2]);
  assert.equal(reads, 0);
  const effective = metadata.package.manifest.trust.timeAttestationGovernance[0].effectiveVerification;
  assert.equal(effective.cryptographicallyValid, true);
  assert.equal(effective.operationalQuorumSatisfied, false);
  assert.equal(effective.attestationDecisions[0].governance.status, 'revoked');
  registry.generateEvidenceDisclosurePackage(tenantId, evidenceId, {
    purpose: 'Sealed package for external regulator',
    confirmation: `EXPORT ${evidenceId}`,
    includeContent: true,
    recipientId: 'regulator'
  }, { actor: 'manager.one' });
  assert.equal(reads, 1);
});
