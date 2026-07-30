import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, generateKeyPairSync } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createEvidenceAssuranceBundleStore } from '../src/evidence/evidenceAssuranceBundleStore.js';
import {
  EvidenceAssuranceBundleVerificationError,
  verifyEvidenceAssuranceBundle
} from '../src/evidence/evidenceAssuranceBundleVerifier.js';
import { sha256 } from '../src/evidence/evidenceCrypto.js';

const tenantId='tenant-verifier';const evidenceId=`EVD-${'7'.repeat(32)}`;const recipientId='external-auditor';const secret=Buffer.alloc(48,71);
const rsa=generateKeyPairSync('rsa',{modulusLength:2048,publicKeyEncoding:{type:'spki',format:'pem'},privateKeyEncoding:{type:'pkcs8',format:'pem'}});
const otherRsa=generateKeyPairSync('rsa',{modulusLength:2048,publicKeyEncoding:{type:'spki',format:'pem'},privateKeyEncoding:{type:'pkcs8',format:'pem'}});
function stable(value){if(Array.isArray(value))return`[${value.map(stable).join(',')}]`;if(value&&typeof value==='object')return`{${Object.keys(value).sort().map((key)=>`${JSON.stringify(key)}:${stable(value[key])}`).join(',')}}`;return JSON.stringify(value);}
function signed(body,operation,timestamp,nonce){const bytes=Buffer.from(JSON.stringify(body));const canonical=[recipientId,'h1',operation,timestamp,nonce,sha256(bytes)].join('\n');return{bytes,headers:{'x-basitclaw-recipient-id':recipientId,'x-basitclaw-recipient-key-id':'h1','x-basitclaw-recipient-timestamp':timestamp,'x-basitclaw-recipient-nonce':nonce,'x-basitclaw-recipient-signature':createHmac('sha256',secret).update(canonical).digest('base64')}};}
function packageFixture({operationallyAcceptable=true,tamperSection=false}={}){const now=new Date('2026-07-30T04:00:00.000Z');const content=Buffer.from('offline assurance verifier evidence');const contentSha=sha256(content);const sections={item:{evidenceId,status:'active'},version:{version:1,sha256:contentSha,sizeBytes:content.length},verification:{valid:true,headHash:sha256('head')},assurancePosture:{cryptographicallyVerified:true,operationallyAcceptable,governedArchives:1,operationalQuorumArchives:operationallyAcceptable?1:0},content:{filename:'evidence.txt',mediaType:'text/plain',sha256:contentSha,sizeBytes:content.length,contentBase64:content.toString('base64')}};const sectionDigests=Object.fromEntries(Object.entries(sections).map(([name,value])=>[name,sha256(stable(value))]));if(tamperSection)sectionDigests.content='0'.repeat(64);const manifest={format:'basitclaw-assurance-bundle-manifest',version:1,tenantId,evidenceId,evidenceVersion:1,contentSha256:contentSha,recipientId,requestedBy:'manager.one',purpose:'Independent regulatory assurance examination',operationallyAcceptable,sectionDigests};manifest.bundleDigest=sha256(stable(manifest));const store=createEvidenceAssuranceBundleStore({mode:'pull',required:true,directory:mkdtempSync(join(tmpdir(),'verifier-bundle-')),encryptionKeys:{b1:Buffer.alloc(32,72).toString('base64')},encryptionPrimaryKeyId:'b1',recipients:{[recipientId]:{keys:{h1:secret.toString('base64')},primaryPublicKeyId:'r1',publicKeys:{r1:rsa.publicKey}}},now:()=>new Date(now)});const queued=store.queue({tenantId,evidenceId,evidenceVersion:1,contentSha256:contentSha,recipientId,requestedBy:'manager.one',purpose:manifest.purpose,manifest,evidence:sections});const claim=signed({limit:1},'claim',now.toISOString(),'verifier-claim-nonce-0001');const claimed=store.claimSigned(claim.bytes,claim.headers).bundles[0];return{claimed,queued,contentSha};}

test('verifies a production sealed package and emits a redacted report',()=>{const{claimed,queued,contentSha}=packageFixture();const report=verifyEvidenceAssuranceBundle({sealedPackage:claimed.sealedPackage,privateKeyPem:rsa.privateKey,expectedBundleId:queued.bundle.bundleId,expectedPackageSha256:claimed.packageSha256,expectedRecipientPublicKeyId:'r1'});assert.equal(report.valid,true);assert.equal(report.contentSha256,contentSha);assert.equal(report.operationallyAcceptable,true);assert.equal('contentBase64'in report,false);});

test('wrong recipient private key fails before plaintext parsing',()=>{const{claimed}=packageFixture();assert.throws(()=>verifyEvidenceAssuranceBundle({sealedPackage:claimed.sealedPackage,privateKeyPem:otherRsa.privateKey}),EvidenceAssuranceBundleVerificationError);});

test('ciphertext tampering fails AES-GCM authentication',()=>{const{claimed}=packageFixture();const sealed=structuredClone(claimed.sealedPackage);sealed.ciphertext=sealed.ciphertext.replace(/^./,sealed.ciphertext[0]==='A'?'B':'A');assert.throws(()=>verifyEvidenceAssuranceBundle({sealedPackage:sealed,privateKeyPem:rsa.privateKey}),/could not be decrypted/);});

test('manifest section digest mismatch is rejected',()=>{const{claimed}=packageFixture({tamperSection:true});assert.throws(()=>verifyEvidenceAssuranceBundle({sealedPackage:claimed.sealedPackage,privateKeyPem:rsa.privateKey}),/section content failed digest/);});

test('operationally unacceptable proof is rejected by default but can be inspected explicitly',()=>{const{claimed}=packageFixture({operationallyAcceptable:false});assert.throws(()=>verifyEvidenceAssuranceBundle({sealedPackage:claimed.sealedPackage,privateKeyPem:rsa.privateKey}),/operationally unacceptable/);const report=verifyEvidenceAssuranceBundle({sealedPackage:claimed.sealedPackage,privateKeyPem:rsa.privateKey,requireOperationallyAcceptable:false});assert.equal(report.valid,true);assert.equal(report.operationallyAcceptable,false);});
