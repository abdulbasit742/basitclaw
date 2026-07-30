import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createEvidenceAssuranceExportApprovalStore } from '../src/evidence/evidenceAssuranceExportApprovalStore.js';
import { createEvidenceAssuranceExportApprovalRegistry } from '../src/evidence/evidenceAssuranceExportApprovalRegistry.js';
import { EvidenceValidationError } from '../src/evidence/evidenceRegistry.js';

const tenantId='tenant-registry-approval';const evidenceId=`EVD-${'4'.repeat(32)}`;const digest='5'.repeat(64);
function fixture(){const calls=[];const base={enabled:true,assuranceBundleEnabled:true,assuranceBundleStore:{recipientIds(){return['external-auditor'];}},get(){return{evidenceId,status:'active',currentVersion:1,versions:[{version:1,sha256:digest,sizeBytes:4}]};},readContent(){return{sha256:digest,sizeBytes:4};},createAssuranceBundle(_tenant,_evidence,input,context){calls.push({input,context});return{duplicate:false,bundle:{bundleId:`ASB-${'6'.repeat(32)}`,evidenceVersion:input.version,recipientId:input.recipientId}};},health(){return{status:'ready',required:true};},tenantStatus(){return{status:'ready'};}};const approvals=createEvidenceAssuranceExportApprovalStore({mode:'shared-file',required:true,directory:mkdtempSync(join(tmpdir(),'approval-registry-')),encryptionKeys:{k1:Buffer.alloc(32,61).toString('base64')},encryptionPrimaryKeyId:'k1',requiredApprovals:1});return{registry:createEvidenceAssuranceExportApprovalRegistry({registry:base,approvals}),calls};}

test('request pins immutable digest, recipient and purpose',()=>{const{registry}=fixture();const result=registry.requestAssuranceExport(tenantId,evidenceId,{version:1,recipientId:'external-auditor',purpose:'Independent regulatory assurance examination',confirmation:`REQUEST EXPORT ${evidenceId} V1 TO external-auditor`},{actor:'manager.one'});assert.equal(result.request.contentSha256,digest);assert.equal(result.request.requestedBy,'manager.one');});

test('request requires exact recipient-bound confirmation',()=>{const{registry}=fixture();assert.throws(()=>registry.requestAssuranceExport(tenantId,evidenceId,{version:1,recipientId:'external-auditor',purpose:'Independent regulatory assurance examination',confirmation:'REQUEST EXPORT'},{actor:'manager.one'}),EvidenceValidationError);});

test('approved request materialises only pinned fields and requester identity',()=>{const{registry,calls}=fixture();const request=registry.requestAssuranceExport(tenantId,evidenceId,{version:1,recipientId:'external-auditor',purpose:'Independent regulatory assurance examination',confirmation:`REQUEST EXPORT ${evidenceId} V1 TO external-auditor`},{actor:'manager.one'}).request;registry.approveAssuranceExport(tenantId,request.requestId,{actor:'admin.one'});const result=registry.createAssuranceBundle(tenantId,evidenceId,{approvalRequestId:request.requestId,confirmation:`MATERIALIZE EXPORT ${request.requestId}`},{actor:'manager.two'});assert.equal(result.approval.state,'consumed');assert.equal(calls.length,1);assert.equal(calls[0].input.recipientId,'external-auditor');assert.equal(calls[0].input.purpose,'Independent regulatory assurance examination');assert.equal(calls[0].context.actor,'manager.one');});

test('direct export payload is blocked while approval mode is enabled',()=>{const{registry}=fixture();assert.throws(()=>registry.createAssuranceBundle(tenantId,evidenceId,{version:1,recipientId:'external-auditor',purpose:'Independent regulatory assurance examination',confirmation:`EXPORT ${evidenceId} V1 TO external-auditor`},{actor:'manager.one'}),EvidenceValidationError);});
