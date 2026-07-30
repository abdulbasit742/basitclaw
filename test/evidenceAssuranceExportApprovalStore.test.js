import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  EvidenceAssuranceExportApprovalRequiredError,
  createEvidenceAssuranceExportApprovalStore
} from '../src/evidence/evidenceAssuranceExportApprovalStore.js';
import { EvidenceConflictError } from '../src/evidence/evidenceRegistry.js';

const tenantId='tenant-approval';
const evidenceId=`EVD-${'1'.repeat(32)}`;
const digest='2'.repeat(64);
function fixture(options={}){const directory=mkdtempSync(join(tmpdir(),'export-approvals-'));let clock=new Date('2026-07-30T03:00:00.000Z');const store=createEvidenceAssuranceExportApprovalStore({mode:'shared-file',required:true,directory,encryptionKeys:{a1:Buffer.alloc(32,44).toString('base64')},encryptionPrimaryKeyId:'a1',requiredApprovals:options.requiredApprovals??1,requestTtlMinutes:options.requestTtlMinutes??60,retention:100,now:()=>new Date(clock)});return{store,directory,get clock(){return clock;},set clock(value){clock=value;}};}
function input(overrides={}){return{tenantId,evidenceId,evidenceVersion:1,contentSha256:digest,recipientId:'external-auditor',purpose:'Independent regulatory workforce audit examination',...overrides};}
function files(directory){const rows=[];const walk=(path)=>{for(const entry of readdirSync(path,{withFileTypes:true})){const child=join(path,entry.name);entry.isDirectory()?walk(child):rows.push(child);}};walk(directory);return rows;}

test('approval records are encrypted and tenant identifiers are absent from disk',()=>{const fx=fixture();fx.store.request(input(),{actor:'manager.one'});const raw=files(fx.directory).map((path)=>readFileSync(path,'utf8')).join('\n');assert.equal(raw.includes(tenantId),false);assert.equal(raw.includes(evidenceId),false);assert.equal(raw.includes('Independent regulatory'),false);assert.equal(fx.store.health().encrypted,true);});

test('requester cannot self-approve and one distinct approver completes classic dual control',()=>{const fx=fixture();const request=fx.store.request(input(),{actor:'manager.one'}).request;assert.throws(()=>fx.store.approve(tenantId,request.requestId,{actor:'manager.one'}),EvidenceConflictError);const approved=fx.store.approve(tenantId,request.requestId,{actor:'compliance.admin'});assert.equal(approved.state,'approved');assert.equal(approved.approvals.length,1);});

test('configurable quorum requires distinct approvers',()=>{const fx=fixture({requiredApprovals:2});const request=fx.store.request(input(),{actor:'manager.one'}).request;const first=fx.store.approve(tenantId,request.requestId,{actor:'admin.one'});assert.equal(first.state,'pending');const duplicate=fx.store.approve(tenantId,request.requestId,{actor:'admin.one'});assert.equal(duplicate.approvals.length,1);const second=fx.store.approve(tenantId,request.requestId,{actor:'admin.two'});assert.equal(second.state,'approved');});

test('expired requests cannot be approved or executed',()=>{const fx=fixture({requestTtlMinutes:5});const request=fx.store.request(input(),{actor:'manager.one'}).request;fx.clock=new Date(fx.clock.getTime()+6*60_000);assert.equal(fx.store.get(tenantId,request.requestId).state,'expired');assert.throws(()=>fx.store.approve(tenantId,request.requestId,{actor:'admin.one'}),EvidenceConflictError);assert.throws(()=>fx.store.executeApproved(tenantId,request.requestId,input(),{actor:'manager.two'},()=>({})),EvidenceAssuranceExportApprovalRequiredError);});

test('approved request pins every export field and is consumed exactly once',()=>{const fx=fixture();const request=fx.store.request(input(),{actor:'manager.one'}).request;fx.store.approve(tenantId,request.requestId,{actor:'admin.one'});assert.throws(()=>fx.store.executeApproved(tenantId,request.requestId,{...input(),recipientId:'other'}, {actor:'manager.two'},()=>({})),EvidenceAssuranceExportApprovalRequiredError);const result=fx.store.executeApproved(tenantId,request.requestId,input(),{actor:'manager.two'},()=>({bundle:{bundleId:`ASB-${'3'.repeat(32)}`}}));assert.equal(result.approval.state,'consumed');assert.match(result.approval.bundleId,/^ASB-/);assert.throws(()=>fx.store.executeApproved(tenantId,request.requestId,input(),{actor:'manager.two'},()=>({})),EvidenceAssuranceExportApprovalRequiredError);});

test('failed materialisation leaves approval available for safe retry',()=>{const fx=fixture();const request=fx.store.request(input(),{actor:'manager.one'}).request;fx.store.approve(tenantId,request.requestId,{actor:'admin.one'});assert.throws(()=>fx.store.executeApproved(tenantId,request.requestId,input(),{actor:'manager.two'},()=>{throw new Error('queue outage');}),/queue outage/);assert.equal(fx.store.get(tenantId,request.requestId).state,'approved');});
