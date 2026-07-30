import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createEvidenceAssuranceExportApprovalAwareApp } from '../src/evidence/evidenceAssuranceExportApprovalServer.js';

test('enabled export approvals cannot start without assurance bundle delivery',()=>{const baseApp=createServer((_req,res)=>res.end());baseApp.authenticationGateway={authenticate(){},authorise(){}};assert.throws(()=>createEvidenceAssuranceExportApprovalAwareApp({evidenceRegistry:{assuranceExportApprovalEnabled:true,assuranceBundleEnabled:false},baseApp,rateLimiter:null,approvalHandler:{matches(){return false;},handle(){}}}),/require enabled assurance bundle delivery/);baseApp.close();});
