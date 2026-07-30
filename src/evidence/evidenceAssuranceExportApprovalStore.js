import { randomUUID } from 'node:crypto';
import {
  closeSync, existsSync, fsyncSync, mkdirSync, openSync,
  readFileSync, readdirSync, renameSync, rmSync, writeFileSync
} from 'node:fs';
import { dirname, resolve } from 'node:path';
import { createFileMutex } from '../security/fileMutex.js';
import {
  decryptEvidenceJson, encryptEvidenceJson, parseEvidenceKeyring,
  readEvidenceJson, sha256
} from './evidenceCrypto.js';
import {
  EvidenceConflictError, EvidenceIntegrityError, EvidenceStoreError, EvidenceValidationError
} from './evidenceRegistry.js';

const FORMAT = 'basitclaw-assurance-export-approval';
const REQUEST_ID = /^AER-[a-f0-9]{32}$/;
const EVIDENCE_ID = /^EVD-[a-f0-9]{32}$/;
const MODES = new Set(['disabled', 'shared-file']);

export class EvidenceAssuranceExportApprovalStoreError extends EvidenceStoreError {
  constructor(message = 'The assurance export approval store is unavailable.', details = {}, cause = null) {
    super(message, details, cause);
    this.name = 'EvidenceAssuranceExportApprovalStoreError';
    this.code = 'EVIDENCE_ASSURANCE_EXPORT_APPROVAL_STORE_UNAVAILABLE';
  }
}

export class EvidenceAssuranceExportApprovalRequiredError extends EvidenceConflictError {
  constructor(message = 'An approved assurance export request is required.', details = {}) {
    super(message, details);
    this.name = 'EvidenceAssuranceExportApprovalRequiredError';
    this.code = 'EVIDENCE_ASSURANCE_EXPORT_APPROVAL_REQUIRED';
  }
}

export function createEvidenceAssuranceExportApprovalStore({
  mode = 'disabled',
  required = false,
  directory,
  encryptionKeys,
  encryptionPrimaryKeyId,
  requiredApprovals = 2,
  requestTtlMinutes = 1440,
  retention = 10_000,
  now = () => new Date(),
  mutex = null
} = {}) {
  const selectedMode = enumValue(mode, MODES, 'mode');
  const isRequired = booleanValue(required, 'required');
  if (selectedMode === 'disabled') {
    if (isRequired) throw new TypeError('Required assurance export approval cannot be disabled.');
    return disabledStore();
  }
  if (!String(directory ?? '').trim()) throw new TypeError('An assurance export approval directory is required.');
  const root = resolve(String(directory));
  const encryption = parseEvidenceKeyring(encryptionKeys, encryptionPrimaryKeyId);
  const quorum = integer(requiredApprovals, 'requiredApprovals', 1, 5);
  const ttlMs = integer(requestTtlMinutes, 'requestTtlMinutes', 5, 43_200) * 60_000;
  const retained = integer(retention, 'retention', 100, 100_000);
  const lock = mutex ?? createFileMutex({ directory: resolve(root, '.locks'), now });
  mkdirSync(root, { recursive: true, mode: 0o700 });

  function request(input, context = {}) {
    const source = validateRequest(input, context);
    const requestId = requestIdFor(source);
    return lock.withLock(`assurance-export-approval:${source.tenantId}`, () => {
      expireLocked(source.tenantId);
      const path = recordPath(source.tenantId, requestId);
      if (existsSync(path)) {
        const existing = readRecord(path, source.tenantId, requestId);
        assertRequestMatches(existing, source);
        return { duplicate: true, request: publicRecord(existing) };
      }
      const createdAt = now().toISOString();
      const record = {
        format: FORMAT, version: 1, requestId,
        ...source,
        state: 'pending',
        requiredApprovals: quorum,
        approvals: [],
        createdAt,
        expiresAt: new Date(new Date(createdAt).getTime() + ttlMs).toISOString(),
        rejectedAt: null, rejectedBy: null, rejectionReason: null,
        cancelledAt: null, cancelledBy: null,
        consumedAt: null, consumedBy: null, bundleId: null
      };
      writeExclusive(path, record, source.tenantId, requestId);
      pruneLocked(source.tenantId);
      return { duplicate: false, request: publicRecord(record) };
    });
  }

  function approve(tenantId, requestId, context = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = requestIdentifier(requestId);
    const approver = identifier(context.actor, 'actor');
    return mutate(tenant, id, (record) => {
      assertPending(record);
      if (approver === record.requestedBy) throw new EvidenceConflictError('The export requester cannot approve the same disclosure.', { requestId: id, reason: 'self_approval' });
      if (record.approvals.some((entry) => entry.actor === approver)) return record;
      record.approvals.push({ actor: approver, approvedAt: now().toISOString() });
      if (record.approvals.length >= record.requiredApprovals) record.state = 'approved';
      return record;
    });
  }

  function reject(tenantId, requestId, reason, context = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = requestIdentifier(requestId);
    const actor = identifier(context.actor, 'actor');
    const rejectionReason = cleanText(reason, 'reason', 10, 500);
    return mutate(tenant, id, (record) => {
      assertPending(record);
      record.state = 'rejected'; record.rejectedAt = now().toISOString();
      record.rejectedBy = actor; record.rejectionReason = rejectionReason;
      return record;
    });
  }

  function cancel(tenantId, requestId, context = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = requestIdentifier(requestId);
    const actor = identifier(context.actor, 'actor');
    return mutate(tenant, id, (record) => {
      assertPending(record);
      if (actor !== record.requestedBy) throw new EvidenceConflictError('Only the requester can cancel a pending export request.', { requestId: id });
      record.state = 'cancelled'; record.cancelledAt = now().toISOString(); record.cancelledBy = actor;
      return record;
    });
  }

  function executeApproved(tenantId, requestId, expected, context, operation) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = requestIdentifier(requestId);
    const actor = identifier(context.actor, 'actor');
    if (typeof operation !== 'function') throw new TypeError('An approved export operation is required.');
    return lock.withLock(`assurance-export-approval:${tenant}`, () => {
      expireLocked(tenant);
      const path = recordPath(tenant, id);
      if (!existsSync(path)) throw new EvidenceAssuranceExportApprovalRequiredError(undefined, { requestId: id, reason: 'not_found' });
      const record = readRecord(path, tenant, id);
      if (record.state !== 'approved') throw new EvidenceAssuranceExportApprovalRequiredError(undefined, { requestId: id, state: record.state });
      assertExpected(record, expected);
      const result = operation(publicRecord(record));
      record.state = 'consumed'; record.consumedAt = now().toISOString(); record.consumedBy = actor;
      record.bundleId = result?.bundle?.bundleId ?? null;
      replaceRecord(path, record, tenant, id);
      return { approval: publicRecord(record), result };
    });
  }

  function get(tenantId, requestId) {
    const tenant = identifier(tenantId, 'tenantId'); const id = requestIdentifier(requestId);
    return lock.withLock(`assurance-export-approval:${tenant}`, () => {
      expireLocked(tenant); const path = recordPath(tenant, id);
      if (!existsSync(path)) throw new EvidenceValidationError('The assurance export approval request was not found.', { requestId: id });
      return publicRecord(readRecord(path, tenant, id));
    });
  }

  function list(tenantId, { evidenceId = null, state = null, limit = 500 } = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const evidence = evidenceId === null ? null : evidenceIdentifier(evidenceId);
    const selectedState = state === null ? null : stateValue(state);
    const maximum = integer(limit, 'limit', 1, 5000);
    return lock.withLock(`assurance-export-approval:${tenant}`, () => {
      expireLocked(tenant);
      return recordNames(tenant).map((name) => readRecord(recordPath(tenant, name.slice(0, -9)), tenant, name.slice(0, -9)))
        .filter((record) => (!evidence || record.evidenceId === evidence) && (!selectedState || record.state === selectedState))
        .sort((a, b) => b.createdAt.localeCompare(a.createdAt)).slice(0, maximum).map(publicRecord);
    });
  }

  function status(tenantId) {
    const rows = list(tenantId, { limit: 5000 });
    const counts = { pending: 0, approved: 0, rejected: 0, cancelled: 0, expired: 0, consumed: 0 };
    for (const row of rows) counts[row.state] += 1;
    return { status: 'ready', enabled: true, required: isRequired, requiredApprovals: quorum, total: rows.length, ...counts };
  }

  function health() {
    try {
      mkdirSync(root, { recursive: true, mode: 0o700 });
      return { status: 'ready', enabled: true, required: isRequired, encrypted: true, dualControl: quorum > 1, requiredApprovals: quorum, oneTimeConsumption: true, mutex: lock.health() };
    } catch (error) { return { status: 'unavailable', enabled: true, required: isRequired, error: error?.code ?? 'assurance_export_approval_store_unavailable' }; }
  }

  function mutate(tenant, id, operation) {
    return lock.withLock(`assurance-export-approval:${tenant}`, () => {
      expireLocked(tenant); const path = recordPath(tenant, id);
      if (!existsSync(path)) throw new EvidenceValidationError('The assurance export approval request was not found.', { requestId: id });
      const record = operation(readRecord(path, tenant, id)); replaceRecord(path, record, tenant, id); return publicRecord(record);
    });
  }

  function expireLocked(tenant) {
    const current = now();
    for (const name of recordNames(tenant)) {
      const id = name.slice(0, -9); const path = recordPath(tenant, id); const record = readRecord(path, tenant, id);
      if (record.state === 'pending' && new Date(record.expiresAt) <= current) { record.state = 'expired'; replaceRecord(path, record, tenant, id); }
    }
  }

  function pruneLocked(tenant) {
    const terminal = recordNames(tenant).map((name) => { const id = name.slice(0, -9); const path = recordPath(tenant, id); return { path, record: readRecord(path, tenant, id) }; })
      .filter((entry) => ['rejected','cancelled','expired','consumed'].includes(entry.record.state))
      .sort((a,b) => terminalTime(a.record).localeCompare(terminalTime(b.record)));
    while (terminal.length > retained) rmSync(terminal.shift().path, { force: true });
  }

  function tenantRoot(tenant) { const path = resolve(root, sha256(`tenant:${tenant}`)); mkdirSync(path, { recursive: true, mode: 0o700 }); return path; }
  function recordPath(tenant, id) { return resolve(tenantRoot(tenant), `${id}.approval`); }
  function recordNames(tenant) { return readdirSync(tenantRoot(tenant)).filter((name) => name.endsWith('.approval') && REQUEST_ID.test(name.slice(0, -9))).sort(); }

  function readRecord(path, tenant, id) {
    try {
      const record = decryptEvidenceJson(readEvidenceJson(path), encryption, aad(tenant, id), EvidenceIntegrityError);
      if (!record || record.format !== FORMAT || record.version !== 1 || record.requestId !== id || record.tenantId !== tenant) throw new EvidenceIntegrityError('The assurance export approval identity is invalid.', { requestId: id });
      return record;
    } catch (error) { if (error instanceof EvidenceIntegrityError) throw error; throw new EvidenceAssuranceExportApprovalStoreError('The assurance export approval record is unreadable.', { requestId: id }, error); }
  }
  function writeExclusive(path, record, tenant, id) { writeEnvelope(path, record, tenant, id, true); }
  function replaceRecord(path, record, tenant, id) { writeEnvelope(path, record, tenant, id, false); }
  function writeEnvelope(path, record, tenant, id, exclusive) {
    const envelope = encryptEvidenceJson(record, encryption, aad(tenant,id)); mkdirSync(dirname(path),{recursive:true,mode:0o700});
    const target = exclusive ? path : `${path}.${randomUUID()}.tmp`; let descriptor=null; let created=false; let committed=false;
    try { descriptor=openSync(target,'wx',0o600); created=true; writeFileSync(descriptor,`${JSON.stringify(envelope)}\n`,'utf8'); fsyncSync(descriptor); closeSync(descriptor); descriptor=null; committed=true; if(!exclusive)renameSync(target,path); fsyncDirectory(dirname(path)); }
    catch(error){ if(descriptor!==null)try{closeSync(descriptor);}catch{} if(created&&!committed)try{rmSync(target,{force:true});}catch{} if(error?.code==='EEXIST')throw new EvidenceIntegrityError('A conflicting assurance export approval record exists.',{requestId:id}); throw new EvidenceAssuranceExportApprovalStoreError('The assurance export approval record could not be committed.',{requestId:id},error); }
  }

  return Object.freeze({ mode:selectedMode, enabled:true, required:isRequired, requiredApprovals:quorum, request, approve, reject, cancel, executeApproved, get, list, status, health });
}

export function createEvidenceAssuranceExportApprovalStoreFromEnvironment({ env = process.env } = {}) {
  const mode = envValue(env.WORKFORCE_AUDIT_ASSURANCE_EXPORT_APPROVAL_MODE) ?? 'disabled';
  const required = parseBoolean(envValue(env.WORKFORCE_AUDIT_ASSURANCE_EXPORT_APPROVAL_REQUIRED) ?? false);
  if (mode === 'disabled') return createEvidenceAssuranceExportApprovalStore({ mode, required });
  const keysRaw = envValue(env.WORKFORCE_AUDIT_ASSURANCE_EXPORT_APPROVAL_KEYS);
  const primary = envValue(env.WORKFORCE_AUDIT_ASSURANCE_EXPORT_APPROVAL_PRIMARY_KEY_ID);
  if (!keysRaw) throw new EvidenceAssuranceExportApprovalStoreError('Dedicated assurance export approval keys are required.', { reason:'missing_approval_keys' });
  if (!primary) throw new EvidenceAssuranceExportApprovalStoreError('The assurance export approval primary key ID is required.', { reason:'missing_approval_primary_key_id' });
  try { return createEvidenceAssuranceExportApprovalStore({ mode, required, directory:envValue(env.WORKFORCE_AUDIT_ASSURANCE_EXPORT_APPROVAL_DIR), encryptionKeys:JSON.parse(keysRaw), encryptionPrimaryKeyId:primary, requiredApprovals:envValue(env.WORKFORCE_AUDIT_ASSURANCE_EXPORT_REQUIRED_APPROVALS)??2, requestTtlMinutes:envValue(env.WORKFORCE_AUDIT_ASSURANCE_EXPORT_APPROVAL_TTL_MINUTES)??1440, retention:envValue(env.WORKFORCE_AUDIT_ASSURANCE_EXPORT_APPROVAL_RETENTION)??10_000 }); }
  catch(error){ if(error instanceof EvidenceAssuranceExportApprovalStoreError)throw error; throw new EvidenceAssuranceExportApprovalStoreError('Assurance export approval configuration is invalid.',{reason:error?.code??'invalid_configuration'},error); }
}

function validateRequest(input, context){ if(!input||typeof input!=='object'||Array.isArray(input))throw new EvidenceValidationError('A valid assurance export request is required.'); return { tenantId:identifier(input.tenantId,'tenantId'), evidenceId:evidenceIdentifier(input.evidenceId), evidenceVersion:integer(input.evidenceVersion,'evidenceVersion',1,1_000_000), contentSha256:hashValue(input.contentSha256,'contentSha256'), recipientId:identifier(input.recipientId,'recipientId'), purpose:cleanText(input.purpose,'purpose',10,500), requestedBy:identifier(context.actor,'actor') }; }
function requestIdFor(input){return `AER-${sha256([input.tenantId,input.evidenceId,String(input.evidenceVersion),input.contentSha256,input.recipientId,input.purpose,input.requestedBy].join('|')).slice(0,32)}`;}
function assertRequestMatches(record,input){for(const field of ['tenantId','evidenceId','evidenceVersion','contentSha256','recipientId','purpose','requestedBy'])if(record[field]!==input[field])throw new EvidenceIntegrityError('An existing export approval conflicts with this request.',{requestId:record.requestId,field});}
function assertExpected(record,expected={}){for(const field of ['evidenceId','evidenceVersion','contentSha256','recipientId','purpose'])if(expected[field]!==undefined&&record[field]!==expected[field])throw new EvidenceAssuranceExportApprovalRequiredError('The approved request does not match the export.',{requestId:record.requestId,field});}
function assertPending(record){if(record.state!=='pending'&&record.state!=='approved')throw new EvidenceConflictError('The export approval request is no longer actionable.',{requestId:record.requestId,state:record.state}); if(record.state==='approved')throw new EvidenceConflictError('The export approval quorum is already complete.',{requestId:record.requestId});}
function publicRecord(record){return {requestId:record.requestId,evidenceId:record.evidenceId,evidenceVersion:record.evidenceVersion,contentSha256:record.contentSha256,recipientId:record.recipientId,purpose:record.purpose,requestedBy:record.requestedBy,state:record.state,requiredApprovals:record.requiredApprovals,approvals:structuredClone(record.approvals),createdAt:record.createdAt,expiresAt:record.expiresAt,rejectedAt:record.rejectedAt,rejectedBy:record.rejectedBy,rejectionReason:record.rejectionReason,cancelledAt:record.cancelledAt,cancelledBy:record.cancelledBy,consumedAt:record.consumedAt,consumedBy:record.consumedBy,bundleId:record.bundleId};}
function terminalTime(record){return record.consumedAt??record.rejectedAt??record.cancelledAt??record.expiresAt;}
function aad(tenant,id){return `basitclaw:assurance-export-approval:${tenant}:${id}`;}
function fsyncDirectory(path){const descriptor=openSync(path,'r');try{fsyncSync(descriptor);}finally{closeSync(descriptor);}}
function identifier(value,field){const text=String(value??'').trim();if(!/^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{1,191}$/.test(text))throw new EvidenceValidationError(`${field} is invalid.`,{field});return text;}
function evidenceIdentifier(value){const text=String(value??'');if(!EVIDENCE_ID.test(text))throw new EvidenceValidationError('evidenceId is invalid.',{field:'evidenceId'});return text;}
function requestIdentifier(value){const text=String(value??'');if(!REQUEST_ID.test(text))throw new EvidenceValidationError('requestId is invalid.',{field:'requestId'});return text;}
function hashValue(value,field){const text=String(value??'').toLowerCase();if(!/^[a-f0-9]{64}$/.test(text))throw new EvidenceValidationError(`${field} must be a SHA-256 digest.`,{field});return text;}
function cleanText(value,field,min,max){const text=String(value??'').trim();if(text.length<min||text.length>max)throw new EvidenceValidationError(`${field} must contain ${min} to ${max} characters.`,{field});return text;}
function integer(value,field,min,max){const parsed=Number(value);if(!Number.isInteger(parsed)||parsed<min||parsed>max)throw new EvidenceValidationError(`${field} must be an integer from ${min} to ${max}.`,{field});return parsed;}
function stateValue(value){const text=String(value??'');if(!['pending','approved','rejected','cancelled','expired','consumed'].includes(text))throw new EvidenceValidationError('state is invalid.',{field:'state'});return text;}
function enumValue(value,allowed,field){const text=String(value??'');if(!allowed.has(text))throw new TypeError(`${field} must be one of ${[...allowed].join(', ')}.`);return text;}
function booleanValue(value,field){if(typeof value!=='boolean')throw new TypeError(`${field} must be true or false.`);return value;}
function parseBoolean(value){if(typeof value==='boolean')return value;if(value==='true')return true;if(value==='false')return false;throw new TypeError('Boolean environment values must be true or false.');}
function envValue(value){const clean=typeof value==='string'?value.trim():value;return clean===''||clean===undefined||clean===null?undefined:clean;}
function disabledStore(){const status=Object.freeze({status:'disabled',enabled:false,required:false,requiredApprovals:0});return Object.freeze({mode:'disabled',enabled:false,required:false,requiredApprovals:0,request(){throw new EvidenceConflictError('Assurance export approval is disabled.');},approve(){throw new EvidenceConflictError('Assurance export approval is disabled.');},reject(){throw new EvidenceConflictError('Assurance export approval is disabled.');},cancel(){throw new EvidenceConflictError('Assurance export approval is disabled.');},executeApproved(_t,_r,_e,_c,operation){return{approval:null,result:operation(null)};},get(){throw new EvidenceConflictError('Assurance export approval is disabled.');},list(){return[];},status(){return status;},health(){return status;}});}
