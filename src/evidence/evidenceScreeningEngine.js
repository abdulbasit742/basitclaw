import { randomUUID } from 'node:crypto';
import { extname } from 'node:path';
import { sha256, strictBase64 } from './evidenceCrypto.js';

const ENGINE_VERSION = 'basitclaw-evidence-screening/1';
const MODES = new Set(['disabled', 'observe', 'enforce']);
const ARCHIVE_POLICIES = new Set(['allow', 'review']);
const TEXT_MEDIA = /^(text\/|application\/(json|xml|javascript|x-javascript|sql|x-httpd-php))/i;
const ARCHIVE_MEDIA = new Set([
  'application/zip', 'application/x-zip-compressed', 'application/x-rar-compressed',
  'application/vnd.rar', 'application/x-7z-compressed', 'application/gzip', 'application/x-tar'
]);

const EXTENSION_MEDIA = Object.freeze({
  '.pdf': ['application/pdf'],
  '.txt': ['text/plain'],
  '.csv': ['text/csv', 'application/csv', 'text/plain'],
  '.json': ['application/json', 'text/json'],
  '.xml': ['application/xml', 'text/xml'],
  '.png': ['image/png'],
  '.jpg': ['image/jpeg'], '.jpeg': ['image/jpeg'],
  '.gif': ['image/gif'],
  '.docx': ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
  '.xlsx': ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
  '.pptx': ['application/vnd.openxmlformats-officedocument.presentationml.presentation'],
  '.zip': ['application/zip', 'application/x-zip-compressed']
});

export class EvidenceScreeningConfigurationError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = 'EvidenceScreeningConfigurationError';
    this.code = 'EVIDENCE_SCREENING_CONFIGURATION_INVALID';
    this.statusCode = 503;
    this.details = details;
  }
}

export class EvidenceScreeningError extends Error {
  constructor(message, code = 'EVIDENCE_SCREENING_FAILED', statusCode = 422, details = {}) {
    super(message);
    this.name = 'EvidenceScreeningError';
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
  }
}

export function createEvidenceScreeningEngine({
  mode = 'enforce',
  required = false,
  archivePolicy = 'review',
  maximumInspectionBytes = 10_000_000,
  now = () => new Date()
} = {}) {
  const selectedMode = String(mode ?? '').trim();
  if (!MODES.has(selectedMode)) throw new EvidenceScreeningConfigurationError('Evidence screening mode must be disabled, observe, or enforce.');
  if (required && selectedMode === 'disabled') throw new EvidenceScreeningConfigurationError('Required evidence screening cannot be disabled.', { reason: 'required_disabled' });
  const archive = String(archivePolicy ?? '').trim();
  if (!ARCHIVE_POLICIES.has(archive)) throw new EvidenceScreeningConfigurationError('Archive policy must be allow or review.');
  const maximum = integer(maximumInspectionBytes, 'maximumInspectionBytes', 1, 100_000_000);

  function screen(input = {}) {
    if (selectedMode === 'disabled') return disabledReport(input, now);
    let content;
    try { content = strictBase64(input.contentBase64, 'contentBase64'); }
    catch (error) { throw new EvidenceScreeningError('Evidence content cannot be screened because its base64 encoding is invalid.', 'EVIDENCE_SCREENING_INPUT_INVALID', 400, { field: 'contentBase64' }); }
    if (content.length > maximum) {
      throw new EvidenceScreeningError('Evidence exceeds the configured screening inspection limit.', 'EVIDENCE_SCREENING_LIMIT_EXCEEDED', 413, { maximumInspectionBytes: maximum });
    }

    const filename = String(input.filename ?? '').trim();
    const mediaType = String(input.mediaType ?? 'application/octet-stream').split(';')[0].trim().toLowerCase();
    const findings = [];
    inspectMagic(content, findings);
    inspectMedia(filename, mediaType, content, findings, archive);
    inspectText(content, mediaType, findings);
    const wouldQuarantine = findings.some((finding) => ['medium', 'high', 'critical'].includes(finding.severity));
    const decision = selectedMode === 'observe' ? 'clean' : wouldQuarantine ? 'quarantine' : 'clean';
    return Object.freeze({
      reportId: `SCR-${randomUUID().replaceAll('-', '')}`,
      engineVersion: ENGINE_VERSION,
      mode: selectedMode,
      decision,
      wouldQuarantine,
      scannedAt: now().toISOString(),
      contentSha256: sha256(content),
      sizeBytes: content.length,
      findings: findings.map((finding) => Object.freeze({ ...finding }))
    });
  }

  function health() {
    return {
      status: selectedMode === 'disabled' ? 'disabled' : 'ready',
      enabled: selectedMode !== 'disabled',
      required: Boolean(required),
      mode: selectedMode,
      engineVersion: ENGINE_VERSION,
      archivePolicy: archive,
      maximumInspectionBytes: maximum,
      deterministic: true,
      externalScanner: false
    };
  }

  return Object.freeze({ mode: selectedMode, required: Boolean(required), screen, health });
}

export function createEvidenceScreeningEngineFromEnvironment(env = process.env) {
  const mode = environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_SCREENING_MODE) ?? 'disabled';
  const required = booleanValue(environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_SCREENING_REQUIRED) ?? false, 'WORKFORCE_AUDIT_EVIDENCE_SCREENING_REQUIRED');
  return createEvidenceScreeningEngine({
    mode,
    required,
    archivePolicy: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_ARCHIVE_POLICY) ?? 'review',
    maximumInspectionBytes: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_SCREENING_MAX_BYTES)
      ?? environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_MAX_BYTES)
      ?? 10_000_000
  });
}

function inspectMagic(content, findings) {
  const prefix = content.subarray(0, 8);
  if (prefix.length >= 2 && prefix[0] === 0x4d && prefix[1] === 0x5a) add(findings, 'MALWARE_EXECUTABLE_PE', 'critical', 'malware');
  if (prefix.length >= 4 && prefix[0] === 0x7f && prefix[1] === 0x45 && prefix[2] === 0x4c && prefix[3] === 0x46) add(findings, 'MALWARE_EXECUTABLE_ELF', 'critical', 'malware');
  const mach = prefix.length >= 4 ? prefix.readUInt32BE(0) : 0;
  if ([0xfeedface, 0xfeedfacf, 0xcafebabe].includes(mach)) add(findings, 'MALWARE_EXECUTABLE_MACHO', 'critical', 'malware');
  const ascii = content.subarray(0, Math.min(content.length, 4096)).toString('latin1');
  if (ascii.includes('X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')) {
    add(findings, 'MALWARE_EICAR_TEST_SIGNATURE', 'critical', 'malware');
  }
}

function inspectMedia(filename, mediaType, content, findings, archivePolicy) {
  const extension = extname(filename).toLowerCase();
  const expected = EXTENSION_MEDIA[extension];
  if (expected && !expected.includes(mediaType)) add(findings, 'CONTENT_TYPE_EXTENSION_MISMATCH', 'high', 'content-validation');
  const zipMagic = content.length >= 4 && content[0] === 0x50 && content[1] === 0x4b && [0x03, 0x05, 0x07].includes(content[2]);
  const declaredArchive = ARCHIVE_MEDIA.has(mediaType) || extension === '.zip';
  if (archivePolicy === 'review' && (zipMagic || declaredArchive)) add(findings, 'CONTAINER_REQUIRES_DEEP_SCAN', 'medium', 'uninspectable-container');
  if (['application/javascript', 'text/javascript', 'application/x-httpd-php', 'text/x-shellscript'].includes(mediaType)) {
    add(findings, 'ACTIVE_SCRIPT_CONTENT', 'high', 'active-content');
  }
}

function inspectText(content, mediaType, findings) {
  if (!TEXT_MEDIA.test(mediaType) && !looksTextual(content)) return;
  const text = content.subarray(0, Math.min(content.length, 2_000_000)).toString('utf8');
  if (/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/.test(text)) add(findings, 'DLP_PRIVATE_KEY_MATERIAL', 'critical', 'dlp');
  if (/\bAKIA[0-9A-Z]{16}\b/.test(text)) add(findings, 'DLP_CLOUD_ACCESS_KEY', 'critical', 'dlp');
  if (/\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b/.test(text)) add(findings, 'DLP_SOURCE_CONTROL_TOKEN', 'critical', 'dlp');
  if (/<script\b|javascript:/i.test(text)) add(findings, 'ACTIVE_EMBEDDED_SCRIPT', 'high', 'active-content');
  if (/\b(?:\d[ -]*?){13,19}\b/.test(text) && containsLuhnCard(text)) add(findings, 'DLP_PAYMENT_CARD_NUMBER', 'high', 'dlp');
}

function containsLuhnCard(text) {
  const candidates = text.match(/(?:\d[ -]*?){13,19}/g) ?? [];
  return candidates.slice(0, 100).some((candidate) => {
    const digits = candidate.replace(/\D/g, '');
    if (digits.length < 13 || digits.length > 19 || /^(\d)\1+$/.test(digits)) return false;
    let sum = 0;
    let double = false;
    for (let index = digits.length - 1; index >= 0; index -= 1) {
      let value = Number(digits[index]);
      if (double) { value *= 2; if (value > 9) value -= 9; }
      sum += value;
      double = !double;
    }
    return sum % 10 === 0;
  });
}

function looksTextual(content) {
  const sample = content.subarray(0, Math.min(content.length, 8192));
  if (!sample.length) return true;
  let control = 0;
  for (const byte of sample) if (byte === 0 || (byte < 0x09) || (byte > 0x0d && byte < 0x20)) control += 1;
  return control / sample.length < 0.02;
}

function disabledReport(input, now) {
  let content = Buffer.alloc(0);
  try { content = strictBase64(input.contentBase64, 'contentBase64'); } catch {}
  return Object.freeze({
    reportId: `SCR-${randomUUID().replaceAll('-', '')}`,
    engineVersion: ENGINE_VERSION,
    mode: 'disabled',
    decision: 'clean',
    wouldQuarantine: false,
    scannedAt: now().toISOString(),
    contentSha256: sha256(content),
    sizeBytes: content.length,
    findings: []
  });
}

function add(findings, ruleId, severity, category) {
  if (!findings.some((finding) => finding.ruleId === ruleId)) findings.push({ ruleId, severity, category });
}
function integer(value, field, minimum, maximum) { const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) throw new EvidenceScreeningConfigurationError(`${field} must be an integer from ${minimum} to ${maximum}.`, { field }); return parsed; }
function booleanValue(value, field) { if (value === true || value === 'true') return true; if (value === false || value === 'false') return false; throw new EvidenceScreeningConfigurationError(`${field} must be true or false.`, { field }); }
function environmentValue(value) { const clean = typeof value === 'string' ? value.trim() : value; return clean === '' || clean === undefined || clean === null ? undefined : clean; }
