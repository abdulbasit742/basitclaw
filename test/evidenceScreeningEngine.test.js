import test from 'node:test';
import assert from 'node:assert/strict';
import {
  EvidenceScreeningConfigurationError,
  createEvidenceScreeningEngine
} from '../src/evidence/evidenceScreeningEngine.js';

const encode = (value) => Buffer.from(value).toString('base64');

test('clean text evidence passes deterministic screening', () => {
  const engine = createEvidenceScreeningEngine({ mode: 'enforce' });
  const report = engine.screen({ filename: 'payroll.csv', mediaType: 'text/csv', contentBase64: encode('employee,total\nA,10') });
  assert.equal(report.decision, 'clean');
  assert.equal(report.findings.length, 0);
  assert.match(report.reportId, /^SCR-[a-f0-9]{32}$/);
});

test('malware and secret indicators quarantine without exposing matched values', () => {
  const engine = createEvidenceScreeningEngine({ mode: 'enforce' });
  const secret = '-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----';
  const report = engine.screen({ filename: 'notes.txt', mediaType: 'text/plain', contentBase64: encode(secret) });
  assert.equal(report.decision, 'quarantine');
  assert.ok(report.findings.some((finding) => finding.ruleId === 'DLP_PRIVATE_KEY_MATERIAL'));
  assert.equal(JSON.stringify(report).includes('not-a-real-key'), false);
});

test('EICAR and executable signatures are critical quarantine findings', () => {
  const engine = createEvidenceScreeningEngine({ mode: 'enforce' });
  const eicar = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
  const eicarReport = engine.screen({ filename: 'sample.txt', mediaType: 'text/plain', contentBase64: encode(eicar) });
  assert.equal(eicarReport.decision, 'quarantine');
  assert.ok(eicarReport.findings.some((finding) => finding.ruleId === 'MALWARE_EICAR_TEST_SIGNATURE' && finding.severity === 'critical'));

  const pe = Buffer.from([0x4d, 0x5a, 0x90, 0x00]).toString('base64');
  const executable = engine.screen({ filename: 'report.exe', mediaType: 'application/octet-stream', contentBase64: pe });
  assert.ok(executable.findings.some((finding) => finding.ruleId === 'MALWARE_EXECUTABLE_PE'));
});

test('observe mode records risk without blocking evidence', () => {
  const engine = createEvidenceScreeningEngine({ mode: 'observe' });
  const report = engine.screen({ filename: 'script.js', mediaType: 'application/javascript', contentBase64: encode('alert(1)') });
  assert.equal(report.decision, 'clean');
  assert.equal(report.wouldQuarantine, true);
  assert.ok(report.findings.length > 0);
});

test('required screening cannot be disabled', () => {
  assert.throws(
    () => createEvidenceScreeningEngine({ mode: 'disabled', required: true }),
    EvidenceScreeningConfigurationError
  );
});
