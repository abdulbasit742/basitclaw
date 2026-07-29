import { createScreenedEvidenceRegistryFromEnvironment } from '../src/evidence/evidenceScreeningRegistry.js';

export function runEvidenceCommand(argv = process.argv.slice(2), env = process.env, output = console.log) {
  const [command = 'status', tenantId, argument, rawLimit] = argv;
  if (!tenantId) throw commandError('A tenant ID is required.');
  const registry = createScreenedEvidenceRegistryFromEnvironment(env);
  let result;
  if (command === 'status') {
    result = registry.tenantStatus(tenantId);
  } else if (command === 'verify') {
    result = registry.verify(tenantId, argument || null);
  } else if (command === 'list') {
    result = registry.list(tenantId, { limit: positive(argument ?? 100, 'limit', 5000) });
  } else if (command === 'events') {
    const evidenceId = argument && argument !== '-' ? argument : null;
    result = registry.events(tenantId, { evidenceId, limit: positive(rawLimit ?? 100, 'limit', 5000) });
  } else if (command === 'screening') {
    if (!argument) throw commandError('An evidence ID is required for screening.');
    result = registry.screeningReport(tenantId, argument);
  } else if (command === 'screening-events') {
    const evidenceId = argument && argument !== '-' ? argument : null;
    result = registry.screeningEvents(tenantId, { evidenceId, limit: positive(rawLimit ?? 100, 'limit', 5000) });
  } else {
    throw commandError('Command must be status, verify, list, events, screening, or screening-events.');
  }
  output(JSON.stringify(result, null, 2));
  return result;
}

function positive(value, field, maximum) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > maximum) throw commandError(`${field} must be an integer from 1 to ${maximum}.`);
  return parsed;
}
function commandError(message) { const error = new Error(message); error.code = 'EVIDENCE_COMMAND_FAILED'; return error; }

if (process.argv[1]?.endsWith('evidence-check.js')) {
  try { runEvidenceCommand(); }
  catch (error) {
    console.error(JSON.stringify({ success: false, code: error.code ?? 'EVIDENCE_COMMAND_FAILED', error: error.message }));
    process.exitCode = 1;
  }
}
