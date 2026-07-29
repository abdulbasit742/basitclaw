export function publicEvidenceHealth(value) {
  if (!value || typeof value !== 'object') return value;
  const clone = structuredClone(value);
  redactObject(clone);
  return clone;
}

function redactObject(value) {
  if (!value || typeof value !== 'object') return;
  delete value.directory;
  delete value.primaryKeyId;
  delete value.configuredKeyIds;
  delete value.keyId;
  delete value.keys;
  if (value.mutex && typeof value.mutex === 'object') delete value.mutex.directory;
  for (const nested of Object.values(value)) {
    if (nested && typeof nested === 'object') redactObject(nested);
  }
}
