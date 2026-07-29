import { createHash } from 'node:crypto';

export function createGovernanceLedger({ now = () => new Date() } = {}) {
  const events = [];
  const importedTenants = new Set();

  function append(input) {
    assertEventInput(input);
    const tenantEvents = events.filter((event) => event.tenantId === input.tenantId);
    const previousHash = tenantEvents.at(-1)?.hash ?? null;
    const event = {
      id: `GEV-${input.tenantId}-${String(tenantEvents.length + 1).padStart(8, '0')}`,
      sequence: tenantEvents.length + 1,
      tenantId: input.tenantId,
      actor: input.actor,
      action: input.action,
      entityType: input.entityType,
      entityId: input.entityId,
      occurredAt: now().toISOString(),
      metadata: sanitiseMetadata(input.metadata ?? {}),
      previousHash
    };
    const stored = Object.freeze({ ...event, hash: hashEvent(event) });
    events.push(stored);
    return structuredClone(stored);
  }

  function importTenant(tenantId, importedEvents = []) {
    assertIdentifier(tenantId, 'tenantId');
    if (importedTenants.has(tenantId)) return;
    replaceTenant(tenantId, importedEvents);
  }

  function replaceTenant(tenantId, replacementEvents = []) {
    assertIdentifier(tenantId, 'tenantId');
    if (!Array.isArray(replacementEvents)) throw new TypeError('Replacement governance events must be an array.');
    const clones = replacementEvents.map((event) => Object.freeze(structuredClone(event)));
    for (const event of clones) {
      if (event.tenantId !== tenantId) throw new TypeError('Replacement governance event belongs to another tenant.');
    }
    const verification = verifyEvents(clones);
    if (!verification.valid) throw new TypeError(`Replacement governance chain is invalid at ${verification.failedEventId}.`);
    for (let index = events.length - 1; index >= 0; index -= 1) {
      if (events[index].tenantId === tenantId) events.splice(index, 1);
    }
    events.push(...clones);
    importedTenants.add(tenantId);
    return clones.length;
  }

  function list(tenantId, { limit = 100 } = {}) {
    assertIdentifier(tenantId, 'tenantId');
    const safeLimit = Math.max(1, Math.min(500, Number(limit) || 100));
    return exportTenant(tenantId).slice(-safeLimit);
  }

  function exportTenant(tenantId) {
    assertIdentifier(tenantId, 'tenantId');
    return events.filter((event) => event.tenantId === tenantId).map((event) => structuredClone(event));
  }

  function verify(tenantId) {
    const tenantEvents = events.filter((event) => event.tenantId === tenantId);
    return verifyEvents(tenantEvents);
  }

  function checkpoint(tenantId) {
    return events.filter((event) => event.tenantId === tenantId).length;
  }

  function rollbackTo(tenantId, checkpointLength) {
    let seen = 0;
    for (let index = 0; index < events.length; index += 1) {
      if (events[index].tenantId !== tenantId) continue;
      seen += 1;
      if (seen > checkpointLength) {
        events.splice(index, 1);
        index -= 1;
      }
    }
  }

  return { append, importTenant, replaceTenant, list, exportTenant, verify, checkpoint, rollbackTo };
}

export function hashEvent(event) {
  return createHash('sha256').update(stableStringify(event)).digest('hex');
}

function verifyEvents(tenantEvents) {
  let expectedPreviousHash = null;
  for (const event of tenantEvents) {
    const { hash, ...unsigned } = event;
    if (event.previousHash !== expectedPreviousHash || hashEvent(unsigned) !== hash) {
      return { valid: false, checkedEvents: tenantEvents.length, failedEventId: event.id, headHash: tenantEvents.at(-1)?.hash ?? null };
    }
    expectedPreviousHash = hash;
  }
  return { valid: true, checkedEvents: tenantEvents.length, failedEventId: null, headHash: tenantEvents.at(-1)?.hash ?? null };
}

function assertEventInput(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new TypeError('Governance event input must be an object.');
  for (const field of ['tenantId', 'actor', 'action', 'entityType', 'entityId']) assertIdentifier(input[field], field);
}

function assertIdentifier(value, field) {
  const text = String(value ?? '').trim();
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,191}$/.test(text)) throw new TypeError(`${field} must be a safe governance identifier.`);
}

function sanitiseMetadata(value, depth = 0) {
  if (depth > 5) throw new TypeError('Governance metadata exceeds the maximum depth.');
  if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) return value;
  if (Array.isArray(value)) return value.slice(0, 100).map((item) => sanitiseMetadata(item, depth + 1));
  if (typeof value === 'object') {
    const result = {};
    for (const [key, item] of Object.entries(value).slice(0, 100)) {
      if (item !== undefined) result[key] = sanitiseMetadata(item, depth + 1);
    }
    return result;
  }
  return String(value);
}

function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}
