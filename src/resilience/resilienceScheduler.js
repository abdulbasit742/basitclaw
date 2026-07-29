export function createResilienceScheduler({
  registry,
  tenantIds = [],
  intervalMinutes = 0,
  drillMaxAgeDays = 30,
  tickSeconds = 60,
  actor = 'system.scheduler',
  now = () => new Date(),
  setIntervalFn = setInterval,
  clearIntervalFn = clearInterval
} = {}) {
  if (!registry || typeof registry.runResilienceCycle !== 'function') {
    throw new TypeError('A compatible workforce-audit registry is required.');
  }
  const tenants = [...new Set(tenantIds.map(validateTenantId))];
  const backupInterval = normaliseInteger(intervalMinutes, 'Scheduled backup interval', 0, 525600);
  const drillAge = normaliseInteger(drillMaxAgeDays, 'Drill maximum age', 1, 3650);
  const tick = normaliseInteger(tickSeconds, 'Scheduler tick', 10, 86400);
  let timer = null;
  let running = false;
  let lastRunAt = null;
  let lastResult = null;
  let lastError = null;

  function runOnce() {
    if (running) return { status: 'skipped', reason: 'cycle_already_running' };
    if (backupInterval === 0) return { status: 'disabled', tenantCount: tenants.length };
    running = true;
    try {
      const result = registry.runResilienceCycle(tenants, {
        actor,
        scheduledBackupIntervalMinutes: backupInterval,
        drillMaxAgeDays: drillAge
      });
      lastRunAt = now().toISOString();
      lastResult = result;
      lastError = null;
      return result;
    } catch (error) {
      lastRunAt = now().toISOString();
      lastError = error.message;
      throw error;
    } finally {
      running = false;
    }
  }

  function start() {
    if (backupInterval === 0) return status();
    if (timer) return status();
    timer = setIntervalFn(() => {
      try { runOnce(); } catch (error) { console.error('Workforce-audit resilience cycle failed', error); }
    }, tick * 1000);
    timer.unref?.();
    return status();
  }

  function stop() {
    if (timer) clearIntervalFn(timer);
    timer = null;
    return status();
  }

  function status() {
    return {
      enabled: backupInterval > 0,
      active: Boolean(timer),
      running,
      tenantCount: tenants.length,
      intervalMinutes: backupInterval,
      drillMaxAgeDays: drillAge,
      tickSeconds: tick,
      lastRunAt,
      lastResult,
      lastError
    };
  }

  return { runOnce, start, stop, status };
}

export function createResilienceSchedulerFromEnvironment({ registry, tenantIds, env = process.env } = {}) {
  return createResilienceScheduler({
    registry,
    tenantIds,
    intervalMinutes: env.WORKFORCE_AUDIT_SCHEDULED_BACKUP_MINUTES
      ? Number(env.WORKFORCE_AUDIT_SCHEDULED_BACKUP_MINUTES)
      : 0,
    drillMaxAgeDays: env.WORKFORCE_AUDIT_DRILL_MAX_AGE_DAYS
      ? Number(env.WORKFORCE_AUDIT_DRILL_MAX_AGE_DAYS)
      : 30,
    tickSeconds: env.WORKFORCE_AUDIT_SCHEDULER_TICK_SECONDS
      ? Number(env.WORKFORCE_AUDIT_SCHEDULER_TICK_SECONDS)
      : 60
  });
}

function normaliseInteger(value, label, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new TypeError(`${label} must be an integer from ${minimum} to ${maximum}.`);
  }
  return parsed;
}

function validateTenantId(value) {
  const tenantId = String(value ?? '');
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{1,127}$/.test(tenantId)) throw new TypeError('tenantId must be a safe identifier.');
  return tenantId;
}
