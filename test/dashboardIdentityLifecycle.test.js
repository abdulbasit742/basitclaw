import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('dashboard identity lifecycle script compiles and exposes review indicators', async () => {
  const html = await readFile(new URL('../public/workforce-audit.html', import.meta.url), 'utf8');
  const match = html.match(/<script>([\s\S]*?)<\/script>/i);
  assert.ok(match, 'dashboard must contain an inline script');
  assert.doesNotThrow(() => new Function(match[1]));
  for (const marker of ['Identity lifecycle', 'Review posture', 'Provisioned identities', 'Suspended identities', 'Reviews overdue']) {
    assert.ok(html.includes(marker), `dashboard must include ${marker}`);
  }
  assert.ok(html.includes('session.entitlementStatus'));
  assert.ok(html.includes('security?.credentials?.identityEntitlements'));
});
