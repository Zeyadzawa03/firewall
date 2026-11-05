/**
 * Firewall manager + blocklist against the in-memory test seams and the
 * simulated provider. Nothing touches disk or the host firewall.
 */

import { test, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const tmp = path.join(os.tmpdir(), `sentryfw-unit-${process.pid}`);
process.env.FWCTL_DATA_DIR = path.join(tmp, 'data');
process.env.FWCTL_LOG_DIR = path.join(tmp, 'logs');
process.env.FWCTL_LOG_CONSOLE = 'false';

const { loadConfig, __setConfigForTests } = await import('../../src/core/config.js');
const store = await import('../../src/firewall/rule-store.js');
const manager = await import('../../src/firewall/manager.js');
const blocklist = await import('../../src/monitoring/blocklist.js');
const { __setProviderForTests } = await import('../../src/firewall/providers/index.js');
const { SimulatedProvider } = await import('../../src/firewall/providers/simulated.js');
const { __resetAudit } = await import('../../src/core/audit.js');
const { __resetLog } = await import('../../src/core/logger.js');

const baseConfig = loadConfig({ refresh: true });
let provider;

function useConfig(patch = {}) {
    const cfg = structuredClone(baseConfig);
    cfg.logging.console = false;
    cfg.firewall = { ...cfg.firewall, ...patch };
    __setConfigForTests(cfg);
}

beforeEach(() => {
    useConfig({ applyToOS: false });
    store.__setRulesForTests([]);
    blocklist.__setBlocklistForTests([]);
    provider = new SimulatedProvider();
    __setProviderForTests(provider, 'simulated');
    __resetAudit();
    __resetLog();
});

after(() => fs.rmSync(tmp, { recursive: true, force: true }));

const ctx = { actor: 'unit', source: 'test' };

test('creating a rule with applyToOS off stores it but leaves the OS untouched', async () => {
    const { rule, os: osResult } = await manager.createRuleAndApply({ name: 'Web', protocol: 'tcp', dstPort: '443', action: 'allow' }, ctx);
    assert.equal(osResult.skipped, true);
    assert.equal(rule.osApplied, false);
    assert.equal(provider.shadow.size, 0);
    assert.equal(manager.stats().total, 1);
});

test('with applyToOS on, create/disable/delete are mirrored in the provider', async () => {
    useConfig({ applyToOS: true });
    const { rule } = await manager.createRuleAndApply({ name: 'SSH', protocol: 'tcp', dstPort: '22', action: 'allow' }, ctx);
    assert.equal(store.getRule(rule.id).osApplied, true);
    assert.equal(provider.shadow.get(rule.osRuleName).enabled, true);

    await manager.setEnabled(rule.id, false, ctx);
    assert.equal(provider.shadow.get(rule.osRuleName).enabled, false);

    await manager.deleteRule(rule.id, ctx);
    assert.equal(provider.shadow.size, 0);
    assert.equal(manager.stats().total, 0);
});

test('renaming an applied rule retires the old OS rule', async () => {
    useConfig({ applyToOS: true });
    const { rule } = await manager.createRuleAndApply({ name: 'Old name', protocol: 'tcp', dstPort: '80' }, ctx);
    const oldOsName = rule.osRuleName;
    const { rule: renamed } = await manager.updateRule(rule.id, { name: 'New name' }, ctx);
    assert.ok(!provider.shadow.has(oldOsName));
    assert.ok(provider.shadow.has(renamed.osRuleName));
});

test('sync reports drift and repair fixes it', async () => {
    useConfig({ applyToOS: true });
    const { rule } = await manager.createRuleAndApply({ name: 'Drifty', protocol: 'tcp', dstPort: '8080', action: 'allow' }, ctx);
    provider.shadow.get(rule.osRuleName).action = 'deny';

    const drift = await manager.sync(ctx);
    assert.equal(drift.inSync, false);
    assert.equal(drift.drift[0].type, 'modified-in-os');

    await manager.sync({ repair: true, ...ctx });
    assert.equal((await manager.sync(ctx)).inSync, true);
});

test('reorder rewrites priorities in the requested order', async () => {
    const a = (await manager.createRuleAndApply({ name: 'A', priority: 10 }, ctx)).rule;
    const b = (await manager.createRuleAndApply({ name: 'B', priority: 20 }, ctx)).rule;
    await manager.reorder([b.id, a.id], ctx);
    assert.deepEqual(store.allRules().map((r) => r.name), ['B', 'A']);
});

test('import replaces the rule set and rejects duplicates atomically', async () => {
    await manager.createRuleAndApply({ name: 'Keep me' }, ctx);
    await assert.rejects(
        manager.importRules({ rules: [{ name: 'Dup' }, { name: 'dup' }] }, ctx),
        /Duplicate rule name/,
    );
    assert.equal(store.allRules()[0].name, 'Keep me', 'a failed import changes nothing');
    const res = await manager.importRules({ rules: [{ name: 'One' }, { name: 'Two' }] }, ctx);
    assert.deepEqual(res, { replaced: 1, imported: 2 });
});

test('test packet rejects ranges and explains default-policy decisions', () => {
    assert.throws(() => manager.testPacket({ direction: 'inbound', protocol: 'tcp', dstPort: '80-90' }), /single value/);
    const res = manager.testPacket({ direction: 'inbound', protocol: 'tcp', srcAddress: '1.2.3.4', dstPort: '80' });
    assert.equal(res.usedDefault, true);
    assert.match(res.explanation, /default inbound policy/);
});

test('blocking an address creates priority-1 deny rules in both directions', async () => {
    const { entry, rules } = await blocklist.block({ target: '203.0.113.50', reason: 'unit' }, ctx);
    assert.equal(rules.length, 2);
    const created = store.allRules();
    assert.ok(created.every((r) => r.action === 'deny' && r.priority === 1));
    assert.ok(blocklist.isBlocked('203.0.113.50'));
    await assert.rejects(blocklist.block({ target: '203.0.113.50' }, ctx), /already on the blocklist/);

    await blocklist.unblock(entry.target, ctx);
    assert.equal(blocklist.isBlocked('203.0.113.50'), null);
    assert.equal(store.allRules().length, 0, 'backing rules are removed with the entry');
});

test('blocking a CIDR covers addresses inside it', async () => {
    await blocklist.block({ target: '198.51.100.0/24' }, ctx);
    assert.ok(blocklist.isBlocked('198.51.100.200'));
    assert.equal(blocklist.isBlocked('198.51.101.1'), null);
});
