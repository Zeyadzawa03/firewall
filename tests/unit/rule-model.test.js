import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
    createRule, evaluate, analyseRules, sortRules, osRuleName, parseOsRuleName,
    needsReapply, applyPatch, describeRule, ruleMatchesConnection,
} from '../../src/firewall/rule-model.js';

function rule(overrides) {
    return createRule({
        name: overrides.name ?? 'r',
        direction: 'inbound',
        action: 'deny',
        protocol: 'tcp',
        ...overrides,
    });
}

const inbound = (overrides = {}) => ({
    direction: 'inbound',
    protocol: 'tcp',
    localAddress: '10.0.0.5',
    localPort: 22,
    remoteAddress: '203.0.113.9',
    remotePort: 51000,
    ...overrides,
});

test('first match by priority decides', () => {
    const allow = rule({ name: 'allow-ssh', action: 'allow', dstPort: '22', priority: 10 });
    const deny = rule({ name: 'deny-ssh', action: 'deny', dstPort: '22', priority: 20 });
    const result = evaluate([deny, allow], inbound());
    assert.equal(result.decision, 'allow');
    assert.equal(result.matchedRule.name, 'allow-ssh');
    assert.equal(result.matchCount, 2);
    // WFP semantics: a matching block wins regardless of order.
    assert.equal(result.wfpDecision, 'deny');
    assert.equal(result.agrees, false);
});

test('default policy applies when nothing matches', () => {
    const r = rule({ name: 'https', action: 'allow', dstPort: '443' });
    const result = evaluate([r], inbound(), { inbound: 'deny', outbound: 'allow' });
    assert.equal(result.usedDefault, true);
    assert.equal(result.decision, 'deny');
    const out = evaluate([r], inbound({ direction: 'outbound' }), { inbound: 'deny', outbound: 'allow' });
    assert.equal(out.decision, 'allow');
});

test('disabled rules never match', () => {
    const r = rule({ name: 'off', action: 'allow', dstPort: '22', enabled: false });
    assert.equal(ruleMatchesConnection(r, inbound()), false);
});

test('inbound source is the remote peer; outbound source is the local host', () => {
    const fromLan = rule({ name: 'lan', action: 'allow', srcAddress: '203.0.113.0/24', dstPort: '22' });
    assert.ok(ruleMatchesConnection(fromLan, inbound()));
    const egress = rule({ name: 'egress', direction: 'outbound', action: 'deny', dstAddress: '203.0.113.9', dstPort: '51000' });
    assert.ok(ruleMatchesConnection(egress, inbound({ direction: 'outbound' })));
});

test('analysis flags shadowed, duplicate and exposed rules', () => {
    const broad = rule({ name: 'deny-all-tcp', action: 'deny', priority: 10 });
    const shadowed = rule({ name: 'allow-web', action: 'allow', dstPort: '443', priority: 20 });
    const dup = rule({ name: 'deny-all-tcp-copy', action: 'deny', priority: 30 });
    const rdp = rule({ name: 'open-rdp', action: 'allow', dstPort: '3389', priority: 5 });
    const findings = analyseRules([broad, shadowed, dup, rdp], { sensitivePorts: [3389] });
    const types = findings.map((f) => `${f.type}:${f.ruleName}`);
    assert.ok(types.includes('shadowed:allow-web'));
    assert.ok(types.includes('duplicate:deny-all-tcp-copy'));
    assert.ok(types.includes('exposed-service:open-rdp'));
    assert.equal(findings[0].severity, 'high', 'findings are sorted most severe first');
});

test('an allow-everything rule is critical', () => {
    const r = createRule({ name: 'yolo', direction: 'inbound', action: 'allow', protocol: 'any' });
    assert.equal(analyseRules([r])[0].severity, 'critical');
});

test('sorting is by priority then creation time', () => {
    const a = rule({ name: 'a', priority: 50 });
    const b = rule({ name: 'b', priority: 10 });
    assert.deepEqual(sortRules([a, b]).map((r) => r.name), ['b', 'a']);
});

test('OS rule names round-trip the id and strip unsafe characters', () => {
    const r = rule({ name: 'Allow "web" & more' });
    const name = osRuleName(r, 'SentryFW');
    assert.match(name, /^SentryFW - Allow web  more \[rule_[a-z0-9]+\]$/);
    assert.equal(parseOsRuleName(name), r.id);
    assert.equal(parseOsRuleName('Some unrelated rule'), null);
});

test('only matching-relevant changes require a re-apply', () => {
    const r = rule({ name: 'x', dstPort: '22' });
    assert.equal(needsReapply(r, applyPatch(r, { description: 'docs only' })), false);
    assert.equal(needsReapply(r, applyPatch(r, { dstPort: '2222' })), true);
    assert.equal(applyPatch(r, { description: 'y' }).revision, 2);
});

test('describeRule is a readable one-liner', () => {
    const r = rule({ name: 'x', action: 'allow', srcAddress: '10.0.0.0/8', dstPort: '22' });
    assert.equal(describeRule(r), 'ALLOW TCP 10.0.0.0/8 → any:22');
});
