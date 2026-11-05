import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
    validateAddressSpec, validatePortSpec, validateRuleInput, validatePassword, validateUsername,
    ipMatchesSpec, portMatchesSpec, expandPortSpec, isPrivateIP, isIPv4, isIPv6, assertNoShellMeta,
} from '../../src/core/validate.js';
import { ValidationError } from '../../src/core/errors.js';

test('address specs accept any, IPs, CIDRs, ranges and lists', () => {
    assert.equal(validateAddressSpec(undefined), 'any');
    assert.equal(validateAddressSpec('*'), 'any');
    assert.equal(validateAddressSpec('ANY'), 'any');
    assert.equal(validateAddressSpec('10.0.0.1'), '10.0.0.1');
    assert.equal(validateAddressSpec('10.0.0.0/8'), '10.0.0.0/8');
    assert.ok(validateAddressSpec('10.0.0.1-10.0.0.9'));
    assert.ok(validateAddressSpec('10.0.0.1, 192.168.1.0/24'));
    assert.ok(validateAddressSpec('2001:db8::/32'));
});

test('address specs reject junk and mixed "any"', () => {
    assert.throws(() => validateAddressSpec('10.0.0.256'), ValidationError);
    assert.throws(() => validateAddressSpec('10.0.0.0/33'), ValidationError);
    assert.throws(() => validateAddressSpec('any,10.0.0.1'), ValidationError);
    assert.throws(() => validateAddressSpec('10.0.0.1; rm -rf /'), ValidationError);
});

test('port specs accept single ports, ranges and lists', () => {
    assert.equal(validatePortSpec(''), 'any');
    assert.equal(validatePortSpec('443'), '443');
    assert.ok(validatePortSpec('8000-8100'));
    assert.ok(validatePortSpec('80, 443, 8080-8090'));
    assert.throws(() => validatePortSpec('70000'), ValidationError);
    assert.throws(() => validatePortSpec('9000-8000'), ValidationError);
    assert.throws(() => validatePortSpec('0'), ValidationError);
});

test('IP and port matching', () => {
    assert.ok(ipMatchesSpec('10.1.2.3', '10.0.0.0/8'));
    assert.ok(!ipMatchesSpec('11.1.2.3', '10.0.0.0/8'));
    assert.ok(ipMatchesSpec('192.168.1.50', '192.168.1.10-192.168.1.60'));
    assert.ok(ipMatchesSpec('1.2.3.4', 'any'));
    assert.ok(portMatchesSpec(443, '80,443'));
    assert.ok(portMatchesSpec(8050, '8000-8100'));
    assert.ok(!portMatchesSpec(22, '80,443'));
    assert.deepEqual(expandPortSpec('80,443,1000-1002'), [80, 443, 1000, 1001, 1002]);
});

test('address classification', () => {
    assert.ok(isIPv4('8.8.8.8'));
    assert.ok(!isIPv4('8.8.8'));
    assert.ok(isIPv6('::1'));
    assert.ok(isPrivateIP('10.0.0.1'));
    assert.ok(isPrivateIP('172.20.1.1'));
    assert.ok(!isPrivateIP('172.32.1.1'));
    assert.ok(!isPrivateIP('8.8.8.8'));
});

test('rule input: unknown fields and ports on portless protocols are rejected', () => {
    assert.throws(() => validateRuleInput({ name: 'x', bogus: 1 }), /Unknown rule field/);
    assert.throws(() => validateRuleInput({ name: 'x', protocol: 'icmp', dstPort: '80' }), /Ports may only be specified/);
    const ok = validateRuleInput({ name: 'Web', protocol: 'tcp', dstPort: '443' });
    assert.equal(ok.direction, 'inbound');
    assert.equal(ok.action, 'deny');
    assert.equal(ok.dstPort, '443');
});

test('partial rule input only validates supplied keys', () => {
    assert.deepEqual(validateRuleInput({ priority: 5 }, { partial: true }), { priority: 5 });
});

test('password policy', () => {
    assert.throws(() => validatePassword('short'), /at least 10/);
    assert.throws(() => validatePassword('alllowercase1'), /three of/);
    assert.equal(validatePassword('Good-Pass-123'), 'Good-Pass-123');
});

test('usernames are normalised to lower case', () => {
    assert.equal(validateUsername('Alice'), 'alice');
    assert.throws(() => validateUsername('-bad'), ValidationError);
});

test('shell metacharacters are refused', () => {
    assert.throws(() => assertNoShellMeta('a; b'), ValidationError);
    assert.throws(() => assertNoShellMeta('$(whoami)'), ValidationError);
});
