import { test } from 'node:test';
import assert from 'node:assert/strict';

import { Router, parseCookies, serializeCookie, parseQuery, RateLimiter } from '../../src/api/http.js';
import { parseArgs } from '../../src/cli/args.js';
import { safeResolve } from '../../src/core/paths.js';
import { checkOrigin, isKbAsset } from '../../src/api/server.js';

const noop = async () => null;

test('router extracts named parameters (regression: every :param route used to 404)', () => {
    const r = new Router();
    r.get('/api/rules/:id', noop);
    r.post('/api/rules/:id/enable', noop);
    assert.deepEqual(r.match('GET', '/api/rules/rule_abc123').params, { id: 'rule_abc123' });
    assert.deepEqual(r.match('POST', '/api/rules/rule_abc123/enable').params, { id: 'rule_abc123' });
    assert.deepEqual(r.match('GET', '/api/rules/rule_abc123/').params, { id: 'rule_abc123' });
});

test('router decodes encoded slashes inside a parameter', () => {
    const r = new Router();
    r.delete('/api/blocklist/:target', noop);
    assert.deepEqual(r.match('DELETE', '/api/blocklist/10.0.0.0%2F8').params, { target: '10.0.0.0/8' });
});

test('literal routes registered first win over parameters', () => {
    const r = new Router();
    r.get('/api/rules/stats', noop, { tag: 'stats' });
    r.get('/api/rules/:id', noop, { tag: 'id' });
    assert.equal(r.match('GET', '/api/rules/stats').route.meta.tag, 'stats');
});

test('router reports allowed methods on a method mismatch', () => {
    const r = new Router();
    r.get('/api/x/:id', noop);
    r.delete('/api/x/:id', noop);
    assert.deepEqual(r.match('PUT', '/api/x/1').allowed.sort(), ['DELETE', 'GET']);
    assert.equal(r.match('GET', '/api/y'), null);
});

test('router treats regex metacharacters in paths literally', () => {
    const r = new Router();
    r.get('/api/a.b', noop);
    assert.ok(r.match('GET', '/api/a.b'));
    assert.equal(r.match('GET', '/api/aXb'), null);
});

test('describe() reports declared paths', () => {
    const r = new Router();
    r.get('/api/rules/:id/', noop, { permission: 'rules:read' });
    assert.deepEqual(r.describe(), [{ method: 'GET', path: '/api/rules/:id', permission: 'rules:read', auth: true }]);
});

test('cookies parse and serialise safely', () => {
    assert.deepEqual({ ...parseCookies('a=1; b=hello%20world; junk') }, { a: '1', b: 'hello world' });
    const c = serializeCookie('s', 'v', { maxAge: 60, secure: true });
    assert.match(c, /^s=v; Path=\/; Max-Age=60; HttpOnly; SameSite=Strict; Secure$/);
});

test('query helpers coerce and clamp', () => {
    const q = parseQuery(new URLSearchParams('limit=5000&on=yes&level=warn,error&dir=INBOUND'));
    assert.equal(q.int('limit', 10, { max: 1000 }), 1000);
    assert.equal(q.bool('on'), true);
    assert.deepEqual(q.list('level'), ['warn', 'error']);
    assert.equal(q.enum('dir', ['inbound', 'outbound']), 'inbound');
    assert.equal(q.enum('missing', ['a'], 'fallback'), 'fallback');
});

test('rate limiter blocks after the window budget is spent', () => {
    const rl = new RateLimiter({ windowSeconds: 60, maxRequests: 2 });
    assert.ok(rl.check('x').ok);
    assert.ok(rl.check('x').ok);
    assert.equal(rl.check('x').ok, false);
    assert.ok(rl.check('y').ok, 'buckets are per client');
});

test('safeResolve refuses traversal', () => {
    assert.ok(safeResolve('/srv/www', 'index.html'));
    assert.equal(safeResolve('/srv/www', '../etc/passwd'), null);
    assert.equal(safeResolve('/srv/www', 'a/../../etc/passwd'), null);
});

test('origin check rejects a foreign Origin and accepts same-host', () => {
    assert.match(checkOrigin({ headers: { host: 'localhost:8787', origin: 'http://evil.example' } }), /does not match/);
    assert.equal(checkOrigin({ headers: { host: 'localhost:8787', origin: 'http://localhost:8787' } }), null);
    assert.equal(checkOrigin({ headers: { host: 'localhost:8787' } }), null);
});

test('only knowledge-base assets are served under /kb/', () => {
    assert.ok(isKbAsset('index.html'));
    assert.ok(isKbAsset('content/fg-vpn.js'));
    assert.equal(isKbAsset('package.json'), false);
    assert.equal(isKbAsset('content/../src/core/auth.js'), false);
});

test('CLI args: long, short, negated, list, number and unknown flags', () => {
    const spec = {
        flags: {
            name: { type: 'string', alias: 'n' },
            yes: { type: 'boolean', alias: 'y' },
            monitor: { type: 'boolean', default: true },
            tags: { type: 'list' },
            port: { type: 'number' },
            action: { type: 'string', choices: ['allow', 'deny'] },
        },
    };
    const { flags, positional } = parseArgs(['add', '-y', '--name=web', '--tags', 'a,b', '--tags', 'c', '--port', '80', '--no-monitor', '--', '--literal'], spec);
    assert.equal(flags.name, 'web');
    assert.equal(flags.yes, true);
    assert.equal(flags.monitor, false);
    assert.deepEqual(flags.tags, ['a', 'b', 'c']);
    assert.equal(flags.port, 80);
    assert.deepEqual(positional, ['add', '--literal']);
    assert.throws(() => parseArgs(['--bogus'], spec), /Unknown option/);
    assert.throws(() => parseArgs(['--action', 'maybe'], spec), /Expected one of/);
    assert.throws(() => parseArgs(['--port', 'eighty'], spec), /must be a number/);
    assert.throws(() => parseArgs(['--name'], spec), /requires a value/);
});
