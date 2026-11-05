/**
 * End-to-end API tests: a real ApiServer on an ephemeral port, backed by a
 * throw-away data directory, driven over HTTP exactly as the GUI drives it
 * (session cookie + CSRF header).
 */

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sentryfw-it-'));
process.env.FWCTL_DATA_DIR = path.join(tmp, 'data');
process.env.FWCTL_LOG_DIR = path.join(tmp, 'logs');
process.env.FWCTL_LOG_CONSOLE = 'false';
process.env.FWCTL_MONITOR = 'false';
process.env.FWCTL_PROVIDER = 'simulated';

const { bootstrap, shutdown } = await import('../../src/bootstrap.js');
const { ApiServer } = await import('../../src/api/server.js');
const { createUser, updateUser } = await import('../../src/core/auth.js');

const ADMIN = { username: 'it-admin', password: 'Integration-Pass-1' };
const AUDITOR = { username: 'it-auditor', password: 'Integration-Pass-2' };

let server;
let base;

before(async () => {
    await bootstrap({ withAuth: true, silent: true, loadHistory: false });
    await createUser({ ...ADMIN, role: 'admin' }, 'test');
    await createUser({ ...AUDITOR, role: 'auditor' }, 'test');
    server = new ApiServer({ host: '127.0.0.1', port: 0 });
    await server.start();
    base = `http://127.0.0.1:${server.server.address().port}`;
});

after(async () => {
    await server?.stop();
    await shutdown('tests');
    fs.rmSync(tmp, { recursive: true, force: true });
});

/** Minimal cookie-jar client. */
function client() {
    let cookie = '';
    let csrf = '';
    const call = async (method, url, body, headers = {}) => {
        const res = await fetch(`${base}${url}`, {
            method,
            headers: {
                ...(cookie ? { cookie } : {}),
                ...(csrf && method !== 'GET' ? { 'x-sentryfw-csrf': csrf } : {}),
                ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
                ...headers,
            },
            body: body !== undefined ? JSON.stringify(body) : undefined,
        });
        const setCookie = res.headers.get('set-cookie');
        if (setCookie) cookie = setCookie.split(';')[0];
        const text = await res.text();
        let json = null;
        try { json = text ? JSON.parse(text) : null; } catch { /* not JSON */ }
        return { status: res.status, body: json, text, headers: res.headers };
    };
    return {
        call,
        async login(creds) {
            const res = await call('POST', '/api/auth/login', creds);
            if (res.status === 200) csrf = res.body.csrf;
            return res;
        },
        dropCsrf() { csrf = ''; },
        get: (u) => call('GET', u),
        post: (u, b = {}) => call('POST', u, b),
        patch: (u, b) => call('PATCH', u, b),
        del: (u, b) => call('DELETE', u, b),
    };
}

test('health and route inventory are public', async () => {
    const api = client();
    assert.equal((await api.get('/api/health')).status, 200);
    const inv = await api.get('/api');
    assert.equal(inv.status, 200);
    assert.ok(inv.body.routes.some((r) => r.path === '/api/rules/:id' && r.method === 'DELETE'), 'describe() keeps parameter names');
});

test('protected endpoints require a session', async () => {
    const res = await client().get('/api/rules');
    assert.equal(res.status, 401);
    assert.equal(res.body.error.code, 'UNAUTHENTICATED');
});

test('bad credentials are rejected without revealing which part was wrong', async () => {
    const res = await client().login({ username: ADMIN.username, password: 'nope-nope-nope' });
    assert.equal(res.status, 401);
    assert.equal(res.body.error.message, 'Invalid username or password');
});

test('session cookie is HttpOnly and SameSite=Strict', async () => {
    const api = client();
    const res = await api.call('POST', '/api/auth/login', ADMIN);
    assert.equal(res.status, 200);
    const cookie = res.headers.get('set-cookie');
    assert.match(cookie, /HttpOnly/);
    assert.match(cookie, /SameSite=Strict/);
});

test('rule lifecycle: create, read, patch, disable, delete (with confirmation)', async () => {
    const api = client();
    await api.login(ADMIN);

    const created = await api.post('/api/rules', {
        name: 'IT Allow SSH', direction: 'inbound', action: 'allow', protocol: 'tcp',
        srcAddress: '10.0.0.0/8', dstPort: '22', priority: 30,
    });
    assert.equal(created.status, 201);
    const id = created.body.rule.id;
    assert.match(id, /^rule_/);

    const read = await api.get(`/api/rules/${id}`);
    assert.equal(read.status, 200, 'parameterised GET route matches');
    assert.equal(read.body.dstPort, '22');

    const patched = await api.patch(`/api/rules/${id}`, { priority: 5 });
    assert.equal(patched.status, 200);
    assert.equal(patched.body.rule.priority, 5);

    const disabled = await api.post(`/api/rules/${id}/disable`);
    assert.equal(disabled.status, 200);
    assert.equal(disabled.body.rule.enabled, false);

    const unconfirmed = await api.del(`/api/rules/${id}`);
    assert.equal(unconfirmed.status, 409);
    assert.equal(unconfirmed.body.error.details.requiresConfirmation, true);

    const deleted = await api.del(`/api/rules/${id}`, { confirm: true });
    assert.equal(deleted.status, 200);
    assert.equal((await api.get(`/api/rules/${id}`)).status, 404);
});

test('duplicate rule names conflict; invalid input is a 400 with field details', async () => {
    const api = client();
    await api.login(ADMIN);
    const rule = { name: 'IT Unique', direction: 'inbound', action: 'deny', protocol: 'udp', dstPort: '161' };
    assert.equal((await api.post('/api/rules', rule)).status, 201);
    assert.equal((await api.post('/api/rules', rule)).status, 409);

    const bad = await api.post('/api/rules', { name: 'IT Bad', protocol: 'icmp', dstPort: '80' });
    assert.equal(bad.status, 400);
    assert.equal(bad.body.error.code, 'VALIDATION_ERROR');
});

test('packet tester explains the decision', async () => {
    const api = client();
    await api.login(ADMIN);
    await api.post('/api/rules', { name: 'IT Deny Telnet', direction: 'inbound', action: 'deny', protocol: 'tcp', dstPort: '23', priority: 10 });
    const res = await api.post('/api/rules/test', { direction: 'inbound', protocol: 'tcp', srcAddress: '203.0.113.7', dstPort: '23' });
    assert.equal(res.status, 200);
    assert.equal(res.body.decision, 'deny');
    assert.match(res.body.explanation, /IT Deny Telnet/);
});

test('CIDR blocklist entries can be removed through an encoded path parameter', async () => {
    const api = client();
    await api.login(ADMIN);
    const blocked = await api.post('/api/blocklist', { target: '198.51.100.0/24', reason: 'integration' });
    assert.equal(blocked.status, 200);
    assert.equal(blocked.body.rules.length, 2);

    const check = await api.get('/api/blocklist/check/198.51.100.77');
    assert.equal(check.body.blocked, true);

    const removed = await api.del(`/api/blocklist/${encodeURIComponent('198.51.100.0/24')}`);
    assert.equal(removed.status, 200);
    assert.equal((await api.get('/api/blocklist/check/198.51.100.77')).body.blocked, false);
});

test('mutations without the CSRF header are refused', async () => {
    const api = client();
    await api.login(ADMIN);
    api.dropCsrf();
    const res = await api.post('/api/rules', { name: 'IT No CSRF' });
    assert.equal(res.status, 403);
    assert.match(res.body.error.message, /CSRF/);
});

test('cross-origin mutations are refused', async () => {
    const api = client();
    await api.login(ADMIN);
    const res = await api.call('POST', '/api/rules', { name: 'IT Cross Origin' }, { origin: 'http://evil.example' });
    assert.equal(res.status, 403);
});

test('auditors can read but not write', async () => {
    const api = client();
    await api.login(AUDITOR);
    assert.equal((await api.get('/api/rules')).status, 200);
    assert.equal((await api.get('/api/audit')).status, 200);
    const res = await api.post('/api/rules', { name: 'IT Auditor Rule' });
    assert.equal(res.status, 403);
    assert.equal((await api.get('/api/users')).status, 403);
});

test('a one-time password must be changed before anything else is allowed', async () => {
    const tempPass = 'Temporary-Pass-9';
    await createUser({ username: 'it-fresh', password: tempPass, role: 'operator' }, 'test');
    await updateUser('it-fresh', { password: tempPass, mustChangePassword: true }, 'test');

    const api = client();
    const login = await api.login({ username: 'it-fresh', password: tempPass });
    assert.equal(login.body.mustChangePassword, true);

    const blocked = await api.get('/api/rules');
    assert.equal(blocked.status, 403);
    assert.equal(blocked.body.error.code, 'PASSWORD_CHANGE_REQUIRED');

    const changed = await api.post('/api/account/password', { currentPassword: tempPass, newPassword: 'Brand-New-Pass-7' });
    assert.equal(changed.status, 200);
    assert.equal((await api.get('/api/rules')).status, 200);
});

test('malformed percent-encoding is a 400, not a crash', async () => {
    const res = await client().get('/api/rules/%E0%A4%A');
    assert.equal(res.status, 400);
});

test('static files cannot escape the served directories', async () => {
    const res = await client().get('/kb/../data/users.json');
    assert.notEqual(res.status, 200);
    const kb = await client().get('/kb/content/..%2F..%2Fpackage.json');
    assert.notEqual(kb.status, 200);
});

test('audit chain stays intact across API mutations', async () => {
    const api = client();
    await api.login(ADMIN);
    const res = await api.get('/api/audit/verify');
    assert.equal(res.status, 200);
    assert.equal(res.body.valid, true);
    assert.ok(res.body.checked > 0);
});

test('backups round-trip through validate and restore', async () => {
    const api = client();
    await api.login(ADMIN);
    const created = await api.post('/api/backups', { note: 'it' });
    assert.equal(created.status, 200);
    const doc = await api.get(`/api/backups/${created.body.filename}`);
    assert.equal(doc.status, 200);
    const valid = await api.post('/api/backups/validate', { backup: doc.body });
    assert.equal(valid.body.valid, true);
    const restored = await api.post('/api/backups/restore', { filename: created.body.filename, confirm: true });
    assert.equal(restored.status, 200);
    assert.equal(restored.body.rules.imported, doc.body.rules.length);
});
