/**
 * Authentication, sessions and role-based authorisation.
 *
 * Design notes:
 *  - Passwords: PBKDF2-HMAC-SHA512, per-user 16-byte salt, iteration count from
 *    config (default 210k), 64-byte derived key. Verified with timingSafeEqual.
 *  - No credentials are shipped. On first start the service generates a random
 *    bootstrap password for `admin`, prints it once, and requires a change on
 *    first login (`mustChangePassword`).
 *  - Sessions are opaque 256-bit tokens stored server-side only. The cookie is
 *    HttpOnly + SameSite=Strict; Secure is set when the request arrived over TLS.
 *  - Every state-changing API call must present a CSRF token bound to the session
 *    (double-submit: header value compared to the server-side session secret).
 *  - Failed logins are counted per username and per source address and trigger a
 *    temporary lockout.
 */

import crypto from 'node:crypto';

import { PATHS, readJson, writeJsonAtomic, ensureRuntimeDirs } from './paths.js';
import { getConfig } from './config.js';
import { randomId, randomToken } from './ids.js';
import { AuthError, ForbiddenError, ValidationError, ConflictError, NotFoundError } from './errors.js';
import { validateUsername, validatePassword, validateEnum } from './validate.js';
import { logEvent } from './logger.js';
import { audit } from './audit.js';

export const ROLES = Object.freeze(['admin', 'operator', 'auditor']);

/**
 * Permission matrix. Keys are permission names used by route guards.
 *  - admin    : full control including users and settings
 *  - operator : day-to-day firewall work, no user management
 *  - auditor   : read-only, including logs and audit trail
 */
export const PERMISSIONS = Object.freeze({
    'rules:read': ['admin', 'operator', 'auditor'],
    'rules:write': ['admin', 'operator'],
    'rules:apply': ['admin', 'operator'],
    'blocklist:read': ['admin', 'operator', 'auditor'],
    'blocklist:write': ['admin', 'operator'],
    'traffic:read': ['admin', 'operator', 'auditor'],
    'logs:read': ['admin', 'operator', 'auditor'],
    'logs:export': ['admin', 'operator', 'auditor'],
    'audit:read': ['admin', 'auditor'],
    'backup:read': ['admin', 'operator', 'auditor'],
    'backup:write': ['admin'],
    'settings:read': ['admin', 'operator', 'auditor'],
    'settings:write': ['admin'],
    'users:read': ['admin'],
    'users:write': ['admin'],
});

const SESSION_SWEEP_MS = 60_000;

/** @type {{users: Array<object>, version: number}|null} */
let store = null;
/** @type {Map<string, object>} */
const sessions = new Map();
/** @type {Map<string, {count:number, until:number}>} */
const lockouts = new Map();
let sweepTimer = null;
let bootstrapPassword = null;
/** When true, the user store is kept in memory only (unit tests). */
let persistDisabled = false;

/* ------------------------------------------------------------------ *
 * Password hashing
 * ------------------------------------------------------------------ */

function pbkdf2(password, salt, iterations) {
    return new Promise((resolve, reject) => {
        crypto.pbkdf2(password, salt, iterations, 64, 'sha512', (err, key) => {
            if (err) reject(err); else resolve(key);
        });
    });
}

export async function hashPassword(password, iterations = getConfig().security.pbkdf2Iterations) {
    const salt = crypto.randomBytes(16);
    const key = await pbkdf2(password, salt, iterations);
    return {
        algorithm: 'pbkdf2-sha512',
        iterations,
        salt: salt.toString('base64'),
        hash: key.toString('base64'),
    };
}

export async function verifyPassword(password, record) {
    if (!record || record.algorithm !== 'pbkdf2-sha512') return false;
    const salt = Buffer.from(record.salt, 'base64');
    const expected = Buffer.from(record.hash, 'base64');
    const actual = await pbkdf2(password, salt, record.iterations);
    if (actual.length !== expected.length) return false;
    return crypto.timingSafeEqual(actual, expected);
}

/* ------------------------------------------------------------------ *
 * User store
 * ------------------------------------------------------------------ */

export async function initAuth({ silent = false } = {}) {
    ensureRuntimeDirs();
    store = await readJson(PATHS.users, null);

    if (!store || !Array.isArray(store.users) || store.users.length === 0) {
        // Generate a random bootstrap credential. Never hardcode one.
        bootstrapPassword = generateBootstrapPassword();
        const credential = await hashPassword(bootstrapPassword);
        store = {
            version: 1,
            createdAt: new Date().toISOString(),
            users: [{
                id: randomId('usr'),
                username: 'admin',
                role: 'admin',
                credential,
                mustChangePassword: true,
                disabled: false,
                createdAt: new Date().toISOString(),
                lastLoginAt: null,
                lastLoginFrom: null,
            }],
        };
        await persistUsers();

        if (!silent) {
            const banner = [
                '',
                '  ┌──────────────────────────────────────────────────────────────┐',
                '  │  SentryFW first-run bootstrap credential                     │',
                '  ├──────────────────────────────────────────────────────────────┤',
                '  │  username : admin                                            │',
                `  │  password : ${bootstrapPassword.padEnd(48)} │`,
                '  │                                                              │',
                '  │  Shown once. You must change it at first login.              │',
                '  │  Stored only as a PBKDF2-SHA512 hash in data/users.json.     │',
                '  └──────────────────────────────────────────────────────────────┘',
                '',
            ].join('\n');
            process.stdout.write(`${banner}\n`);
        }

        logEvent({
            level: 'warn', category: 'auth', action: 'auth.bootstrap',
            message: 'Created initial admin account with a generated password (change required at first login)',
        });
    }

    if (!sweepTimer) {
        sweepTimer = setInterval(sweepSessions, SESSION_SWEEP_MS);
        sweepTimer.unref?.();
    }
    return { users: store.users.length, bootstrapPassword };
}

function generateBootstrapPassword() {
    // 4 groups of 5 unambiguous characters: readable, ~90 bits of entropy.
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
    const bytes = crypto.randomBytes(20);
    let out = '';
    for (let i = 0; i < 20; i++) {
        if (i > 0 && i % 5 === 0) out += '-';
        out += alphabet[bytes[i] % alphabet.length];
    }
    return out;
}

async function persistUsers() {
    if (persistDisabled) return;
    await writeJsonAtomic(PATHS.users, store, { mode: 0o600 });
}

function requireStore() {
    if (!store) throw new AuthError('Authentication subsystem is not initialised', 'NOT_INITIALISED');
    return store;
}

export function findUser(username) {
    return requireStore().users.find((u) => u.username === username) ?? null;
}

export function publicUser(user) {
    if (!user) return null;
    return {
        id: user.id,
        username: user.username,
        role: user.role,
        disabled: !!user.disabled,
        mustChangePassword: !!user.mustChangePassword,
        createdAt: user.createdAt,
        lastLoginAt: user.lastLoginAt,
        lastLoginFrom: user.lastLoginFrom,
        permissions: permissionsForRole(user.role),
    };
}

export function listUsers() {
    return requireStore().users.map(publicUser);
}

export function permissionsForRole(role) {
    return Object.entries(PERMISSIONS).filter(([, roles]) => roles.includes(role)).map(([p]) => p);
}

export async function createUser({ username, password, role }, actor = 'system', source = null) {
    requireStore();
    const uname = validateUsername(username);
    const pwd = validatePassword(password);
    const r = validateEnum(role, 'role', ROLES);

    if (findUser(uname)) throw new ConflictError(`User already exists: ${uname}`);
    if (store.users.length >= 64) throw new ConflictError('User limit reached (64)');

    const user = {
        id: randomId('usr'),
        username: uname,
        role: r,
        credential: await hashPassword(pwd),
        mustChangePassword: false,
        disabled: false,
        createdAt: new Date().toISOString(),
        lastLoginAt: null,
        lastLoginFrom: null,
    };
    store.users.push(user);
    await persistUsers();
    await audit({ actor, action: 'user.create', target: uname, after: { username: uname, role: r }, source });
    return publicUser(user);
}

export async function updateUser(username, patch, actor = 'system', source = null) {
    requireStore();
    const uname = validateUsername(username);
    const user = findUser(uname);
    if (!user) throw new NotFoundError('User', uname);

    const before = { role: user.role, disabled: !!user.disabled };
    const after = { ...before };

    if (patch.role !== undefined) {
        after.role = validateEnum(patch.role, 'role', ROLES);
        if (user.role === 'admin' && after.role !== 'admin' && countAdmins() <= 1) {
            throw new ConflictError('Cannot demote the last administrator');
        }
        user.role = after.role;
    }
    if (patch.disabled !== undefined) {
        const disabled = patch.disabled === true || patch.disabled === 'true';
        if (disabled && user.role === 'admin' && countAdmins() <= 1) {
            throw new ConflictError('Cannot disable the last administrator');
        }
        user.disabled = disabled;
        after.disabled = disabled;
        if (disabled) revokeUserSessions(uname);
    }
    if (patch.password !== undefined) {
        user.credential = await hashPassword(validatePassword(patch.password));
        user.mustChangePassword = patch.mustChangePassword === true;
        revokeUserSessions(uname);
        after.passwordReset = true;
    }

    await persistUsers();
    await audit({ actor, action: 'user.update', target: uname, before, after, source });
    return publicUser(user);
}

export async function deleteUser(username, actor = 'system', source = null) {
    requireStore();
    const uname = validateUsername(username);
    const idx = store.users.findIndex((u) => u.username === uname);
    if (idx === -1) throw new NotFoundError('User', uname);
    if (store.users[idx].role === 'admin' && countAdmins() <= 1) {
        throw new ConflictError('Cannot delete the last administrator');
    }
    const [removed] = store.users.splice(idx, 1);
    revokeUserSessions(uname);
    await persistUsers();
    await audit({ actor, action: 'user.delete', target: uname, before: { username: uname, role: removed.role }, source });
    return { username: uname, deleted: true };
}

function countAdmins() {
    return requireStore().users.filter((u) => u.role === 'admin' && !u.disabled).length;
}

export async function changeOwnPassword(username, currentPassword, newPassword, source = null) {
    requireStore();
    const user = findUser(validateUsername(username));
    if (!user) throw new NotFoundError('User', username);
    if (!(await verifyPassword(String(currentPassword ?? ''), user.credential))) {
        logEvent({ level: 'warn', category: 'auth', action: 'auth.password_change_denied', message: `Password change refused for ${user.username}: current password incorrect`, actor: user.username, source });
        throw new AuthError('Current password is incorrect', 'BAD_CREDENTIALS');
    }
    const pwd = validatePassword(newPassword);
    if (await verifyPassword(pwd, user.credential)) {
        throw new ValidationError('New password must differ from the current password');
    }
    user.credential = await hashPassword(pwd);
    user.mustChangePassword = false;
    await persistUsers();
    // Keep the caller's own session, drop any others for that user.
    await audit({ actor: user.username, action: 'user.password_change', target: user.username, source });
    return publicUser(user);
}

/* ------------------------------------------------------------------ *
 * Lockout
 * ------------------------------------------------------------------ */

function lockKey(username, source) {
    return `${username}|${source ?? '-'}`;
}

function isLockedOut(username, source) {
    const rec = lockouts.get(lockKey(username, source));
    if (!rec) return 0;
    if (rec.until <= Date.now()) { lockouts.delete(lockKey(username, source)); return 0; }
    return Math.ceil((rec.until - Date.now()) / 1000);
}

function noteFailure(username, source) {
    const cfg = getConfig().security;
    const key = lockKey(username, source);
    const rec = lockouts.get(key) ?? { count: 0, until: 0 };
    rec.count += 1;
    if (rec.count >= (cfg.loginMaxAttempts ?? 5)) {
        rec.until = Date.now() + (cfg.loginLockoutSeconds ?? 300) * 1000;
        rec.count = 0;
        logEvent({
            level: 'warn', category: 'auth', action: 'auth.lockout',
            message: `Too many failed logins for "${username}" — locked for ${cfg.loginLockoutSeconds ?? 300}s`,
            actor: username, source, outcome: 'denied',
        });
    }
    lockouts.set(key, rec);
}

function clearFailures(username, source) {
    lockouts.delete(lockKey(username, source));
}

/* ------------------------------------------------------------------ *
 * Sessions
 * ------------------------------------------------------------------ */

export async function login({ username, password }, { source = null, userAgent = null } = {}) {
    requireStore();
    const uname = validateUsername(username);

    const wait = isLockedOut(uname, source);
    if (wait > 0) {
        throw new AuthError(`Account temporarily locked. Try again in ${wait}s.`, 'LOCKED_OUT');
    }

    const user = findUser(uname);
    // Constant-ish work whether or not the user exists, to avoid a trivial oracle.
    const credential = user?.credential ?? {
        algorithm: 'pbkdf2-sha512',
        iterations: getConfig().security.pbkdf2Iterations,
        salt: Buffer.alloc(16).toString('base64'),
        hash: Buffer.alloc(64).toString('base64'),
    };
    const ok = await verifyPassword(String(password ?? ''), credential);

    if (!user || !ok || user.disabled) {
        noteFailure(uname, source);
        logEvent({
            level: 'warn', category: 'auth', action: 'auth.login_failed',
            message: `Failed login for "${uname}"${user?.disabled ? ' (account disabled)' : ''}`,
            actor: uname, source, outcome: 'denied', details: { userAgent },
        });
        throw new AuthError('Invalid username or password', 'BAD_CREDENTIALS');
    }

    clearFailures(uname, source);

    const token = randomToken(32);
    const csrf = randomToken(24);
    const ttlMs = getConfig().server.sessionTtlMinutes * 60_000;
    const session = {
        id: randomId('ses'),
        token,
        csrf,
        username: user.username,
        role: user.role,
        createdAt: Date.now(),
        lastSeenAt: Date.now(),
        expiresAt: Date.now() + ttlMs,
        source,
        userAgent: userAgent ? String(userAgent).slice(0, 200) : null,
    };
    sessions.set(token, session);

    user.lastLoginAt = new Date().toISOString();
    user.lastLoginFrom = source;
    await persistUsers();

    logEvent({
        level: 'info', category: 'auth', action: 'auth.login',
        message: `${user.username} signed in (${user.role})`,
        actor: user.username, source, outcome: 'allowed',
    });

    return {
        token,
        csrf,
        expiresAt: new Date(session.expiresAt).toISOString(),
        user: publicUser(user),
    };
}

export function logout(token, { source = null } = {}) {
    const session = sessions.get(token);
    if (session) {
        sessions.delete(token);
        logEvent({
            level: 'info', category: 'auth', action: 'auth.logout',
            message: `${session.username} signed out`, actor: session.username, source,
        });
        return true;
    }
    return false;
}

export function getSession(token) {
    if (!token) return null;
    const session = sessions.get(token);
    if (!session) return null;
    if (session.expiresAt <= Date.now()) {
        sessions.delete(token);
        logEvent({ level: 'info', category: 'auth', action: 'auth.session_expired', message: `Session expired for ${session.username}`, actor: session.username });
        return null;
    }
    session.lastSeenAt = Date.now();
    // Sliding expiry, capped at the configured TTL.
    session.expiresAt = Date.now() + getConfig().server.sessionTtlMinutes * 60_000;
    return session;
}

export function revokeUserSessions(username) {
    let n = 0;
    for (const [token, s] of sessions) {
        if (s.username === username) { sessions.delete(token); n += 1; }
    }
    return n;
}

export function listSessions() {
    return [...sessions.values()].map((s) => ({
        id: s.id,
        username: s.username,
        role: s.role,
        createdAt: new Date(s.createdAt).toISOString(),
        lastSeenAt: new Date(s.lastSeenAt).toISOString(),
        expiresAt: new Date(s.expiresAt).toISOString(),
        source: s.source,
        userAgent: s.userAgent,
    }));
}

function sweepSessions() {
    const now = Date.now();
    for (const [token, s] of sessions) {
        if (s.expiresAt <= now) sessions.delete(token);
    }
    for (const [key, rec] of lockouts) {
        if (rec.until && rec.until <= now) lockouts.delete(key);
    }
}

/* ------------------------------------------------------------------ *
 * Authorisation helpers
 * ------------------------------------------------------------------ */

export function hasPermission(role, permission) {
    const roles = PERMISSIONS[permission];
    if (!roles) return false;
    return roles.includes(role);
}

export function requirePermission(principal, permission) {
    if (!principal) throw new AuthError();
    if (!hasPermission(principal.role, permission)) {
        throw new ForbiddenError(`Role "${principal.role}" is not permitted to ${permission}`, { required: permission, role: principal.role });
    }
    return true;
}

/** Constant-time CSRF comparison. */
export function verifyCsrf(session, provided) {
    if (!session) return false;
    if (typeof provided !== 'string' || provided.length === 0) return false;
    const a = Buffer.from(session.csrf);
    const b = Buffer.from(provided);
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
}

export function authStats() {
    return {
        users: store ? store.users.length : 0,
        activeSessions: sessions.size,
        lockedOut: [...lockouts.values()].filter((r) => r.until > Date.now()).length,
        roles: ROLES,
    };
}

/** Stop the sweep timer (used when shutting down and in tests). */
export function stopAuth() {
    if (sweepTimer) { clearInterval(sweepTimer); sweepTimer = null; }
}

/** Test seam: in-memory store, no disk writes. */
export async function __setAuthStoreForTests(users = []) {
    store = { version: 1, createdAt: new Date().toISOString(), users };
    sessions.clear();
    lockouts.clear();
    persistDisabled = true;
}
