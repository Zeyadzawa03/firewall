/**
 * Structured event log + in-memory query index.
 *
 * Two sinks:
 *   - logs/events.log  — every operational/security event, JSON Lines, rotated.
 *   - in-memory ring   — the last N events, so the GUI can filter/sort/paginate
 *                        without re-reading the file on every keystroke.
 *
 * Event shape (stable, both on disk and over the API):
 *   { id, ts, level, category, action, message, actor, source, target, details, outcome }
 */

import { PATHS, appendLine, appendLineSync, ensureRuntimeDirs, fileSize } from './paths.js';
import { getConfig } from './config.js';
import { randomId } from './ids.js';
import fsp from 'node:fs/promises';
import fs from 'node:fs';
import path from 'node:path';

export const LEVELS = Object.freeze(['debug', 'info', 'warn', 'error', 'critical']);

export const CATEGORIES = Object.freeze([
    'system',       // startup/shutdown/provider selection
    'auth',         // login, logout, lockout
    'rule',         // rule create/update/delete/enable/disable/reorder
    'firewall',     // apply/sync/OS interaction
    'traffic',      // connection observations
    'detection',    // suspicious activity
    'blocklist',    // IP block/unblock
    'config',       // settings changes
    'backup',       // export/import/restore
    'error',        // unexpected failures
]);

const LEVEL_RANK = Object.freeze({ debug: 10, info: 20, warn: 30, error: 40, critical: 50 });

const RING_CAPACITY = 5000;

/** @type {Array<object>} newest-last ring buffer */
const ring = [];
let counters = null;
let listeners = new Set();

function resetCounters() {
    counters = {
        total: 0,
        byLevel: Object.fromEntries(LEVELS.map((l) => [l, 0])),
        byCategory: Object.fromEntries(CATEGORIES.map((c) => [c, 0])),
        allowed: 0,
        denied: 0,
        suspicious: 0,
        errors: 0,
        startedAt: new Date().toISOString(),
    };
}
resetCounters();

function levelEnabled(level) {
    let min = 'info';
    try { min = getConfig().logging.level; } catch { /* config not loaded yet */ }
    return (LEVEL_RANK[level] ?? 20) >= (LEVEL_RANK[min] ?? 20);
}

function consoleEnabled() {
    try { return getConfig().logging.console !== false; } catch { return true; }
}

function push(event) {
    ring.push(event);
    if (ring.length > RING_CAPACITY) ring.splice(0, ring.length - RING_CAPACITY);

    counters.total += 1;
    if (counters.byLevel[event.level] !== undefined) counters.byLevel[event.level] += 1;
    if (counters.byCategory[event.category] !== undefined) counters.byCategory[event.category] += 1;
    if (event.outcome === 'allowed') counters.allowed += 1;
    if (event.outcome === 'denied') counters.denied += 1;
    if (event.category === 'detection') counters.suspicious += 1;
    if (event.level === 'error' || event.level === 'critical') counters.errors += 1;

    for (const fn of listeners) {
        try { fn(event); } catch { /* a listener must never break logging */ }
    }
}

/**
 * Record an event. Fire-and-forget by design: logging must never block a
 * firewall operation, but write failures are surfaced on the console.
 */
export function logEvent({
    level = 'info',
    category = 'system',
    action = '',
    message = '',
    actor = null,
    source = null,
    target = null,
    details = null,
    outcome = null,
} = {}) {
    const event = {
        id: randomId('ev'),
        ts: new Date().toISOString(),
        level: LEVELS.includes(level) ? level : 'info',
        category: CATEGORIES.includes(category) ? category : 'system',
        action: String(action || '').slice(0, 64),
        message: String(message || '').slice(0, 1000),
        actor: actor ? String(actor).slice(0, 64) : null,
        source: source ? String(source).slice(0, 128) : null,
        target: target ? String(target).slice(0, 200) : null,
        outcome: outcome ? String(outcome).slice(0, 32) : null,
        details: sanitizeDetails(details),
    };

    push(event);

    if (levelEnabled(event.level)) {
        if (consoleEnabled()) writeConsole(event);
        appendLine(PATHS.eventLog, JSON.stringify(event)).catch((err) => {
            process.stderr.write(`[logger] failed to append event log: ${err.message}\n`);
        });
        rotateIfNeeded().catch(() => { /* rotation failure must not break logging */ });
    }

    return event;
}

/** Redact anything that looks like a credential before it reaches disk. */
function sanitizeDetails(details) {
    if (details === null || details === undefined) return null;
    if (typeof details !== 'object') return { value: String(details).slice(0, 500) };
    const SECRET = /(pass|secret|token|key|hash|salt|cookie|authorization|credential)/i;
    const walk = (node, depth = 0) => {
        if (depth > 4) return '[truncated]';
        if (Array.isArray(node)) return node.slice(0, 50).map((v) => walk(v, depth + 1));
        if (node && typeof node === 'object') {
            const out = {};
            for (const [k, v] of Object.entries(node).slice(0, 50)) {
                out[k] = SECRET.test(k) ? '[redacted]' : walk(v, depth + 1);
            }
            return out;
        }
        if (typeof node === 'string') return node.length > 1000 ? `${node.slice(0, 1000)}…` : node;
        return node;
    };
    return walk(details);
}

const CONSOLE_TAG = {
    debug: 'DBG',
    info: 'INF',
    warn: 'WRN',
    error: 'ERR',
    critical: 'CRT',
};

function writeConsole(event) {
    const line = `${event.ts} ${CONSOLE_TAG[event.level]} [${event.category}] ${event.action ? `${event.action}: ` : ''}${event.message}`;
    const stream = event.level === 'error' || event.level === 'critical' ? process.stderr : process.stdout;
    stream.write(`${line}\n`);
}

/* ------------------------------------------------------------------ *
 * Convenience wrappers
 * ------------------------------------------------------------------ */

export const log = {
    debug: (msg, extra = {}) => logEvent({ ...extra, level: 'debug', message: msg }),
    info: (msg, extra = {}) => logEvent({ ...extra, level: 'info', message: msg }),
    warn: (msg, extra = {}) => logEvent({ ...extra, level: 'warn', message: msg }),
    error: (msg, extra = {}) => logEvent({ ...extra, level: 'error', category: extra.category ?? 'error', message: msg }),
    critical: (msg, extra = {}) => logEvent({ ...extra, level: 'critical', category: extra.category ?? 'error', message: msg }),
};

/* ------------------------------------------------------------------ *
 * Rotation
 * ------------------------------------------------------------------ */

let rotating = false;

async function rotateIfNeeded() {
    if (rotating) return;
    const cfg = getConfig().logging;
    const size = await fileSize(PATHS.eventLog);
    if (size < (cfg.maxFileBytes ?? 5_242_880)) return;

    rotating = true;
    try {
        const maxFiles = Math.max(1, cfg.maxFiles ?? 5);
        for (let i = maxFiles - 1; i >= 1; i--) {
            const from = `${PATHS.eventLog}.${i}`;
            const to = `${PATHS.eventLog}.${i + 1}`;
            if (fs.existsSync(from)) {
                if (i + 1 > maxFiles) await fsp.unlink(from).catch(() => {});
                else await fsp.rename(from, to).catch(() => {});
            }
        }
        await fsp.rename(PATHS.eventLog, `${PATHS.eventLog}.1`).catch(() => {});
    } finally {
        rotating = false;
    }
}

/* ------------------------------------------------------------------ *
 * Query API (used by the GUI logs page and the CLI)
 * ------------------------------------------------------------------ */

/**
 * Filter / sort / paginate events.
 * @param {object} q
 * @param {string} [q.text]      free-text across message/action/target/source/actor
 * @param {string[]} [q.levels]
 * @param {string[]} [q.categories]
 * @param {string} [q.outcome]
 * @param {string} [q.from]      ISO timestamp (inclusive)
 * @param {string} [q.to]        ISO timestamp (inclusive)
 * @param {string} [q.sort]      'ts' | 'level' | 'category' | 'action'
 * @param {string} [q.order]     'asc' | 'desc'
 * @param {number} [q.limit]
 * @param {number} [q.offset]
 */
export function queryEvents(q = {}) {
    const {
        text = '', levels = null, categories = null, outcome = null,
        from = null, to = null, sort = 'ts', order = 'desc',
        limit = 100, offset = 0,
    } = q;

    const needle = String(text || '').trim().toLowerCase();
    const fromTs = from ? Date.parse(from) : null;
    const toTs = to ? Date.parse(to) : null;
    const levelSet = levels && levels.length ? new Set(levels) : null;
    const catSet = categories && categories.length ? new Set(categories) : null;

    let rows = ring.filter((e) => {
        if (levelSet && !levelSet.has(e.level)) return false;
        if (catSet && !catSet.has(e.category)) return false;
        if (outcome && e.outcome !== outcome) return false;
        if (fromTs !== null && Date.parse(e.ts) < fromTs) return false;
        if (toTs !== null && Date.parse(e.ts) > toTs) return false;
        if (needle) {
            const hay = `${e.message} ${e.action} ${e.target ?? ''} ${e.source ?? ''} ${e.actor ?? ''}`.toLowerCase();
            if (!hay.includes(needle)) return false;
        }
        return true;
    });

    const dir = order === 'asc' ? 1 : -1;
    const key = ['ts', 'level', 'category', 'action', 'outcome'].includes(sort) ? sort : 'ts';
    rows = rows.slice().sort((a, b) => {
        if (key === 'level') return (LEVEL_RANK[a.level] - LEVEL_RANK[b.level]) * dir;
        const av = String(a[key] ?? '');
        const bv = String(b[key] ?? '');
        return av < bv ? -dir : av > bv ? dir : 0;
    });

    const total = rows.length;
    const page = rows.slice(Math.max(0, offset), Math.max(0, offset) + Math.min(1000, Math.max(1, limit)));
    return { total, offset, limit, events: page };
}

export function recentEvents(n = 20, filter = {}) {
    return queryEvents({ ...filter, limit: n, offset: 0, sort: 'ts', order: 'desc' }).events;
}

export function logStats() {
    return {
        ...counters,
        buffered: ring.length,
        capacity: RING_CAPACITY,
        file: PATHS.eventLog,
        fileBytes: (() => { try { return fs.statSync(PATHS.eventLog).size; } catch { return 0; } })(),
    };
}

/** Export the filtered set as JSON, CSV or NDJSON text. */
export function exportEvents(q = {}, format = 'json') {
    const { events } = queryEvents({ ...q, limit: 10_000 });
    if (format === 'ndjson') return events.map((e) => JSON.stringify(e)).join('\n');
    if (format === 'csv') {
        const cols = ['ts', 'level', 'category', 'action', 'outcome', 'actor', 'source', 'target', 'message'];
        const esc = (v) => {
            const s = v === null || v === undefined ? '' : String(v);
            return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
        };
        return [cols.join(','), ...events.map((e) => cols.map((c) => esc(e[c])).join(','))].join('\r\n');
    }
    return JSON.stringify({ exportedAt: new Date().toISOString(), count: events.length, events }, null, 2);
}

/** Re-hydrate the in-memory ring from disk (used at startup). */
export async function loadRecentFromDisk(max = RING_CAPACITY) {
    ensureRuntimeDirs();
    let text;
    try {
        text = await fsp.readFile(PATHS.eventLog, 'utf8');
    } catch {
        return 0;
    }
    const lines = text.split('\n').filter(Boolean).slice(-max);
    let loaded = 0;
    for (const line of lines) {
        try {
            const e = JSON.parse(line);
            if (e && e.ts && e.level) { push(e); loaded += 1; }
        } catch { /* skip malformed line */ }
    }
    return loaded;
}

/** Subscribe to live events (server-sent events endpoint uses this). */
export function onEvent(fn) {
    listeners.add(fn);
    return () => listeners.delete(fn);
}

/** Test seam: clear in-memory state. */
export function __resetLog() {
    ring.length = 0;
    resetCounters();
    listeners = new Set();
}

/** Synchronous emergency logging used by crash handlers. */
export function logSync(event) {
    const e = { id: randomId('ev'), ts: new Date().toISOString(), level: 'critical', category: 'error', ...event };
    push(e);
    try { appendLineSync(PATHS.eventLog, JSON.stringify(e)); } catch { /* nothing left to do */ }
    process.stderr.write(`${e.ts} CRT [${e.category}] ${e.message}\n`);
    return e;
}

export const EVENT_LOG_PATH = path.normalize(PATHS.eventLog);
