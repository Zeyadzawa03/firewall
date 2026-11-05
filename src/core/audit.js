/**
 * Tamper-evident audit trail for administrative changes.
 *
 * Separate from the event log on purpose: the event log is high-volume and
 * rotates, while the audit trail is the record of *who changed what*. Each
 * entry stores the hash of the previous entry, so a deletion or edit in the
 * middle of the file is detectable with `verifyChain()`.
 *
 * This is integrity evidence, not tamper-proofing: an attacker with write
 * access to logs/ can rebuild the chain. Ship the file to a WORM store or a
 * SIEM (e.g. FortiSIEM, see docs/) if you need stronger guarantees.
 */

import crypto from 'node:crypto';
import fsp from 'node:fs/promises';

import { PATHS, appendLine, ensureRuntimeDirs } from './paths.js';
import { randomId } from './ids.js';
import { logEvent } from './logger.js';

const GENESIS = '0'.repeat(64);

let lastHash = null;
let sequence = 0;
let initialised = false;
const memory = [];

function hashEntry(entry) {
    const material = JSON.stringify({
        seq: entry.seq,
        ts: entry.ts,
        actor: entry.actor,
        action: entry.action,
        target: entry.target,
        outcome: entry.outcome,
        before: entry.before ?? null,
        after: entry.after ?? null,
        reason: entry.reason ?? null,
        prevHash: entry.prevHash,
    });
    return crypto.createHash('sha256').update(material).digest('hex');
}

/** Load the existing chain so appends continue from the right place. */
export async function initAudit() {
    if (initialised) return;
    ensureRuntimeDirs();
    let text = '';
    try {
        text = await fsp.readFile(PATHS.auditLog, 'utf8');
    } catch {
        lastHash = GENESIS;
        sequence = 0;
        initialised = true;
        return;
    }
    const lines = text.split('\n').filter(Boolean);
    for (const line of lines) {
        try {
            const e = JSON.parse(line);
            memory.push(e);
            lastHash = e.hash;
            sequence = e.seq;
        } catch { /* skip malformed line */ }
    }
    if (lastHash === null) lastHash = GENESIS;
    if (memory.length > 5000) memory.splice(0, memory.length - 5000);
    initialised = true;
}

/**
 * Append an audit entry.
 * @param {object} p
 * @param {string} p.actor    username or 'system' / 'cli:<user>'
 * @param {string} p.action   e.g. 'rule.create', 'blocklist.add', 'config.update'
 * @param {string} p.target   the object acted upon
 * @param {string} [p.outcome] 'success' | 'failure' | 'partial'
 * @param {object} [p.before] previous state snapshot
 * @param {object} [p.after]  new state snapshot
 * @param {string} [p.reason] operator-supplied justification
 * @param {string} [p.source] request source (ip / 'cli')
 */
export async function audit({
    actor = 'system',
    action,
    target = '',
    outcome = 'success',
    before = null,
    after = null,
    reason = null,
    source = null,
} = {}) {
    if (!initialised) await initAudit();
    sequence += 1;

    const entry = {
        id: randomId('au'),
        seq: sequence,
        ts: new Date().toISOString(),
        actor: String(actor).slice(0, 64),
        action: String(action || 'unknown').slice(0, 64),
        target: String(target || '').slice(0, 200),
        outcome,
        source: source ? String(source).slice(0, 128) : null,
        reason: reason ? String(reason).slice(0, 400) : null,
        before: redact(before),
        after: redact(after),
        prevHash: lastHash ?? GENESIS,
    };
    entry.hash = hashEntry(entry);
    lastHash = entry.hash;

    memory.push(entry);
    if (memory.length > 5000) memory.shift();

    try {
        await appendLine(PATHS.auditLog, JSON.stringify(entry));
    } catch (err) {
        logEvent({
            level: 'error', category: 'error', action: 'audit.write_failed',
            message: `Failed to persist audit entry: ${err.message}`,
        });
    }

    logEvent({
        level: outcome === 'failure' ? 'warn' : 'info',
        category: 'config',
        action: entry.action,
        message: `${entry.actor} ${entry.action} ${entry.target}`.trim(),
        actor: entry.actor,
        source: entry.source,
        target: entry.target,
        outcome,
        details: entry.reason ? { reason: entry.reason } : null,
    });

    return entry;
}

function redact(obj) {
    if (obj === null || obj === undefined) return null;
    const SECRET = /(pass|secret|token|salt|hash|cookie|credential)/i;
    const walk = (node, depth = 0) => {
        if (depth > 4) return '[truncated]';
        if (Array.isArray(node)) return node.slice(0, 50).map((v) => walk(v, depth + 1));
        if (node && typeof node === 'object') {
            const out = {};
            for (const [k, v] of Object.entries(node)) out[k] = SECRET.test(k) ? '[redacted]' : walk(v, depth + 1);
            return out;
        }
        return node;
    };
    return walk(obj);
}

export function queryAudit({ text = '', actor = null, action = null, from = null, to = null, limit = 100, offset = 0 } = {}) {
    const needle = String(text || '').trim().toLowerCase();
    const fromTs = from ? Date.parse(from) : null;
    const toTs = to ? Date.parse(to) : null;

    const rows = memory.filter((e) => {
        if (actor && e.actor !== actor) return false;
        if (action && !e.action.startsWith(action)) return false;
        if (fromTs !== null && Date.parse(e.ts) < fromTs) return false;
        if (toTs !== null && Date.parse(e.ts) > toTs) return false;
        if (needle) {
            const hay = `${e.actor} ${e.action} ${e.target} ${e.reason ?? ''}`.toLowerCase();
            if (!hay.includes(needle)) return false;
        }
        return true;
    }).slice().reverse();

    return {
        total: rows.length,
        offset,
        limit,
        entries: rows.slice(Math.max(0, offset), Math.max(0, offset) + Math.min(1000, Math.max(1, limit))),
    };
}

/**
 * Recompute the chain and report the first inconsistency.
 * @returns {{valid:boolean, checked:number, brokenAt:number|null, reason:string|null}}
 */
export function verifyChain() {
    let prev = GENESIS;
    for (const [i, entry] of memory.entries()) {
        if (entry.prevHash !== prev) {
            return { valid: false, checked: i, brokenAt: entry.seq, reason: 'previous-hash mismatch (an earlier entry was altered or removed)' };
        }
        const expected = hashEntry(entry);
        if (expected !== entry.hash) {
            return { valid: false, checked: i, brokenAt: entry.seq, reason: 'entry hash mismatch (this entry was altered)' };
        }
        prev = entry.hash;
    }
    return { valid: true, checked: memory.length, brokenAt: null, reason: null };
}

export function auditStats() {
    const byAction = {};
    for (const e of memory) byAction[e.action] = (byAction[e.action] ?? 0) + 1;
    return {
        entries: memory.length,
        lastSeq: sequence,
        lastHash,
        byAction,
        chain: verifyChain(),
        file: PATHS.auditLog,
    };
}

export function exportAudit(format = 'json', filter = {}) {
    const { entries } = queryAudit({ ...filter, limit: 10_000 });
    if (format === 'ndjson') return entries.map((e) => JSON.stringify(e)).join('\n');
    if (format === 'csv') {
        const cols = ['seq', 'ts', 'actor', 'action', 'target', 'outcome', 'source', 'reason', 'hash'];
        const esc = (v) => {
            const s = v === null || v === undefined ? '' : String(v);
            return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
        };
        return [cols.join(','), ...entries.map((e) => cols.map((c) => esc(e[c])).join(','))].join('\r\n');
    }
    return JSON.stringify({ exportedAt: new Date().toISOString(), count: entries.length, chain: verifyChain(), entries }, null, 2);
}

/** Test seam. */
export function __resetAudit() {
    memory.length = 0;
    lastHash = GENESIS;
    sequence = 0;
    initialised = true;
}
