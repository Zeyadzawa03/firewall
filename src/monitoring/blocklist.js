/**
 * IP blocklist.
 *
 * A blocklist entry is a first-class object with an owner, a reason, an optional
 * TTL and an audit trail — not just a string in an array. Each entry is backed
 * by a real firewall rule so a block actually stops traffic instead of only
 * appearing in the console.
 *
 * Two sources are supported:
 *   manual    — an operator or the CLI blocked the address
 *   automatic — a detection rule blocked it (only when detection.autoBlockOnScan)
 *
 * Reputation/threat-feed imports reuse the same store with source='feed', which
 * is why entries carry a `feed` label and a `confidence` field.
 */

import { PATHS, readJson, writeJsonAtomic, ensureRuntimeDirs } from '../core/paths.js';
import { getConfig } from '../core/config.js';
import { randomId } from '../core/ids.js';
import { logEvent } from '../core/logger.js';
import { audit } from '../core/audit.js';
import { ConflictError, NotFoundError, ValidationError } from '../core/errors.js';
import {
    validateIP, validateCIDR, validateString, validateInteger, ipMatchesSpec, isPrivateIP,
} from '../core/validate.js';
import * as manager from '../firewall/manager.js';

/** @type {{version:number, entries:Array<object>}|null} */
let state = null;
let persistDisabled = false;

export async function initBlocklist() {
    ensureRuntimeDirs();
    const loaded = await readJson(PATHS.blocklist, null);
    state = loaded && Array.isArray(loaded.entries)
        ? { version: loaded.version ?? 1, entries: loaded.entries }
        : { version: 1, entries: [] };
    await expireStale();
    return state.entries.length;
}

function requireState() {
    if (!state) throw new Error('Blocklist is not initialised — call initBlocklist() first');
    return state;
}

async function persist() {
    if (persistDisabled) return;
    await writeJsonAtomic(PATHS.blocklist, state);
}

/** Normalise "1.2.3.4" or "10.0.0.0/8" into a canonical target string. */
function normaliseTarget(value) {
    const raw = String(value ?? '').trim();
    if (raw.includes('/')) return validateCIDR(raw, 'target');
    return validateIP(raw, 'target');
}

export function listEntries({ text = '', source = null, active = null, limit = 500, offset = 0 } = {}) {
    const needle = String(text || '').trim().toLowerCase();
    const now = Date.now();
    let rows = requireState().entries.filter((e) => {
        const isActive = !e.expiresAt || Date.parse(e.expiresAt) > now;
        if (active !== null && active !== undefined && isActive !== active) return false;
        if (source && e.source !== source) return false;
        if (needle) {
            const hay = `${e.target} ${e.reason ?? ''} ${e.addedBy} ${e.source} ${e.feed ?? ''}`.toLowerCase();
            if (!hay.includes(needle)) return false;
        }
        return true;
    });
    rows = rows.slice().sort((a, b) => Date.parse(b.addedAt) - Date.parse(a.addedAt));
    return {
        total: rows.length,
        offset,
        limit,
        entries: rows.slice(Math.max(0, offset), Math.max(0, offset) + Math.min(2000, Math.max(1, limit))).map(decorate),
    };
}

function decorate(entry) {
    const expired = !!entry.expiresAt && Date.parse(entry.expiresAt) <= Date.now();
    return {
        ...entry,
        active: !expired,
        expiresIn: entry.expiresAt ? Math.max(0, Math.round((Date.parse(entry.expiresAt) - Date.now()) / 1000)) : null,
    };
}

export function findEntry(target) {
    const normalised = String(target ?? '').trim();
    return requireState().entries.find((e) => e.target === normalised) ?? null;
}

/** Is an address covered by any active blocklist entry? */
export function isBlocked(ip) {
    if (!getConfig().blocklist?.enabled) return null;
    const now = Date.now();
    for (const entry of requireState().entries) {
        if (entry.expiresAt && Date.parse(entry.expiresAt) <= now) continue;
        if (ipMatchesSpec(ip, entry.target)) return decorate(entry);
    }
    return null;
}

/**
 * Block an address or network.
 * Creates a matching deny rule (priority 1, so it precedes normal policy) and
 * applies it through the firewall manager, so the block is enforced rather than
 * cosmetic.
 */
export async function block({ target, reason = '', ttlHours = null, source = 'manual', feed = null, confidence = null, direction = 'both' }, ctx = {}) {
    requireState();
    const actor = ctx.actor ?? 'system';
    const normalised = normaliseTarget(target);
    const cleanReason = validateString(reason, 'reason', { max: 300, optional: true, fallback: '' });
    const ttl = ttlHours === null || ttlHours === undefined || ttlHours === ''
        ? (getConfig().blocklist?.defaultTtlHours ?? 0)
        : validateInteger(ttlHours, 'ttlHours', { min: 0, max: 8760 });

    if (findEntry(normalised)) {
        throw new ConflictError(`${normalised} is already on the blocklist`);
    }
    if (state.entries.length >= 5000) {
        throw new ConflictError('Blocklist limit reached (5000 entries)');
    }

    // Guard against locking the operator out of their own console.
    const selfCheck = warnIfSelfBlocking(normalised, ctx);

    const entry = {
        id: randomId('blk'),
        target: normalised,
        reason: cleanReason,
        source,
        feed: feed ? validateString(feed, 'feed', { max: 64 }) : null,
        confidence: confidence === null || confidence === undefined ? null : validateInteger(confidence, 'confidence', { min: 0, max: 100 }),
        addedBy: actor,
        addedAt: new Date().toISOString(),
        expiresAt: ttl > 0 ? new Date(Date.now() + ttl * 3600_000).toISOString() : null,
        ruleIds: [],
        warnings: selfCheck ? [selfCheck] : [],
    };

    // Back the entry with real deny rules.
    const directions = direction === 'both' ? ['inbound', 'outbound'] : [direction];
    const ruleResults = [];
    for (const dir of directions) {
        const name = `Blocklist ${normalised} ${dir}`.replace(/[^A-Za-z0-9 _.\-]/g, '-').slice(0, 90);
        try {
            const { rule, os } = await manager.createRuleAndApply({
                name,
                description: `Automatic blocklist entry${cleanReason ? `: ${cleanReason}` : ''}`.slice(0, 400),
                direction: dir,
                action: 'deny',
                protocol: 'any',
                srcAddress: dir === 'inbound' ? normalised : 'any',
                dstAddress: dir === 'inbound' ? 'any' : normalised,
                priority: 1,
                enabled: true,
                tags: ['blocklist', source],
            }, { ...ctx, actor, reason: `blocklist:${normalised}` });
            entry.ruleIds.push(rule.id);
            ruleResults.push({ direction: dir, ruleId: rule.id, os });
        } catch (err) {
            ruleResults.push({ direction: dir, error: err.message, code: err.code ?? null });
        }
    }

    state.entries.push(entry);
    await persist();

    await audit({
        actor, action: 'blocklist.add', target: normalised,
        after: { target: normalised, reason: cleanReason, source, expiresAt: entry.expiresAt, rules: entry.ruleIds },
        reason: cleanReason || null, source: ctx.source ?? null,
        outcome: ruleResults.every((r) => !r.error) ? 'success' : 'partial',
    });

    logEvent({
        level: 'warn', category: 'blocklist', action: 'blocklist.add',
        message: `Blocked ${normalised}${cleanReason ? ` — ${cleanReason}` : ''}${entry.expiresAt ? ` (expires ${entry.expiresAt})` : ''}`,
        actor, source: ctx.source ?? null, target: normalised, outcome: 'denied',
        details: { source, rules: ruleResults, warnings: entry.warnings },
    });

    return { entry: decorate(entry), rules: ruleResults };
}

export async function unblock(target, ctx = {}) {
    requireState();
    const actor = ctx.actor ?? 'system';
    const normalised = String(target ?? '').trim();
    const idx = state.entries.findIndex((e) => e.target === normalised || e.id === normalised);
    if (idx === -1) throw new NotFoundError('Blocklist entry', normalised);

    const [entry] = state.entries.splice(idx, 1);

    const ruleResults = [];
    for (const ruleId of entry.ruleIds ?? []) {
        try {
            await manager.deleteRule(ruleId, { ...ctx, actor, reason: `unblock:${entry.target}` });
            ruleResults.push({ ruleId, removed: true });
        } catch (err) {
            // A rule the operator already deleted by hand is not an error here.
            ruleResults.push({ ruleId, removed: false, error: err.message });
        }
    }

    await persist();

    await audit({
        actor, action: 'blocklist.remove', target: entry.target,
        before: { target: entry.target, reason: entry.reason, source: entry.source, rules: entry.ruleIds },
        source: ctx.source ?? null,
    });

    logEvent({
        level: 'info', category: 'blocklist', action: 'blocklist.remove',
        message: `Unblocked ${entry.target}`,
        actor, source: ctx.source ?? null, target: entry.target,
        details: { rules: ruleResults },
    });

    return { entry: decorate(entry), rules: ruleResults };
}

/** Remove expired entries and their backing rules. */
export async function expireStale(ctx = {}) {
    requireState();
    const now = Date.now();
    const expired = state.entries.filter((e) => e.expiresAt && Date.parse(e.expiresAt) <= now);
    const removed = [];
    for (const entry of expired) {
        try {
            await unblock(entry.target, { ...ctx, actor: 'system' });
            removed.push(entry.target);
        } catch { /* already gone */ }
    }
    if (removed.length > 0) {
        logEvent({
            level: 'info', category: 'blocklist', action: 'blocklist.expire',
            message: `Expired ${removed.length} blocklist entry/ies`,
            details: { targets: removed.slice(0, 50) },
        });
    }
    return removed;
}

/**
 * Bulk import (threat feed / reputation list).
 * Accepts an array of strings or {target, reason, confidence} objects. Invalid
 * lines are reported rather than silently dropped.
 */
export async function importFeed({ entries, feed = 'import', reason = 'Imported from feed', ttlHours = null, createRules = false }, ctx = {}) {
    requireState();
    const actor = ctx.actor ?? 'system';
    if (!Array.isArray(entries)) throw new ValidationError('entries must be an array');
    if (entries.length > 5000) throw new ValidationError('Cannot import more than 5000 entries at once');

    const added = [];
    const skipped = [];
    const invalid = [];

    for (const raw of entries) {
        const target = typeof raw === 'string' ? raw : raw?.target;
        try {
            const normalised = normaliseTarget(target);
            if (findEntry(normalised)) {
                skipped.push({ target: normalised, reason: 'already present' });
                continue;
            }
            if (isPrivateIP(normalised.split('/')[0])) {
                skipped.push({ target: normalised, reason: 'private/reserved address — refused to import from a feed' });
                continue;
            }
            const entry = {
                id: randomId('blk'),
                target: normalised,
                reason: typeof raw === 'object' && raw?.reason ? String(raw.reason).slice(0, 300) : reason,
                source: 'feed',
                feed: String(feed).slice(0, 64),
                confidence: typeof raw === 'object' && Number.isFinite(raw?.confidence) ? Math.max(0, Math.min(100, raw.confidence)) : null,
                addedBy: actor,
                addedAt: new Date().toISOString(),
                expiresAt: ttlHours ? new Date(Date.now() + Number(ttlHours) * 3600_000).toISOString() : null,
                ruleIds: [],
                warnings: [],
            };
            state.entries.push(entry);
            added.push(normalised);
        } catch (err) {
            invalid.push({ target: String(target).slice(0, 60), error: err.message });
        }
    }

    await persist();

    // Feeds are large: a rule per entry is usually wrong. One aggregate deny rule
    // holding up to 32 addresses is created only when explicitly requested.
    let aggregateRule = null;
    if (createRules && added.length > 0) {
        const chunk = added.slice(0, 32);
        try {
            const { rule } = await manager.createRuleAndApply({
                name: `Blocklist feed ${feed}`.slice(0, 90),
                description: `Aggregate deny for feed "${feed}" (${chunk.length} of ${added.length} entries)`,
                direction: 'inbound',
                action: 'deny',
                protocol: 'any',
                srcAddress: chunk.join(','),
                priority: 1,
                tags: ['blocklist', 'feed'],
            }, { ...ctx, actor, reason: `feed:${feed}` });
            aggregateRule = { ruleId: rule.id, covered: chunk.length, total: added.length };
        } catch (err) {
            aggregateRule = { error: err.message };
        }
    }

    await audit({
        actor, action: 'blocklist.import', target: `feed:${feed}`,
        after: { added: added.length, skipped: skipped.length, invalid: invalid.length },
        source: ctx.source ?? null,
        outcome: invalid.length === 0 ? 'success' : 'partial',
    });

    logEvent({
        level: 'info', category: 'blocklist', action: 'blocklist.import',
        message: `Imported ${added.length} address(es) from feed "${feed}" (${skipped.length} skipped, ${invalid.length} invalid)`,
        actor, source: ctx.source ?? null,
        details: { invalid: invalid.slice(0, 20), aggregateRule },
    });

    return { added: added.length, skipped, invalid, aggregateRule };
}

function warnIfSelfBlocking(target, ctx) {
    const requester = ctx.source ?? null;
    if (requester && ipMatchesSpec(requester, target)) {
        return `The address you are connecting from (${requester}) is covered by this block. You may lose access to this console.`;
    }
    if (target === '0.0.0.0/0' || target === '::/0') {
        return 'This entry covers the entire address space and will deny all traffic in the chosen direction.';
    }
    if (isPrivateIP(target.split('/')[0])) {
        return 'This is a private/reserved address. Blocking internal ranges can break local services, DNS or management access.';
    }
    return null;
}

export function stats() {
    const entries = requireState().entries;
    const now = Date.now();
    const bySource = {};
    let active = 0;
    let temporary = 0;
    for (const e of entries) {
        bySource[e.source] = (bySource[e.source] ?? 0) + 1;
        if (!e.expiresAt || Date.parse(e.expiresAt) > now) active += 1;
        if (e.expiresAt) temporary += 1;
    }
    return {
        enabled: getConfig().blocklist?.enabled !== false,
        total: entries.length,
        active,
        expired: entries.length - active,
        temporary,
        permanent: entries.length - temporary,
        bySource,
    };
}

export function exportBlocklist() {
    return {
        kind: 'sentryfw-blocklist',
        version: requireState().version,
        exportedAt: new Date().toISOString(),
        count: state.entries.length,
        entries: state.entries.map(decorate),
    };
}

/** Test seam. */
export function __setBlocklistForTests(entries = []) {
    state = { version: 1, entries };
    persistDisabled = true;
}
