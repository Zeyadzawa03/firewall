/**
 * Rule store — the authoritative, persisted rule set.
 *
 * Responsibilities:
 *   - hold the canonical rules and persist them atomically
 *   - enforce uniqueness of rule names
 *   - keep an ordered view (priority, then creation time)
 *   - serialise mutations so two concurrent API calls cannot interleave a
 *     read-modify-write and lose a rule
 *
 * It deliberately knows nothing about the OS. Applying rules is the firewall
 * manager's job (src/firewall/manager.js).
 */

import { PATHS, readJson, writeJsonAtomic, ensureRuntimeDirs } from '../core/paths.js';
import { ConflictError, NotFoundError, ValidationError } from '../core/errors.js';
import { createRule, applyPatch, sortRules, RULE_VERSION, osRuleName } from './rule-model.js';
import { validateRuleInput } from '../core/validate.js';
import { getConfig } from '../core/config.js';

/** @type {{version:number, updatedAt:string, rules:Array<object>}|null} */
let state = null;
/** Serialises writes. */
let chain = Promise.resolve();
let persistDisabled = false;

function withLock(fn) {
    const next = chain.then(fn, fn);
    // Keep the chain alive even if fn rejects.
    chain = next.then(() => undefined, () => undefined);
    return next;
}

export async function initRules() {
    ensureRuntimeDirs();
    const loaded = await readJson(PATHS.rules, null);
    if (loaded && Array.isArray(loaded.rules)) {
        state = {
            version: loaded.version ?? RULE_VERSION,
            updatedAt: loaded.updatedAt ?? new Date().toISOString(),
            rules: loaded.rules.map(migrate),
        };
    } else {
        state = { version: RULE_VERSION, updatedAt: new Date().toISOString(), rules: [] };
    }
    return state.rules.length;
}

/** Bring older persisted rules up to the current shape. */
function migrate(rule) {
    const r = { ...rule };
    r.profiles ??= ['Any'];
    r.tags ??= [];
    r.program ??= '';
    r.revision ??= 1;
    r.hitCount ??= 0;
    r.lastHitAt ??= null;
    r.osApplied ??= false;
    r.osLastError ??= null;
    r.srcPort ??= 'any';
    r.dstPort ??= 'any';
    r.srcAddress ??= 'any';
    r.dstAddress ??= 'any';
    r.iface ??= 'any';
    r.priority ??= 100;
    if (!r.osRuleName) r.osRuleName = osRuleName(r, getConfig().firewall.rulePrefix);
    return r;
}

function requireState() {
    if (!state) throw new Error('Rule store is not initialised — call initRules() first');
    return state;
}

async function persist() {
    if (persistDisabled) return;
    requireState().updatedAt = new Date().toISOString();
    await writeJsonAtomic(PATHS.rules, state);
}

/* ------------------------------------------------------------------ *
 * Queries
 * ------------------------------------------------------------------ */

export function allRules() {
    return sortRules(requireState().rules).map((r) => ({ ...r }));
}

export function getRule(id) {
    const rule = requireState().rules.find((r) => r.id === id);
    return rule ? { ...rule } : null;
}

export function getRuleByName(name) {
    const lower = String(name ?? '').toLowerCase();
    const rule = requireState().rules.find((r) => r.name.toLowerCase() === lower);
    return rule ? { ...rule } : null;
}

/**
 * Filter / sort / paginate for the GUI table and CLI.
 * @param {object} q
 */
export function queryRules(q = {}) {
    const {
        text = '', direction = null, action = null, protocol = null,
        enabled = null, iface = null, tag = null, applied = null,
        sort = 'priority', order = 'asc', limit = 200, offset = 0,
    } = q;

    const needle = String(text || '').trim().toLowerCase();
    let rows = requireState().rules.filter((r) => {
        if (direction && r.direction !== direction) return false;
        if (action && r.action !== action) return false;
        if (protocol && r.protocol !== protocol) return false;
        if (enabled !== null && enabled !== undefined && r.enabled !== enabled) return false;
        if (applied !== null && applied !== undefined && !!r.osApplied !== applied) return false;
        if (iface && r.iface !== iface) return false;
        if (tag && !(r.tags ?? []).includes(tag)) return false;
        if (needle) {
            const hay = [
                r.name, r.description, r.srcAddress, r.dstAddress,
                r.srcPort, r.dstPort, r.protocol, r.direction, r.action,
                r.iface, (r.tags ?? []).join(' '), r.id, r.program,
            ].join(' ').toLowerCase();
            if (!hay.includes(needle)) return false;
        }
        return true;
    });

    const dir = order === 'desc' ? -1 : 1;
    const allowedSort = ['priority', 'name', 'direction', 'action', 'protocol', 'createdAt', 'updatedAt', 'hitCount', 'enabled'];
    const key = allowedSort.includes(sort) ? sort : 'priority';
    rows = rows.slice().sort((a, b) => {
        if (key === 'priority' || key === 'hitCount') return ((a[key] ?? 0) - (b[key] ?? 0)) * dir;
        if (key === 'enabled') return ((a.enabled ? 1 : 0) - (b.enabled ? 1 : 0)) * dir;
        const av = String(a[key] ?? '');
        const bv = String(b[key] ?? '');
        return av < bv ? -dir : av > bv ? dir : 0;
    });
    // Stable secondary ordering so equal priorities are deterministic.
    if (key === 'priority') rows = sortRules(rows);

    const total = rows.length;
    const page = rows
        .slice(Math.max(0, offset), Math.max(0, offset) + Math.min(1000, Math.max(1, limit)))
        .map((r) => ({ ...r }));
    return { total, offset, limit, rules: page };
}

export function ruleStats() {
    const rules = requireState().rules;
    const count = (fn) => rules.filter(fn).length;
    return {
        total: rules.length,
        enabled: count((r) => r.enabled),
        disabled: count((r) => !r.enabled),
        inbound: count((r) => r.direction === 'inbound'),
        outbound: count((r) => r.direction === 'outbound'),
        allow: count((r) => r.action === 'allow'),
        deny: count((r) => r.action === 'deny'),
        appliedToOS: count((r) => r.osApplied),
        withErrors: count((r) => !!r.osLastError),
        byProtocol: rules.reduce((acc, r) => {
            acc[r.protocol] = (acc[r.protocol] ?? 0) + 1;
            return acc;
        }, {}),
        totalHits: rules.reduce((sum, r) => sum + (r.hitCount ?? 0), 0),
        updatedAt: state.updatedAt,
    };
}

/* ------------------------------------------------------------------ *
 * Mutations (all serialised)
 * ------------------------------------------------------------------ */

export function addRule(input, { actor = 'system' } = {}) {
    return withLock(async () => {
        requireState();
        const clean = validateRuleInput(input);
        if (getRuleByName(clean.name)) {
            throw new ConflictError(`A rule named "${clean.name}" already exists`, [{ field: 'name', message: 'must be unique' }]);
        }
        if (state.rules.length >= 2000) {
            throw new ConflictError('Rule limit reached (2000)');
        }
        const rule = createRule(clean, { actor });
        rule.osRuleName = osRuleName(rule, getConfig().firewall.rulePrefix);
        state.rules.push(rule);
        await persist();
        return { ...rule };
    });
}

export function patchRule(id, patch, { actor = 'system' } = {}) {
    return withLock(async () => {
        requireState();
        const idx = state.rules.findIndex((r) => r.id === id);
        if (idx === -1) throw new NotFoundError('Rule', id);

        const clean = validateRuleInput(patch, { partial: true });
        if (Object.keys(clean).length === 0) throw new ValidationError('No editable fields supplied');

        if (clean.name && clean.name.toLowerCase() !== state.rules[idx].name.toLowerCase()) {
            if (getRuleByName(clean.name)) {
                throw new ConflictError(`A rule named "${clean.name}" already exists`, [{ field: 'name', message: 'must be unique' }]);
            }
        }

        const before = { ...state.rules[idx] };
        const after = applyPatch(before, clean, { actor });
        state.rules[idx] = after;
        await persist();
        return { before, after: { ...after } };
    });
}

export function removeRule(id, { actor = 'system' } = {}) {
    return withLock(async () => {
        requireState();
        const idx = state.rules.findIndex((r) => r.id === id);
        if (idx === -1) throw new NotFoundError('Rule', id);
        const [removed] = state.rules.splice(idx, 1);
        removed.deletedAt = new Date().toISOString();
        removed.deletedBy = actor;
        await persist();
        return { ...removed };
    });
}

export function setRuleEnabled(id, enabled, { actor = 'system' } = {}) {
    return patchRule(id, { enabled: !!enabled }, { actor });
}

/**
 * Reorder by supplying an explicit rule-id order. Priorities are rewritten to
 * 10, 20, 30 … which leaves gaps for later manual insertion.
 */
export function reorderRules(orderedIds, { actor = 'system' } = {}) {
    return withLock(async () => {
        requireState();
        if (!Array.isArray(orderedIds) || orderedIds.length === 0) {
            throw new ValidationError('order must be a non-empty array of rule ids');
        }
        const known = new Set(state.rules.map((r) => r.id));
        const seen = new Set();
        for (const id of orderedIds) {
            if (!known.has(id)) throw new NotFoundError('Rule', id);
            if (seen.has(id)) throw new ValidationError(`Duplicate rule id in order: ${id}`);
            seen.add(id);
        }

        const before = allRules().map((r) => ({ id: r.id, name: r.name, priority: r.priority }));
        let step = 10;
        for (const id of orderedIds) {
            const rule = state.rules.find((r) => r.id === id);
            rule.priority = step;
            rule.updatedAt = new Date().toISOString();
            rule.updatedBy = actor;
            rule.revision = (rule.revision ?? 1) + 1;
            step += 10;
        }
        // Anything not named keeps a priority after the explicit block.
        for (const rule of sortRules(state.rules.filter((r) => !seen.has(r.id)))) {
            rule.priority = step;
            step += 10;
        }
        await persist();
        return { before, after: allRules().map((r) => ({ id: r.id, name: r.name, priority: r.priority })) };
    });
}

/** Update OS-application bookkeeping after a provider call. */
export function markApplied(id, { osRuleName: appliedName = null, applied = true, error = null } = {}) {
    return withLock(async () => {
        requireState();
        const rule = state.rules.find((r) => r.id === id);
        if (!rule) return null;
        rule.osApplied = !!applied;
        rule.osLastError = error ? String(error).slice(0, 500) : null;
        rule.osAppliedAt = applied ? new Date().toISOString() : rule.osAppliedAt ?? null;
        if (appliedName) rule.osRuleName = appliedName;
        await persist();
        return { ...rule };
    });
}

/** Record a match against a rule (monitoring feeds this). */
export function recordHit(id, count = 1) {
    const rule = requireState().rules.find((r) => r.id === id);
    if (!rule) return null;
    rule.hitCount = (rule.hitCount ?? 0) + count;
    rule.lastHitAt = new Date().toISOString();
    // Not persisted on every hit: the periodic flush handles durability.
    return rule.hitCount;
}

/** Flush counters to disk; called on a timer and at shutdown. */
export function flushRules() {
    return withLock(() => persist());
}

/** Replace the entire rule set (restore/import). */
export function replaceAll(rules, { actor = 'system' } = {}) {
    return withLock(async () => {
        requireState();
        if (!Array.isArray(rules)) throw new ValidationError('rules must be an array');
        if (rules.length > 2000) throw new ValidationError('Cannot import more than 2000 rules');

        const cleaned = [];
        const names = new Set();
        for (const [i, raw] of rules.entries()) {
            let clean;
            try {
                clean = validateRuleInput(stripRuntime(raw));
            } catch (err) {
                throw new ValidationError(`Rule ${i + 1} (${raw?.name ?? 'unnamed'}) is invalid: ${err.message}`, err.details);
            }
            const key = clean.name.toLowerCase();
            if (names.has(key)) throw new ConflictError(`Duplicate rule name in import: ${clean.name}`);
            names.add(key);
            const rule = createRule(clean, { actor });
            // Preserve identity and history when the import came from our own export.
            if (typeof raw.id === 'string' && /^rule_[a-z0-9]{6,20}$/.test(raw.id)) rule.id = raw.id;
            if (raw.createdAt) rule.createdAt = raw.createdAt;
            if (raw.createdBy) rule.createdBy = raw.createdBy;
            if (Number.isFinite(raw.hitCount)) rule.hitCount = raw.hitCount;
            rule.osRuleName = osRuleName(rule, getConfig().firewall.rulePrefix);
            cleaned.push(rule);
        }

        const before = state.rules.length;
        state.rules = cleaned;
        await persist();
        return { replaced: before, imported: cleaned.length };
    });
}

function stripRuntime(raw) {
    const {
        id, createdAt, updatedAt, createdBy, updatedBy, revision,
        osRuleName: _osName, osApplied, osLastError, osAppliedAt,
        hitCount, lastHitAt, deletedAt, deletedBy,
        ...rest
    } = raw ?? {};
    return rest;
}

/** Serialisable snapshot for backup/export. */
export function exportRules() {
    const s = requireState();
    return {
        kind: 'sentryfw-rules',
        version: s.version,
        exportedAt: new Date().toISOString(),
        count: s.rules.length,
        rules: allRules(),
    };
}

/** Test seam: in-memory store with no disk persistence. */
export function __setRulesForTests(rules = []) {
    state = { version: RULE_VERSION, updatedAt: new Date().toISOString(), rules: rules.map(migrate) };
    persistDisabled = true;
    chain = Promise.resolve();
}

export function __enablePersistence() {
    persistDisabled = false;
}
