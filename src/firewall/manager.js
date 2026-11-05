/**
 * Firewall manager — the single entry point for every rule change.
 *
 * Both the REST API and the CLI call this module; neither talks to the rule
 * store or a provider directly. That is what keeps GUI and CLI behaviour
 * identical, and it is the only place where "validate → persist → apply to OS →
 * audit → log" is sequenced.
 *
 * Ordering rationale: the canonical store is written first, then the OS is
 * programmed. If the OS call fails, the rule stays in the store marked
 * `osApplied:false` with `osLastError` set, and the GUI shows it as "pending".
 * The alternative (OS first) can leave an OS rule with no owner if the process
 * dies mid-operation, which is worse — an orphan rule silently filtering traffic
 * that no operator can find in the console.
 */

import * as store from './rule-store.js';
import { getProvider, activeProviderId } from './providers/index.js';
import { getConfig } from '../core/config.js';
import { logEvent } from '../core/logger.js';
import { audit } from '../core/audit.js';
import { AppError, ConflictError, NotFoundError, ValidationError, PrivilegeError } from '../core/errors.js';
import {
    analyseRules, evaluate, needsReapply, describeRule, parseOsRuleName, sortRules,
} from './rule-model.js';
import { validateRuleInput, validateISODate } from '../core/validate.js';

/** Should changes be pushed to the OS at all? */
function applyEnabled() {
    return getConfig().firewall.applyToOS === true;
}

function actorOf(ctx) {
    return ctx?.actor ?? 'system';
}

/* ------------------------------------------------------------------ *
 * Reads
 * ------------------------------------------------------------------ */

export function listRules(query = {}) {
    return store.queryRules(query);
}

export function readRule(id) {
    const rule = store.getRule(id);
    if (!rule) throw new NotFoundError('Rule', id);
    return rule;
}

export function stats() {
    return store.ruleStats();
}

export function analyse() {
    const cfg = getConfig();
    return analyseRules(store.allRules(), { sensitivePorts: cfg.detection?.sensitivePorts ?? [] });
}

/** Native command preview for a stored or hypothetical rule. */
export function preview(ruleOrInput) {
    const provider = getProvider();
    const rule = typeof ruleOrInput === 'string'
        ? readRule(ruleOrInput)
        : { ...validateRuleInput(ruleOrInput), id: 'rule_preview', osRuleName: null };
    return {
        provider: activeProviderId(),
        applyToOS: applyEnabled(),
        summary: describeRule(rule),
        native: provider.translate(rule),
    };
}

/**
 * "What would happen to this packet?" — the policy tester behind the GUI's
 * Test Packet panel and `fwctl test`.
 */
export function testPacket(input) {
    const conn = normalisePacket(input);
    const cfg = getConfig();
    const result = evaluate(store.allRules(), conn, cfg.firewall.defaultPolicy);
    return {
        packet: conn,
        ...result,
        matchedRule: result.matchedRule ? { ...result.matchedRule } : null,
        explanation: explain(result, conn),
        provider: activeProviderId(),
        note: result.agrees
            ? null
            : 'First-match ordering and Windows Filtering Platform precedence disagree for this packet. Windows applies the Block rule regardless of priority.',
    };
}

function normalisePacket(input) {
    const clean = validateRuleInput({
        direction: input.direction,
        protocol: input.protocol,
        srcAddress: input.srcAddress ?? 'any',
        dstAddress: input.dstAddress ?? 'any',
        srcPort: input.srcPort ?? 'any',
        dstPort: input.dstPort ?? 'any',
        iface: input.iface ?? 'any',
        name: 'packet-probe',
    }, { partial: true });

    // A packet has single values, not specs.
    const single = (spec, field) => {
        const value = spec ?? 'any';
        if (value === 'any') return field.endsWith('Port') ? 0 : '0.0.0.0';
        if (String(value).includes(',') || String(value).includes('-') || String(value).includes('/')) {
            throw ValidationError.field(field, 'a test packet needs a single value, not a range or list');
        }
        return field.endsWith('Port') ? Number(value) : String(value);
    };

    const direction = clean.direction ?? 'inbound';
    return {
        direction,
        protocol: clean.protocol ?? 'tcp',
        localAddress: direction === 'inbound' ? single(clean.dstAddress, 'dstAddress') : single(clean.srcAddress, 'srcAddress'),
        localPort: direction === 'inbound' ? single(clean.dstPort, 'dstPort') : single(clean.srcPort, 'srcPort'),
        remoteAddress: direction === 'inbound' ? single(clean.srcAddress, 'srcAddress') : single(clean.dstAddress, 'dstAddress'),
        remotePort: direction === 'inbound' ? single(clean.srcPort, 'srcPort') : single(clean.dstPort, 'dstPort'),
        iface: clean.iface ?? 'any',
    };
}

function explain(result, conn) {
    if (result.matchedRule) {
        return `Rule "${result.matchedRule.name}" (priority ${result.matchedRule.priority}) matched first and its action is ${result.decision.toUpperCase()}.`;
    }
    return `No rule matched, so the default ${conn.direction} policy applies: ${result.defaultPolicy.toUpperCase()}.`;
}

/* ------------------------------------------------------------------ *
 * Writes
 * ------------------------------------------------------------------ */

export async function createRuleAndApply(input, ctx = {}) {
    const actor = actorOf(ctx);
    const rule = await store.addRule(input, { actor });

    const applied = await pushToOS(rule, 'apply', ctx);

    await audit({
        actor,
        action: 'rule.create',
        target: `${rule.name} (${rule.id})`,
        after: publicRule(rule),
        reason: ctx.reason ?? null,
        source: ctx.source ?? null,
        outcome: applied.ok ? 'success' : 'partial',
    });

    logEvent({
        level: applied.ok ? 'info' : 'warn',
        category: 'rule',
        action: 'rule.create',
        message: `Rule created: ${rule.name} — ${describeRule(rule)}${applied.ok ? '' : ` (OS apply failed: ${applied.error})`}`,
        actor, source: ctx.source ?? null, target: rule.id,
        details: { rule: publicRule(rule), os: applied },
    });

    return { rule: store.getRule(rule.id), os: applied };
}

export async function updateRule(id, patch, ctx = {}) {
    const actor = actorOf(ctx);
    const { before, after } = await store.patchRule(id, patch, { actor });

    let os = { ok: true, skipped: true, reason: 'no OS-visible change' };
    if (needsReapply(before, after)) {
        // Name changes produce a new OS rule name, so retire the old one first.
        if (before.osRuleName !== after.osRuleName && before.osApplied) {
            await pushToOS(before, 'remove', ctx);
        }
        os = await pushToOS(after, 'apply', ctx);
    }

    await audit({
        actor,
        action: 'rule.update',
        target: `${after.name} (${id})`,
        before: publicRule(before),
        after: publicRule(after),
        reason: ctx.reason ?? null,
        source: ctx.source ?? null,
        outcome: os.ok ? 'success' : 'partial',
    });

    logEvent({
        level: os.ok ? 'info' : 'warn',
        category: 'rule',
        action: 'rule.update',
        message: `Rule updated: ${after.name} — ${changeSummary(before, after)}`,
        actor, source: ctx.source ?? null, target: id,
        details: { changed: changedFields(before, after), os },
    });

    return { rule: store.getRule(id), os };
}

export async function deleteRule(id, ctx = {}) {
    const actor = actorOf(ctx);
    const existing = readRule(id);

    const os = existing.osApplied || applyEnabled()
        ? await pushToOS(existing, 'remove', ctx)
        : { ok: true, skipped: true, reason: 'rule was never applied to the OS' };

    const removed = await store.removeRule(id, { actor });

    await audit({
        actor,
        action: 'rule.delete',
        target: `${removed.name} (${id})`,
        before: publicRule(removed),
        reason: ctx.reason ?? null,
        source: ctx.source ?? null,
        outcome: os.ok ? 'success' : 'partial',
    });

    logEvent({
        level: 'warn',
        category: 'rule',
        action: 'rule.delete',
        message: `Rule deleted: ${removed.name} — ${describeRule(removed)}`,
        actor, source: ctx.source ?? null, target: id,
        details: { rule: publicRule(removed), os },
    });

    return { rule: removed, os };
}

export async function setEnabled(id, enabled, ctx = {}) {
    const actor = actorOf(ctx);
    const { before, after } = await store.setRuleEnabled(id, enabled, { actor });

    let os = { ok: true, skipped: true, reason: 'OS apply disabled' };
    if (applyEnabled()) {
        const provider = getProvider();
        try {
            const res = await provider.setEnabled(after, !!enabled);
            await store.markApplied(id, { osRuleName: res.osName, applied: !!enabled || !!res.osName, error: null });
            os = { ok: true, ...res };
        } catch (err) {
            const e = toAppErrorLike(err);
            await store.markApplied(id, { applied: before.osApplied, error: e.message });
            os = { ok: false, error: e.message, code: e.code };
        }
    }

    await audit({
        actor,
        action: enabled ? 'rule.enable' : 'rule.disable',
        target: `${after.name} (${id})`,
        before: { enabled: before.enabled },
        after: { enabled: after.enabled },
        reason: ctx.reason ?? null,
        source: ctx.source ?? null,
        outcome: os.ok ? 'success' : 'partial',
    });

    logEvent({
        level: 'info',
        category: 'rule',
        action: enabled ? 'rule.enable' : 'rule.disable',
        message: `Rule ${enabled ? 'enabled' : 'disabled'}: ${after.name}`,
        actor, source: ctx.source ?? null, target: id,
        details: { os },
    });

    return { rule: store.getRule(id), os };
}

export async function reorder(orderedIds, ctx = {}) {
    const actor = actorOf(ctx);
    const { before, after } = await store.reorderRules(orderedIds, { actor });

    // Priority is a SentryFW concept on Windows (WFP has no order) but maps to
    // chain position on Linux, so re-apply there.
    const provider = getProvider();
    let os = { ok: true, skipped: true, reason: 'provider does not use rule order' };
    if (applyEnabled() && provider.capabilities().priorities) {
        const results = [];
        for (const rule of sortRules(store.allRules()).filter((r) => r.osApplied)) {
            results.push(await pushToOS(rule, 'apply', ctx));
        }
        os = { ok: results.every((r) => r.ok), reapplied: results.length };
    }

    await audit({
        actor, action: 'rule.reorder', target: `${orderedIds.length} rule(s)`,
        before, after, reason: ctx.reason ?? null, source: ctx.source ?? null,
    });

    logEvent({
        level: 'info', category: 'rule', action: 'rule.reorder',
        message: `Rule order changed (${orderedIds.length} rule(s) repositioned)`,
        actor, source: ctx.source ?? null, details: { os },
    });

    return { order: after, os };
}

/* ------------------------------------------------------------------ *
 * OS interaction
 * ------------------------------------------------------------------ */

/**
 * Push one rule to the OS. Never throws: the outcome is returned so the caller
 * can record a partial success and the GUI can show a per-rule error badge.
 */
async function pushToOS(rule, operation, ctx = {}) {
    if (!applyEnabled()) {
        return { ok: true, skipped: true, reason: 'firewall.applyToOS is disabled', provider: activeProviderId() };
    }

    const provider = getProvider();
    try {
        if (operation === 'remove') {
            const res = await provider.removeRule(rule);
            await store.markApplied(rule.id, { applied: false, error: null });
            logEvent({
                level: 'info', category: 'firewall', action: 'os.remove',
                message: `Removed OS firewall rule ${res.osName}`,
                actor: actorOf(ctx), target: rule.id, details: res,
            });
            return { ok: true, provider: activeProviderId(), ...res };
        }

        if (rule.enabled === false && provider.capabilities().enableDisable) {
            // Keep a disabled rule present-but-off so it is visible in wf.msc.
            const res = await provider.applyRule(rule);
            await store.markApplied(rule.id, { osRuleName: res.osName, applied: true, error: null });
            return { ok: true, provider: activeProviderId(), ...res };
        }

        const res = await provider.applyRule(rule);
        await store.markApplied(rule.id, { osRuleName: res.osName, applied: true, error: null });
        logEvent({
            level: 'info', category: 'firewall', action: 'os.apply',
            message: `Applied OS firewall rule ${res.osName}${res.replaced ? ' (replaced existing)' : ''}`,
            actor: actorOf(ctx), target: rule.id, details: res,
        });
        return { ok: true, provider: activeProviderId(), ...res };
    } catch (err) {
        const e = toAppErrorLike(err);
        await store.markApplied(rule.id, { applied: false, error: e.message });
        logEvent({
            level: e instanceof PrivilegeError ? 'warn' : 'error',
            category: 'firewall',
            action: `os.${operation}_failed`,
            message: `OS firewall ${operation} failed for "${rule.name}": ${e.message}`,
            actor: actorOf(ctx), target: rule.id,
            details: { code: e.code, details: e.details ?? null, hint: e.details?.hint ?? null },
        });
        return { ok: false, provider: activeProviderId(), error: e.message, code: e.code, hint: e.details?.hint ?? null };
    }
}

/** Apply every enabled rule that is not yet present in the OS. */
export async function applyAll(ctx = {}) {
    const actor = actorOf(ctx);
    if (!applyEnabled()) {
        throw new ConflictError('firewall.applyToOS is disabled — enable it in Settings before applying rules to the operating system');
    }
    const rules = sortRules(store.allRules());
    const results = [];
    for (const rule of rules) {
        results.push({ id: rule.id, name: rule.name, ...(await pushToOS(rule, 'apply', ctx)) });
    }
    const failed = results.filter((r) => !r.ok);

    await audit({
        actor, action: 'firewall.apply_all',
        target: `${rules.length} rule(s)`,
        after: { applied: results.length - failed.length, failed: failed.length },
        reason: ctx.reason ?? null, source: ctx.source ?? null,
        outcome: failed.length === 0 ? 'success' : 'partial',
    });

    logEvent({
        level: failed.length ? 'warn' : 'info',
        category: 'firewall', action: 'firewall.apply_all',
        message: `Applied ${results.length - failed.length}/${results.length} rules to the operating system`,
        actor, source: ctx.source ?? null, details: { failed: failed.map((f) => ({ name: f.name, error: f.error })) },
    });

    return { total: results.length, applied: results.length - failed.length, failed, results };
}

/**
 * Compare the canonical store with the live OS rule set and report drift.
 * Read-only unless `repair` is set.
 */
export async function sync({ repair = false, ...ctx } = {}) {
    const provider = getProvider();
    const caps = provider.capabilities();
    if (!caps.read) {
        return { supported: false, reason: `${provider.label} cannot enumerate OS rules` };
    }

    let native;
    try {
        native = await provider.listNative({ scope: 'managed' });
    } catch (err) {
        const e = toAppErrorLike(err);
        return { supported: true, ok: false, error: e.message, code: e.code, hint: e.details?.hint ?? null };
    }

    const nativeList = Array.isArray(native) ? native : (native.rules ?? []);
    const byName = new Map(nativeList.map((n) => [n.osName, n]));
    const byRuleId = new Map();
    for (const n of nativeList) {
        const id = parseOsRuleName(n.osName) ?? parseOsRuleName(n.displayName);
        if (id) byRuleId.set(id, n);
        // Linux comment form: "<prefix>:<ruleId>"
        const colonId = /:(rule_[a-z0-9]{6,20})$/.exec(String(n.osName ?? ''))?.[1];
        if (colonId) byRuleId.set(colonId, n);
    }

    const drift = [];
    for (const rule of sortRules(store.allRules())) {
        const found = byRuleId.get(rule.id) ?? byName.get(rule.osRuleName);
        if (!found) {
            if (rule.osApplied) {
                drift.push({ type: 'missing-in-os', ruleId: rule.id, name: rule.name, detail: 'The store believes this rule is applied but it is not present in the OS' });
            } else {
                drift.push({ type: 'not-applied', ruleId: rule.id, name: rule.name, detail: 'Rule exists in SentryFW but has not been applied to the OS' });
            }
            continue;
        }
        const diffs = compareToNative(rule, found);
        if (diffs.length > 0) {
            drift.push({ type: 'modified-in-os', ruleId: rule.id, name: rule.name, detail: `OS rule differs: ${diffs.join('; ')}`, fields: diffs });
        }
    }

    const managedIds = new Set(store.allRules().map((r) => r.id));
    for (const n of nativeList) {
        const id = parseOsRuleName(n.osName) ?? /:(rule_[a-z0-9]{6,20})$/.exec(String(n.osName ?? ''))?.[1];
        if (id && !managedIds.has(id)) {
            drift.push({ type: 'orphan-in-os', osName: n.osName, detail: 'OS rule carries the SentryFW group but has no matching rule in the store' });
        }
    }

    let repaired = null;
    if (repair && drift.length > 0) {
        if (!applyEnabled()) throw new ConflictError('Cannot repair drift while firewall.applyToOS is disabled');
        const actions = [];
        for (const d of drift) {
            if (d.type === 'orphan-in-os') {
                const res = await pushToOS({ id: 'orphan', name: d.osName, osRuleName: d.osName }, 'remove', ctx);
                actions.push({ ...d, action: 'removed-orphan', ok: res.ok });
            } else if (d.type !== 'not-applied') {
                const rule = store.getRule(d.ruleId);
                if (rule) {
                    const res = await pushToOS(rule, 'apply', ctx);
                    actions.push({ ...d, action: 'reapplied', ok: res.ok, error: res.error ?? null });
                }
            }
        }
        repaired = actions;
        await audit({
            actor: actorOf(ctx), action: 'firewall.sync_repair',
            target: `${actions.length} item(s)`, after: { actions: actions.length },
            source: ctx.source ?? null,
        });
    }

    logEvent({
        level: drift.length ? 'warn' : 'info',
        category: 'firewall', action: 'firewall.sync',
        message: drift.length
            ? `Configuration drift detected: ${drift.length} discrepancy/ies between SentryFW and the OS firewall`
            : 'SentryFW and the OS firewall are in sync',
        actor: actorOf(ctx), source: ctx.source ?? null,
        details: { drift: drift.slice(0, 50), repaired: repaired?.length ?? 0 },
    });

    return {
        supported: true,
        ok: true,
        provider: activeProviderId(),
        osRuleCount: nativeList.length,
        storeRuleCount: store.allRules().length,
        inSync: drift.length === 0,
        drift,
        repaired,
    };
}

const COMPARE_FIELDS = Object.freeze(['direction', 'action', 'protocol', 'srcAddress', 'dstAddress', 'srcPort', 'dstPort', 'enabled']);

function compareToNative(rule, native) {
    const diffs = [];
    for (const field of COMPARE_FIELDS) {
        const mine = normaliseForCompare(rule[field]);
        const theirs = normaliseForCompare(native[field]);
        if (theirs === undefined || theirs === null || theirs === '') continue; // provider could not read it
        if (mine !== theirs) diffs.push(`${field}: expected "${mine}", OS has "${theirs}"`);
    }
    return diffs;
}

function normaliseForCompare(v) {
    if (typeof v === 'boolean') return v ? 'true' : 'false';
    if (v === undefined || v === null) return v;
    return String(v).toLowerCase().split(',').map((s) => s.trim()).filter(Boolean).sort().join(',');
}

/* ------------------------------------------------------------------ *
 * OS-level inspection helpers
 * ------------------------------------------------------------------ */

export async function osRules({ scope = 'managed', limit = 500 } = {}) {
    const provider = getProvider();
    if (!provider.capabilities().read) {
        return { supported: false, reason: `${provider.label} cannot enumerate OS rules`, rules: [] };
    }
    const res = await provider.listNative({ scope, limit });
    const rules = Array.isArray(res) ? res : (res.rules ?? []);
    return {
        supported: true,
        provider: activeProviderId(),
        scope,
        total: Array.isArray(res) ? rules.length : (res.total ?? rules.length),
        truncated: Array.isArray(res) ? false : !!res.truncated,
        rules,
    };
}

export async function providerStatus() {
    const provider = getProvider();
    const [probe, policy] = await Promise.all([
        provider.probe().catch((err) => ({ available: false, reason: err.message })),
        provider.defaultPolicy().catch(() => ({ inbound: null, outbound: null, source: 'error' })),
    ]);
    return {
        id: activeProviderId(),
        label: provider.label,
        capabilities: provider.capabilities(),
        applyToOS: applyEnabled(),
        probe,
        osDefaultPolicy: policy,
        configuredDefaultPolicy: { ...getConfig().firewall.defaultPolicy },
    };
}

/* ------------------------------------------------------------------ *
 * Backup / restore
 * ------------------------------------------------------------------ */

export async function importRules(payload, ctx = {}) {
    const actor = actorOf(ctx);
    const rules = Array.isArray(payload) ? payload : payload?.rules;
    if (!Array.isArray(rules)) throw new ValidationError('Import payload must contain a "rules" array');

    const result = await store.replaceAll(rules, { actor });

    await audit({
        actor, action: 'firewall.import',
        target: `${result.imported} rule(s)`,
        before: { rules: result.replaced }, after: { rules: result.imported },
        reason: ctx.reason ?? null, source: ctx.source ?? null,
    });

    logEvent({
        level: 'warn', category: 'backup', action: 'firewall.import',
        message: `Rule set replaced: ${result.replaced} rule(s) removed, ${result.imported} imported`,
        actor, source: ctx.source ?? null,
    });

    return result;
}

export function exportRules() {
    return store.exportRules();
}

/* ------------------------------------------------------------------ *
 * Utilities
 * ------------------------------------------------------------------ */

function publicRule(rule) {
    const { osLastError, ...rest } = rule ?? {};
    return rest;
}

function changedFields(before, after) {
    const fields = new Set([...Object.keys(before ?? {}), ...Object.keys(after ?? {})]);
    const changed = {};
    for (const f of fields) {
        if (['updatedAt', 'revision', 'updatedBy'].includes(f)) continue;
        if (JSON.stringify(before?.[f]) !== JSON.stringify(after?.[f])) {
            changed[f] = { from: before?.[f], to: after?.[f] };
        }
    }
    return changed;
}

function changeSummary(before, after) {
    const changed = changedFields(before, after);
    const keys = Object.keys(changed);
    if (keys.length === 0) return 'no effective change';
    return keys.map((k) => `${k}: ${JSON.stringify(changed[k].from)} → ${JSON.stringify(changed[k].to)}`).join(', ');
}

function toAppErrorLike(err) {
    if (err instanceof AppError) return err;
    return new AppError(err?.message ?? String(err), { code: 'INTERNAL_ERROR', status: 500 });
}

export { validateISODate };
