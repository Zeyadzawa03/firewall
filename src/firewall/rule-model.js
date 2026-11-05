/**
 * Canonical rule model.
 *
 * One vendor-neutral shape is stored and shown in the GUI/CLI; each provider
 * translates it into its native form (Windows NetSecurity, iptables, nft, ufw,
 * firewalld). Keeping translation at the edge means the store, the API, the
 * evaluation engine and the tests all agree on one representation.
 *
 * Rule shape:
 * {
 *   id, name, description, direction, action, protocol,
 *   srcAddress, dstAddress, srcPort, dstPort, iface, profiles, program,
 *   priority, enabled, tags,
 *   createdAt, updatedAt, createdBy, updatedBy,
 *   osRuleName, osApplied, osLastError, hitCount, lastHitAt, revision
 * }
 */

import { randomId, shortHash } from '../core/ids.js';
import { ipMatchesSpec, portMatchesSpec, expandPortSpec } from '../core/validate.js';

export const RULE_VERSION = 2;

export function createRule(input, { actor = 'system' } = {}) {
    const now = new Date().toISOString();
    const rule = {
        id: randomId('rule'),
        name: input.name,
        description: input.description ?? '',
        direction: input.direction ?? 'inbound',
        action: input.action ?? 'deny',
        protocol: input.protocol ?? 'any',
        srcAddress: input.srcAddress ?? 'any',
        dstAddress: input.dstAddress ?? 'any',
        srcPort: input.srcPort ?? 'any',
        dstPort: input.dstPort ?? 'any',
        iface: input.iface ?? 'any',
        profiles: input.profiles ?? ['Any'],
        program: input.program ?? '',
        priority: input.priority ?? 100,
        enabled: input.enabled !== false,
        tags: input.tags ?? [],
        createdAt: now,
        updatedAt: now,
        createdBy: actor,
        updatedBy: actor,
        revision: 1,
        osRuleName: null,
        osApplied: false,
        osLastError: null,
        hitCount: 0,
        lastHitAt: null,
    };
    rule.osRuleName = osRuleName(rule);
    return rule;
}

/**
 * Deterministic OS-visible rule name. The id suffix lets `sync` correlate an OS
 * rule back to the managed rule even after a rename, and the prefix makes
 * SentryFW-managed rules obvious in the Windows Firewall GUI.
 */
export function osRuleName(rule, prefix = 'SentryFW') {
    const safeName = String(rule.name || 'rule').replace(/[^A-Za-z0-9 _.\-]/g, '').slice(0, 48).trim() || 'rule';
    return `${prefix} - ${safeName} [${rule.id}]`;
}

/** Extract the managed rule id from an OS rule name, or null. */
export function parseOsRuleName(name) {
    const m = /\[(rule_[a-z0-9]{6,20})\]\s*$/.exec(String(name ?? '').trim());
    return m ? m[1] : null;
}

export function applyPatch(rule, patch, { actor = 'system' } = {}) {
    const next = { ...rule };
    for (const [k, v] of Object.entries(patch)) next[k] = v;
    next.updatedAt = new Date().toISOString();
    next.updatedBy = actor;
    next.revision = (rule.revision ?? 1) + 1;
    if (patch.name !== undefined && patch.name !== rule.name) {
        next.osRuleName = osRuleName(next);
    }
    return next;
}

/** Fields that change the packet-matching behaviour and require a re-apply. */
const MATCH_FIELDS = Object.freeze([
    'direction', 'action', 'protocol', 'srcAddress', 'dstAddress',
    'srcPort', 'dstPort', 'iface', 'profiles', 'program', 'enabled', 'name',
]);

export function needsReapply(before, after) {
    return MATCH_FIELDS.some((f) => JSON.stringify(before?.[f]) !== JSON.stringify(after?.[f]));
}

/** Stable fingerprint of the matching criteria; used for duplicate detection. */
export function ruleFingerprint(rule) {
    return shortHash([
        rule.direction, rule.action, rule.protocol,
        rule.srcAddress, rule.dstAddress, rule.srcPort, rule.dstPort,
        rule.iface, (rule.profiles ?? []).join('+'), rule.program ?? '',
    ].join('|'), 16);
}

/* ------------------------------------------------------------------ *
 * Evaluation
 * ------------------------------------------------------------------ */

/**
 * Does a rule match an observed connection?
 * @param {object} rule
 * @param {{direction:string, protocol:string, localAddress:string, localPort:number, remoteAddress:string, remotePort:number, iface?:string}} conn
 */
export function ruleMatchesConnection(rule, conn) {
    if (!rule.enabled) return false;
    if (rule.direction !== conn.direction) return false;

    if (rule.protocol !== 'any') {
        const p = String(conn.protocol ?? '').toLowerCase();
        if (p !== rule.protocol) return false;
    }

    // For an inbound rule, "source" is the remote peer; for outbound it is us.
    const src = conn.direction === 'inbound' ? conn.remoteAddress : conn.localAddress;
    const dst = conn.direction === 'inbound' ? conn.localAddress : conn.remoteAddress;
    const sport = conn.direction === 'inbound' ? conn.remotePort : conn.localPort;
    const dport = conn.direction === 'inbound' ? conn.localPort : conn.remotePort;

    if (!ipMatchesSpec(src, rule.srcAddress)) return false;
    if (!ipMatchesSpec(dst, rule.dstAddress)) return false;

    const portish = rule.protocol === 'tcp' || rule.protocol === 'udp' || rule.protocol === 'any';
    if (portish) {
        if (!portMatchesSpec(sport, rule.srcPort)) return false;
        if (!portMatchesSpec(dport, rule.dstPort)) return false;
    }

    if (rule.iface !== 'any' && conn.iface && conn.iface !== rule.iface) return false;

    return true;
}

/**
 * First-match evaluation, mirroring how the OS engines behave: rules are
 * considered in priority order (lower number = evaluated earlier), then by
 * creation order. If nothing matches, the configured default policy applies.
 *
 * Note on Windows semantics: the real Windows Filtering Platform evaluates
 * block rules ahead of allow rules regardless of order. `evaluate()` reports
 * both the first-match decision and the WFP-style decision so the GUI can warn
 * when they disagree.
 */
export function evaluate(rules, conn, defaultPolicy = { inbound: 'deny', outbound: 'allow' }) {
    const ordered = sortRules(rules);
    const matches = ordered.filter((r) => ruleMatchesConnection(r, conn));

    const firstMatch = matches[0] ?? null;
    const denyMatch = matches.find((r) => r.action === 'deny') ?? null;

    const fallback = defaultPolicy[conn.direction] ?? 'deny';
    const decision = firstMatch ? firstMatch.action : fallback;
    const wfpDecision = denyMatch ? 'deny' : (matches.find((r) => r.action === 'allow') ? 'allow' : fallback);

    return {
        decision,
        wfpDecision,
        agrees: decision === wfpDecision,
        matchedRule: firstMatch,
        matchedRuleId: firstMatch?.id ?? null,
        matchCount: matches.length,
        matchedRuleIds: matches.map((r) => r.id),
        usedDefault: !firstMatch,
        defaultPolicy: fallback,
    };
}

export function sortRules(rules) {
    return [...rules].sort((a, b) => {
        if ((a.priority ?? 100) !== (b.priority ?? 100)) return (a.priority ?? 100) - (b.priority ?? 100);
        const at = Date.parse(a.createdAt ?? 0) || 0;
        const bt = Date.parse(b.createdAt ?? 0) || 0;
        if (at !== bt) return at - bt;
        return String(a.id).localeCompare(String(b.id));
    });
}

/* ------------------------------------------------------------------ *
 * Static analysis: duplicates, shadowing, risky rules
 * ------------------------------------------------------------------ */

/**
 * Report rules that can never be reached because an earlier, broader rule with
 * a different action already covers them, plus exact duplicates and rules that
 * are risky by policy (e.g. "allow any -> RDP from any source").
 */
export function analyseRules(rules, { sensitivePorts = [] } = {}) {
    const ordered = sortRules(rules.filter((r) => r.enabled));
    const findings = [];

    // Exact duplicates by fingerprint.
    const byFingerprint = new Map();
    for (const r of sortRules(rules)) {
        const fp = ruleFingerprint(r);
        if (byFingerprint.has(fp)) {
            findings.push({
                severity: 'low',
                type: 'duplicate',
                ruleId: r.id,
                ruleName: r.name,
                relatedRuleId: byFingerprint.get(fp).id,
                message: `Identical matching criteria to "${byFingerprint.get(fp).name}"`,
            });
        } else {
            byFingerprint.set(fp, r);
        }
    }

    // Shadowing.
    for (let i = 0; i < ordered.length; i++) {
        for (let j = i + 1; j < ordered.length; j++) {
            const earlier = ordered[i];
            const later = ordered[j];
            if (earlier.direction !== later.direction) continue;
            if (!covers(earlier, later)) continue;
            findings.push({
                severity: earlier.action === later.action ? 'low' : 'medium',
                type: 'shadowed',
                ruleId: later.id,
                ruleName: later.name,
                relatedRuleId: earlier.id,
                message: earlier.action === later.action
                    ? `Redundant: fully covered by earlier rule "${earlier.name}" with the same action`
                    : `Unreachable: earlier rule "${earlier.name}" (${earlier.action}) already covers this traffic`,
            });
            break;
        }
    }

    // Risky allow rules.
    const sensitive = new Set(sensitivePorts.map(Number));
    for (const r of ordered) {
        if (r.action !== 'allow' || r.direction !== 'inbound') continue;
        const openSource = r.srcAddress === 'any';
        const ports = expandPortSpec(r.dstPort, 256);
        const hitsSensitive = ports.some((p) => sensitive.has(p));
        if (openSource && r.dstPort === 'any' && r.protocol === 'any') {
            findings.push({
                severity: 'critical', type: 'permissive', ruleId: r.id, ruleName: r.name,
                message: 'Allows any protocol on any port from any source (equivalent to disabling inbound filtering for matching traffic)',
            });
        } else if (openSource && hitsSensitive) {
            findings.push({
                severity: 'high', type: 'exposed-service', ruleId: r.id, ruleName: r.name,
                message: `Exposes sensitive port(s) ${ports.filter((p) => sensitive.has(p)).join(', ')} to any source address`,
            });
        } else if (openSource && r.dstPort === 'any') {
            findings.push({
                severity: 'medium', type: 'permissive', ruleId: r.id, ruleName: r.name,
                message: `Allows all ${r.protocol.toUpperCase()} ports from any source address`,
            });
        }
    }

    const severityRank = { critical: 0, high: 1, medium: 2, low: 3 };
    findings.sort((a, b) => severityRank[a.severity] - severityRank[b.severity]);
    return findings;
}

/** True when rule `a` matches every packet that rule `b` matches. */
function covers(a, b) {
    if (a.direction !== b.direction) return false;
    if (a.protocol !== 'any' && a.protocol !== b.protocol) return false;
    if (a.iface !== 'any' && a.iface !== b.iface) return false;
    if (a.program && a.program !== b.program) return false;
    if (!specCovers(a.srcAddress, b.srcAddress, 'address')) return false;
    if (!specCovers(a.dstAddress, b.dstAddress, 'address')) return false;
    if (!specCovers(a.srcPort, b.srcPort, 'port')) return false;
    if (!specCovers(a.dstPort, b.dstPort, 'port')) return false;
    if (!profilesCover(a.profiles, b.profiles)) return false;
    return true;
}

function profilesCover(a = ['Any'], b = ['Any']) {
    if (a.includes('Any')) return true;
    if (b.includes('Any')) return false;
    return b.every((p) => a.includes(p));
}

function specCovers(outer, inner, kind) {
    if (outer === 'any') return true;
    if (inner === 'any') return false;
    if (outer === inner) return true;
    if (kind === 'port') {
        const innerPorts = expandPortSpec(inner, 2048);
        if (innerPorts.length === 0) return false;
        return innerPorts.every((p) => portMatchesSpec(p, outer));
    }
    // Addresses: conservative — only claim coverage for representable cases.
    const innerTokens = inner.split(',').map((t) => t.trim());
    return innerTokens.every((token) => {
        if (token.includes('-')) {
            const [from, to] = token.split('-');
            return ipMatchesSpec(from.trim(), outer) && ipMatchesSpec(to.trim(), outer);
        }
        if (token.includes('/')) {
            const [net, prefix] = token.split('/');
            // A CIDR is covered when the outer spec contains an equal-or-shorter prefix over the same network.
            return outer.split(',').some((o) => {
                const ot = o.trim();
                if (!ot.includes('/')) return false;
                const [onet, oprefix] = ot.split('/');
                return Number(oprefix) <= Number(prefix) && ipMatchesSpec(net, `${onet}/${oprefix}`);
            });
        }
        return ipMatchesSpec(token, outer);
    });
}

/** Human-readable one-line summary used by the CLI table and GUI tooltips. */
export function describeRule(rule) {
    const proto = rule.protocol === 'any' ? 'any' : rule.protocol.toUpperCase();
    const arrow = rule.direction === 'inbound' ? '→' : '←';
    const src = `${rule.srcAddress}${rule.srcPort !== 'any' ? `:${rule.srcPort}` : ''}`;
    const dst = `${rule.dstAddress}${rule.dstPort !== 'any' ? `:${rule.dstPort}` : ''}`;
    return `${rule.action.toUpperCase()} ${proto} ${src} ${arrow} ${dst}${rule.iface !== 'any' ? ` on ${rule.iface}` : ''}`;
}
