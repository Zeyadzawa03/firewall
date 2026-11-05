/**
 * REST API surface.
 *
 * Every route declares the permission it requires; the server enforces
 * authentication, CSRF and RBAC from that metadata rather than each handler
 * repeating the checks. Handlers receive a context object and return a plain
 * value that becomes the JSON body.
 *
 * ctx = {
 *   req, res, params, query, body, principal, session,
 *   source,      // client address
 *   actor,       // username or 'anonymous'
 *   requestId,
 * }
 */

import { Router, parseQuery } from './http.js';
import * as manager from '../firewall/manager.js';
import * as ruleStore from '../firewall/rule-store.js';
import * as blocklist from '../monitoring/blocklist.js';
import * as backup from '../config/backup.js';
import { monitor } from '../monitoring/monitor.js';
import { detection } from '../monitoring/detection.js';
import {
    listInterfaces, listConnections, listListeners, connectionStats, invalidateNetworkCache,
} from '../network/inspector.js';
import {
    queryEvents, exportEvents, logStats, recentEvents, LEVELS, CATEGORIES,
} from '../core/logger.js';
import { queryAudit, auditStats, exportAudit, verifyChain } from '../core/audit.js';
import {
    getConfig, publicConfig, updateSettings, MUTABLE_SETTINGS,
} from '../core/config.js';
import { describeProviders } from '../firewall/providers/index.js';
import {
    listUsers, createUser, updateUser, deleteUser, changeOwnPassword,
    listSessions, authStats, publicUser, findUser, permissionsForRole, ROLES,
} from '../core/auth.js';
import { platformInfo, isElevated, elevationHint } from '../core/safe-exec.js';
import { ValidationError, ConflictError, NotFoundError } from '../core/errors.js';
import { validateISODate, validateString } from '../core/validate.js';
import { PROTOCOLS, DIRECTIONS, ACTIONS } from '../core/validate.js';

export const router = new Router();

/** Shorthand: build the ctx passed to manager/blocklist calls. */
function opCtx(ctx, extra = {}) {
    return {
        actor: ctx.actor,
        source: ctx.source,
        reason: typeof ctx.body?.reason === 'string' ? ctx.body.reason.slice(0, 300) : null,
        ...extra,
    };
}

/** Destructive operations require an explicit confirm flag when configured. */
function requireConfirmation(ctx, what) {
    if (getConfig().security.requireConfirmForDestructive === false) return;
    const confirmed = ctx.body?.confirm === true || ctx.query.bool('confirm', false) === true;
    if (!confirmed) {
        throw new ConflictError(
            `This operation is destructive (${what}). Re-send with {"confirm": true} to proceed.`,
            { requiresConfirmation: true, operation: what },
        );
    }
}

/* ================================================================== *
 * Meta
 * ================================================================== */

router.get('/api', async () => ({
    name: 'SentryFW API',
    version: 2,
    documentation: '/docs/API.md',
    routes: router.describe(),
}), { auth: false });

router.get('/api/health', async () => ({
    status: 'ok',
    uptimeSeconds: Math.round(process.uptime()),
    monitor: monitor.status().running,
    timestamp: new Date().toISOString(),
}), { auth: false });

router.get('/api/system', async () => {
    const [provider, elevated] = await Promise.all([
        manager.providerStatus(),
        isElevated(),
    ]);
    return {
        platform: platformInfo(),
        elevated,
        elevationHint: elevated ? null : elevationHint(),
        provider,
        config: publicConfig(),
        auth: authStats(),
        log: logStats(),
        audit: auditStats(),
        monitor: monitor.status(),
        detection: detection.summary(),
        blocklist: blocklist.stats(),
        rules: ruleStore.ruleStats(),
    };
}, { permission: 'settings:read' });

/* ================================================================== *
 * Dashboard
 * ================================================================== */

router.get('/api/dashboard', async () => {
    const [dash, provider] = await Promise.all([
        monitor.dashboard(),
        manager.providerStatus().catch((err) => ({ error: err.message })),
    ]);

    const events = recentEvents(15);
    const findings = detection.query({ limit: 8 }).findings;
    const analysis = manager.analyse();

    return {
        rules: dash.rules,
        monitor: dash.monitor,
        detection: dash.detection,
        network: dash.network ?? { error: 'connection statistics unavailable', total: 0 },
        blocklist: blocklist.stats(),
        provider,
        series: dash.series,
        interfaces: dash.interfaces,
        listeners: dash.listeners.slice(0, 50),
        recentEvents: events,
        topFindings: findings,
        ruleFindings: analysis.slice(0, 10),
        counters: {
            allowed: dash.monitor.counters.allowed,
            denied: dash.monitor.counters.denied,
            blocklisted: dash.monitor.counters.blocklisted,
            suspicious: dash.detection.total,
            openFindings: dash.detection.open,
        },
        generatedAt: new Date().toISOString(),
    };
}, { permission: 'traffic:read' });

/* ================================================================== *
 * Rules
 * ================================================================== */

router.get('/api/rules', async (ctx) => {
    const q = ctx.query;
    return manager.listRules({
        text: q.str('q', ''),
        direction: q.enum('direction', DIRECTIONS),
        action: q.enum('action', ACTIONS),
        protocol: q.enum('protocol', PROTOCOLS),
        enabled: q.bool('enabled', null),
        applied: q.bool('applied', null),
        iface: q.str('iface', '') || null,
        tag: q.str('tag', '') || null,
        sort: q.str('sort', 'priority'),
        order: q.enum('order', ['asc', 'desc'], 'asc'),
        limit: q.int('limit', 200, { min: 1, max: 1000 }),
        offset: q.int('offset', 0, { min: 0 }),
    });
}, { permission: 'rules:read' });

router.get('/api/rules/stats', async () => manager.stats(), { permission: 'rules:read' });

router.get('/api/rules/analysis', async () => ({
    findings: manager.analyse(),
    generatedAt: new Date().toISOString(),
}), { permission: 'rules:read' });

router.post('/api/rules/preview', async (ctx) => manager.preview(ctx.body), { permission: 'rules:read' });

router.post('/api/rules/test', async (ctx) => manager.testPacket(ctx.body), { permission: 'rules:read' });

router.get('/api/rules/schema', async () => ({
    protocols: PROTOCOLS,
    directions: DIRECTIONS,
    actions: ACTIONS,
    fields: {
        name: { type: 'string', required: true, maxLength: 96, help: 'Unique, human-readable rule name.' },
        description: { type: 'string', maxLength: 400 },
        direction: { type: 'enum', values: DIRECTIONS, default: 'inbound' },
        action: { type: 'enum', values: ACTIONS, default: 'deny' },
        protocol: { type: 'enum', values: PROTOCOLS, default: 'any' },
        srcAddress: { type: 'address-spec', default: 'any', help: 'any, an IP, a CIDR, an a.b.c.d-e.f.g.h range, or a comma-separated list.' },
        dstAddress: { type: 'address-spec', default: 'any' },
        srcPort: { type: 'port-spec', default: 'any', help: 'any, 443, 8000-8100, or 80,443,8080-8090. TCP/UDP only.' },
        dstPort: { type: 'port-spec', default: 'any' },
        iface: { type: 'string', default: 'any', help: 'Interface alias/name, or "any".' },
        profiles: { type: 'list', values: ['Domain', 'Private', 'Public', 'Any'], default: ['Any'], help: 'Windows firewall profiles.' },
        program: { type: 'path', help: 'Absolute executable path for an application-scoped rule (Windows only).' },
        priority: { type: 'integer', min: 1, max: 65535, default: 100, help: 'Lower is evaluated first.' },
        enabled: { type: 'boolean', default: true },
        tags: { type: 'list', maxItems: 16 },
    },
}), { permission: 'rules:read' });

router.get('/api/rules/:id', async (ctx) => manager.readRule(ctx.params.id), { permission: 'rules:read' });

router.post('/api/rules', async (ctx) => {
    const { reason, confirm, ...input } = ctx.body ?? {};
    return manager.createRuleAndApply(input, opCtx(ctx));
}, { permission: 'rules:write', csrf: true });

router.patch('/api/rules/:id', async (ctx) => {
    const { reason, confirm, ...patch } = ctx.body ?? {};
    return manager.updateRule(ctx.params.id, patch, opCtx(ctx));
}, { permission: 'rules:write', csrf: true });

router.delete('/api/rules/:id', async (ctx) => {
    requireConfirmation(ctx, 'delete a firewall rule');
    return manager.deleteRule(ctx.params.id, opCtx(ctx));
}, { permission: 'rules:write', csrf: true });

router.post('/api/rules/:id/enable', async (ctx) => manager.setEnabled(ctx.params.id, true, opCtx(ctx)), { permission: 'rules:write', csrf: true });

router.post('/api/rules/:id/disable', async (ctx) => manager.setEnabled(ctx.params.id, false, opCtx(ctx)), { permission: 'rules:write', csrf: true });

router.post('/api/rules/reorder', async (ctx) => {
    const order = ctx.body?.order;
    if (!Array.isArray(order)) throw new ValidationError('Body must contain an "order" array of rule ids');
    return manager.reorder(order, opCtx(ctx));
}, { permission: 'rules:write', csrf: true });

router.post('/api/rules/apply', async (ctx) => {
    requireConfirmation(ctx, 'write every managed rule into the operating system firewall');
    return manager.applyAll(opCtx(ctx));
}, { permission: 'rules:apply', csrf: true });

router.post('/api/rules/sync', async (ctx) => {
    const repair = ctx.body?.repair === true;
    if (repair) requireConfirmation(ctx, 'rewrite operating system firewall rules to match SentryFW');
    return manager.sync({ repair, ...opCtx(ctx) });
}, { permission: 'rules:apply', csrf: true });

router.get('/api/rules/os/list', async (ctx) => manager.osRules({
    scope: ctx.query.enum('scope', ['managed', 'all'], 'managed'),
    limit: ctx.query.int('limit', 500, { min: 1, max: 5000 }),
}), { permission: 'rules:read' });

/* ================================================================== *
 * Traffic
 * ================================================================== */

router.get('/api/traffic/connections', async (ctx) => {
    const q = ctx.query;
    if (q.bool('live', false)) {
        const live = await listConnections({ limit: q.int('limit', 500, { min: 1, max: 5000 }) });
        return { source: live.source, live: true, total: live.total, truncated: live.truncated, connections: live.connections };
    }
    return {
        live: false,
        ...monitor.query({
            text: q.str('q', ''),
            direction: q.enum('direction', DIRECTIONS),
            protocol: q.enum('protocol', ['tcp', 'udp']),
            state: q.str('state', '') || null,
            decision: q.enum('decision', ['allow', 'deny']),
            scope: q.enum('scope', ['public', 'private', 'loopback', 'wildcard', 'unknown']),
            process: q.str('process', '') || null,
            hideLoopback: q.bool('hideLoopback', false),
            sort: q.str('sort', 'lastSeenAt'),
            order: q.enum('order', ['asc', 'desc'], 'desc'),
            limit: q.int('limit', 200, { min: 1, max: 2000 }),
            offset: q.int('offset', 0, { min: 0 }),
        }),
    };
}, { permission: 'traffic:read' });

router.get('/api/traffic/stats', async () => connectionStats(), { permission: 'traffic:read' });

router.get('/api/traffic/series', async (ctx) => ({
    series: monitor.series(ctx.query.int('points', 60, { min: 1, max: 500 })),
}), { permission: 'traffic:read' });

router.get('/api/traffic/listeners', async (ctx) => listListeners({
    limit: ctx.query.int('limit', 1000, { min: 1, max: 5000 }),
}), { permission: 'traffic:read' });

router.get('/api/traffic/interfaces', async () => listInterfaces(), { permission: 'traffic:read' });

router.get('/api/traffic/monitor', async () => monitor.status(), { permission: 'traffic:read' });

router.post('/api/traffic/sample', async () => {
    invalidateNetworkCache();
    const snapshot = await monitor.sample();
    return { sampled: true, sample: snapshot?.sample ?? null, status: monitor.status() };
}, { permission: 'traffic:read', csrf: true });

router.post('/api/traffic/monitor/start', async () => {
    monitor.start();
    return monitor.status();
}, { permission: 'settings:write', csrf: true });

router.post('/api/traffic/monitor/stop', async () => {
    monitor.stop();
    return monitor.status();
}, { permission: 'settings:write', csrf: true });

/* ================================================================== *
 * Detection
 * ================================================================== */

router.get('/api/detection/findings', async (ctx) => {
    const q = ctx.query;
    return detection.query({
        severity: q.enum('severity', ['low', 'medium', 'high', 'critical']),
        type: q.str('type', '') || null,
        acknowledged: q.bool('acknowledged', null),
        text: q.str('q', ''),
        limit: q.int('limit', 100, { min: 1, max: 500 }),
        offset: q.int('offset', 0, { min: 0 }),
    });
}, { permission: 'logs:read' });

router.get('/api/detection/summary', async () => detection.summary(), { permission: 'logs:read' });

router.post('/api/detection/findings/:id/acknowledge', async (ctx) => {
    const finding = detection.acknowledge(ctx.params.id, ctx.actor);
    if (!finding) throw new NotFoundError('Finding', ctx.params.id);
    return finding;
}, { permission: 'logs:read', csrf: true });

/* ================================================================== *
 * Blocklist
 * ================================================================== */

router.get('/api/blocklist', async (ctx) => {
    const q = ctx.query;
    return blocklist.listEntries({
        text: q.str('q', ''),
        source: q.enum('source', ['manual', 'automatic', 'feed']),
        active: q.bool('active', null),
        limit: q.int('limit', 500, { min: 1, max: 2000 }),
        offset: q.int('offset', 0, { min: 0 }),
    });
}, { permission: 'blocklist:read' });

router.get('/api/blocklist/stats', async () => blocklist.stats(), { permission: 'blocklist:read' });

router.post('/api/blocklist', async (ctx) => {
    const { target, reason, ttlHours, direction } = ctx.body ?? {};
    return blocklist.block({ target, reason, ttlHours, direction: direction ?? 'both', source: 'manual' }, opCtx(ctx));
}, { permission: 'blocklist:write', csrf: true });

router.delete('/api/blocklist/:target', async (ctx) => blocklist.unblock(ctx.params.target, opCtx(ctx)), { permission: 'blocklist:write', csrf: true });

router.post('/api/blocklist/import', async (ctx) => {
    const { entries, feed, reason, ttlHours, createRules } = ctx.body ?? {};
    return blocklist.importFeed({ entries, feed, reason, ttlHours, createRules: createRules === true }, opCtx(ctx));
}, { permission: 'blocklist:write', csrf: true });

router.get('/api/blocklist/check/:ip', async (ctx) => {
    const entry = blocklist.isBlocked(ctx.params.ip);
    return { ip: ctx.params.ip, blocked: !!entry, entry };
}, { permission: 'blocklist:read' });

/* ================================================================== *
 * Logs
 * ================================================================== */

router.get('/api/logs', async (ctx) => {
    const q = ctx.query;
    return queryEvents({
        text: q.str('q', ''),
        levels: q.list('level').filter((l) => LEVELS.includes(l)),
        categories: q.list('category').filter((c) => CATEGORIES.includes(c)),
        outcome: q.enum('outcome', ['allowed', 'denied', 'suspicious']),
        from: validateISODate(q.str('from', '') || null, 'from'),
        to: validateISODate(q.str('to', '') || null, 'to'),
        sort: q.str('sort', 'ts'),
        order: q.enum('order', ['asc', 'desc'], 'desc'),
        limit: q.int('limit', 100, { min: 1, max: 1000 }),
        offset: q.int('offset', 0, { min: 0 }),
    });
}, { permission: 'logs:read' });

router.get('/api/logs/stats', async () => ({
    ...logStats(),
    levels: LEVELS,
    categories: CATEGORIES,
}), { permission: 'logs:read' });

router.get('/api/logs/export', async (ctx) => {
    const q = ctx.query;
    const format = q.enum('format', ['json', 'csv', 'ndjson'], 'json');
    const filter = {
        text: q.str('q', ''),
        levels: q.list('level').filter((l) => LEVELS.includes(l)),
        categories: q.list('category').filter((c) => CATEGORIES.includes(c)),
        outcome: q.enum('outcome', ['allowed', 'denied', 'suspicious']),
        from: validateISODate(q.str('from', '') || null, 'from'),
        to: validateISODate(q.str('to', '') || null, 'to'),
    };
    const body = exportEvents(filter, format);
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    return {
        __raw: {
            body,
            contentType: format === 'csv' ? 'text/csv; charset=utf-8' : (format === 'ndjson' ? 'application/x-ndjson' : 'application/json'),
            headers: { 'Content-Disposition': `attachment; filename="sentryfw-events-${stamp}.${format === 'ndjson' ? 'ndjson' : format}"` },
        },
    };
}, { permission: 'logs:export' });

/* ================================================================== *
 * Audit
 * ================================================================== */

router.get('/api/audit', async (ctx) => {
    const q = ctx.query;
    return queryAudit({
        text: q.str('q', ''),
        actor: q.str('actor', '') || null,
        action: q.str('action', '') || null,
        from: validateISODate(q.str('from', '') || null, 'from'),
        to: validateISODate(q.str('to', '') || null, 'to'),
        limit: q.int('limit', 100, { min: 1, max: 1000 }),
        offset: q.int('offset', 0, { min: 0 }),
    });
}, { permission: 'audit:read' });

router.get('/api/audit/stats', async () => auditStats(), { permission: 'audit:read' });

router.get('/api/audit/verify', async () => verifyChain(), { permission: 'audit:read' });

router.get('/api/audit/export', async (ctx) => {
    const format = ctx.query.enum('format', ['json', 'csv', 'ndjson'], 'json');
    const body = exportAudit(format, {
        text: ctx.query.str('q', ''),
        actor: ctx.query.str('actor', '') || null,
        action: ctx.query.str('action', '') || null,
    });
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    return {
        __raw: {
            body,
            contentType: format === 'csv' ? 'text/csv; charset=utf-8' : (format === 'ndjson' ? 'application/x-ndjson' : 'application/json'),
            headers: { 'Content-Disposition': `attachment; filename="sentryfw-audit-${stamp}.${format === 'ndjson' ? 'ndjson' : format}"` },
        },
    };
}, { permission: 'audit:read' });

/* ================================================================== *
 * Settings & providers
 * ================================================================== */

router.get('/api/settings', async () => ({
    config: publicConfig(),
    editable: MUTABLE_SETTINGS,
}), { permission: 'settings:read' });

router.patch('/api/settings', async (ctx) => {
    const { reason, confirm, ...patch } = ctx.body ?? {};
    const result = await updateSettings(patch);
    const { audit } = await import('../core/audit.js');
    await audit({
        actor: ctx.actor, action: 'config.update', target: Object.keys(result.applied).join(', '),
        after: result.applied, reason: reason ?? null, source: ctx.source,
    });
    // Monitoring interval / enablement can change without a restart.
    if ('monitoring.enabled' in result.applied || 'monitoring.intervalSeconds' in result.applied) {
        if (getConfig().monitoring.enabled === false) monitor.stop();
        else if (!monitor.status().running) monitor.start();
    }
    return { applied: result.applied, restartRequired: result.restartRequired, config: publicConfig() };
}, { permission: 'settings:write', csrf: true });

router.get('/api/providers', async () => ({ providers: await describeProviders() }), { permission: 'settings:read' });

router.get('/api/providers/status', async () => manager.providerStatus(), { permission: 'settings:read' });

/* ================================================================== *
 * Backup / restore
 * ================================================================== */

router.get('/api/backups', async () => ({ backups: await backup.listBackups() }), { permission: 'backup:read' });

router.post('/api/backups', async (ctx) => backup.createBackup({
    note: ctx.body?.note ?? '',
    includeBlocklist: ctx.body?.includeBlocklist !== false,
    includeSettings: ctx.body?.includeSettings !== false,
}, opCtx(ctx)), { permission: 'backup:write', csrf: true });

router.get('/api/backups/export', async (ctx) => {
    const doc = backup.buildBackup({
        includeBlocklist: ctx.query.bool('blocklist', true),
        includeSettings: ctx.query.bool('settings', true),
        note: 'Downloaded from the SentryFW console',
    });
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    return {
        __raw: {
            body: JSON.stringify(doc, null, 2),
            contentType: 'application/json',
            headers: { 'Content-Disposition': `attachment; filename="sentryfw-backup-${stamp}.json"` },
        },
    };
}, { permission: 'backup:read' });

router.get('/api/backups/:filename', async (ctx) => backup.readBackupFile(ctx.params.filename), { permission: 'backup:read' });

router.delete('/api/backups/:filename', async (ctx) => {
    requireConfirmation(ctx, 'delete a backup file');
    return backup.deleteBackup(ctx.params.filename, opCtx(ctx));
}, { permission: 'backup:write', csrf: true });

router.post('/api/backups/validate', async (ctx) => backup.validateBackup(ctx.body?.backup ?? ctx.body), { permission: 'backup:read', csrf: true });

router.post('/api/backups/restore', async (ctx) => {
    requireConfirmation(ctx, 'replace the current rule set from a backup');
    const doc = ctx.body?.backup
        ?? (ctx.body?.filename ? await backup.readBackupFile(ctx.body.filename) : null);
    if (!doc) throw new ValidationError('Provide either "backup" (a document) or "filename"');
    return backup.restoreBackup(doc, {
        rules: ctx.body?.rules !== false,
        blocklist: ctx.body?.blocklist !== false,
        settings: ctx.body?.settings === true,
    }, opCtx(ctx));
}, { permission: 'backup:write', csrf: true });

router.get('/api/rules/export/json', async () => {
    const doc = manager.exportRules();
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    return {
        __raw: {
            body: JSON.stringify(doc, null, 2),
            contentType: 'application/json',
            headers: { 'Content-Disposition': `attachment; filename="sentryfw-rules-${stamp}.json"` },
        },
    };
}, { permission: 'backup:read' });

router.post('/api/rules/import', async (ctx) => {
    requireConfirmation(ctx, 'replace the entire rule set');
    return manager.importRules(ctx.body?.rules ? ctx.body : { rules: ctx.body }, opCtx(ctx));
}, { permission: 'backup:write', csrf: true });

/* ================================================================== *
 * Users & sessions
 * ================================================================== */

router.get('/api/users', async () => ({ users: listUsers(), roles: ROLES }), { permission: 'users:read' });

router.post('/api/users', async (ctx) => {
    const { username, password, role } = ctx.body ?? {};
    return createUser({ username, password, role }, ctx.actor, ctx.source);
}, { permission: 'users:write', csrf: true });

router.patch('/api/users/:username', async (ctx) => {
    const { reason, confirm, ...patch } = ctx.body ?? {};
    return updateUser(ctx.params.username, patch, ctx.actor, ctx.source);
}, { permission: 'users:write', csrf: true });

router.delete('/api/users/:username', async (ctx) => {
    requireConfirmation(ctx, 'delete a user account');
    if (ctx.params.username === ctx.actor) throw new ConflictError('You cannot delete the account you are signed in with');
    return deleteUser(ctx.params.username, ctx.actor, ctx.source);
}, { permission: 'users:write', csrf: true });

router.get('/api/sessions', async () => ({ sessions: listSessions() }), { permission: 'users:read' });

router.post('/api/account/password', async (ctx) => {
    const { currentPassword, newPassword } = ctx.body ?? {};
    return changeOwnPassword(ctx.actor, currentPassword, newPassword, ctx.source);
}, { permission: 'rules:read', csrf: true });

router.get('/api/account', async (ctx) => {
    const user = findUser(ctx.actor);
    return {
        user: publicUser(user) ?? {
            username: ctx.actor,
            role: ctx.principal?.role ?? 'anonymous',
            // Lab mode (requireAuth=false) has no stored account; report the role's real permissions.
            permissions: permissionsForRole(ctx.principal?.role),
        },
        session: ctx.session
            ? { createdAt: new Date(ctx.session.createdAt).toISOString(), expiresAt: new Date(ctx.session.expiresAt).toISOString(), source: ctx.session.source }
            : null,
    };
}, { permission: 'rules:read' });

/* ================================================================== *
 * Scenario helpers — one-click hardening tasks
 * ================================================================== */

const SCENARIOS = Object.freeze({
    'block-ip': {
        label: 'Block an IP address',
        description: 'Creates inbound and outbound deny rules for a single address or network and records it on the blocklist.',
        fields: [{ name: 'target', label: 'IP or CIDR', required: true }, { name: 'reason', label: 'Reason' }],
    },
    'allow-rdp-from': {
        label: 'Allow RDP from a trusted network only',
        description: 'Allows TCP 3389 from the network you specify and denies it from everywhere else.',
        fields: [{ name: 'source', label: 'Trusted CIDR', required: true, placeholder: '10.0.0.0/24' }],
    },
    'allow-ssh-from': {
        label: 'Allow SSH from a trusted network only',
        description: 'Allows TCP 22 from the network you specify and denies it from everywhere else.',
        fields: [{ name: 'source', label: 'Trusted CIDR', required: true, placeholder: '10.0.0.0/24' }],
    },
    'allow-web': {
        label: 'Publish HTTP/HTTPS',
        description: 'Allows inbound TCP 80 and 443 from any source.',
        fields: [],
    },
    'block-port': {
        label: 'Block a port',
        description: 'Denies inbound traffic to a single port or port range.',
        fields: [{ name: 'port', label: 'Port or range', required: true, placeholder: '445' }, { name: 'protocol', label: 'Protocol', placeholder: 'tcp' }],
    },
    'restrict-outbound': {
        label: 'Restrict outbound to essential services',
        description: 'Allows outbound DNS, HTTP, HTTPS and NTP, then denies all other outbound traffic.',
        fields: [],
    },
});

router.get('/api/scenarios', async () => ({
    scenarios: Object.entries(SCENARIOS).map(([id, s]) => ({ id, ...s })),
}), { permission: 'rules:read' });

router.post('/api/scenarios/:id', async (ctx) => {
    const id = ctx.params.id;
    const scenario = SCENARIOS[id];
    if (!scenario) throw new NotFoundError('Scenario', id);
    const body = ctx.body ?? {};
    const created = [];
    const c = opCtx(ctx);

    const add = async (input) => {
        try {
            const res = await manager.createRuleAndApply(input, c);
            created.push({ name: input.name, ruleId: res.rule.id, os: res.os });
        } catch (err) {
            created.push({ name: input.name, error: err.message, code: err.code ?? null });
        }
    };

    switch (id) {
        case 'block-ip': {
            const res = await blocklist.block({
                target: body.target, reason: body.reason ?? 'Blocked via scenario', direction: 'both', source: 'manual',
            }, c);
            return { scenario: id, blocklist: res.entry, rules: res.rules };
        }
        case 'allow-rdp-from':
        case 'allow-ssh-from': {
            const isRdp = id === 'allow-rdp-from';
            const port = isRdp ? 3389 : 22;
            const label = isRdp ? 'RDP' : 'SSH';
            const source = validateString(body.source, 'source', { max: 64, pattern: /^[0-9A-Fa-f:./,\-]+$/ });
            await add({
                name: `Allow ${label} from ${source}`.slice(0, 90),
                description: `Permit ${label} (TCP ${port}) from the trusted network ${source}.`,
                direction: 'inbound', action: 'allow', protocol: 'tcp',
                srcAddress: source, dstPort: String(port), priority: 10, tags: ['scenario', label.toLowerCase()],
            });
            await add({
                name: `Deny ${label} from all other sources`.slice(0, 90),
                description: `Catch-all deny for ${label} (TCP ${port}). Must remain at a lower priority than the allow rule.`,
                direction: 'inbound', action: 'deny', protocol: 'tcp',
                dstPort: String(port), priority: 200, tags: ['scenario', label.toLowerCase()],
            });
            break;
        }
        case 'allow-web': {
            await add({
                name: 'Allow HTTP and HTTPS inbound',
                description: 'Publish web services to any source.',
                direction: 'inbound', action: 'allow', protocol: 'tcp',
                dstPort: '80,443', priority: 20, tags: ['scenario', 'web'],
            });
            break;
        }
        case 'block-port': {
            const port = validateString(String(body.port ?? ''), 'port', { max: 32, pattern: /^[0-9,\-]+$/ });
            const protocol = ['tcp', 'udp'].includes(String(body.protocol ?? 'tcp').toLowerCase())
                ? String(body.protocol ?? 'tcp').toLowerCase() : 'tcp';
            await add({
                name: `Block ${protocol.toUpperCase()} ${port} inbound`.slice(0, 90),
                description: `Deny inbound ${protocol.toUpperCase()} traffic to port(s) ${port}.`,
                direction: 'inbound', action: 'deny', protocol,
                dstPort: port, priority: 15, tags: ['scenario', 'block-port'],
            });
            break;
        }
        case 'restrict-outbound': {
            await add({
                name: 'Allow outbound DNS',
                direction: 'outbound', action: 'allow', protocol: 'udp', dstPort: '53', priority: 10, tags: ['scenario', 'egress'],
                description: 'Name resolution must remain available before restricting egress.',
            });
            await add({
                name: 'Allow outbound web',
                direction: 'outbound', action: 'allow', protocol: 'tcp', dstPort: '80,443', priority: 20, tags: ['scenario', 'egress'],
                description: 'HTTP and HTTPS egress.',
            });
            await add({
                name: 'Allow outbound NTP',
                direction: 'outbound', action: 'allow', protocol: 'udp', dstPort: '123', priority: 30, tags: ['scenario', 'egress'],
                description: 'Time synchronisation.',
            });
            await add({
                name: 'Deny all other outbound',
                direction: 'outbound', action: 'deny', protocol: 'any', priority: 500, tags: ['scenario', 'egress'],
                description: 'Default-deny egress. Review the allow rules above before enabling this in production.',
                enabled: body.enableDenyAll === true,
            });
            break;
        }
        default:
            throw new NotFoundError('Scenario', id);
    }

    return { scenario: id, label: scenario.label, created };
}, { permission: 'rules:write', csrf: true });
