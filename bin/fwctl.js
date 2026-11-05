#!/usr/bin/env node
/**
 * fwctl — SentryFW command-line interface.
 *
 * The CLI drives the same firewall manager, blocklist, audit trail and backup
 * code as the REST API, in-process. That keeps GUI and CLI behaviour identical,
 * but it also means two processes must never mutate the same data directory at
 * once: the server keeps state in memory and would overwrite a CLI change on its
 * next write. `fwctl serve` therefore holds a lock file, and mutating commands
 * refuse to run while a live server owns the data directory (override with
 * --force only if you know the server is gone).
 *
 * Exit codes: 0 success · 1 operation failed · 2 usage error.
 */

import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

import { parseArgs, formatFlags } from '../src/cli/args.js';
import {
    c, out, heading, ok, warn, fail, note, table, kv,
    actionBadge, enabledBadge, appliedBadge, severityBadge, levelBadge,
    shortTime, relativeTime, bytes, maybeJson,
} from '../src/cli/format.js';
import { AppError, ValidationError, NotFoundError } from '../src/core/errors.js';
import { PATHS, writeJsonAtomic, readJson } from '../src/core/paths.js';
import { describeRule } from '../src/firewall/rule-model.js';

const CLI_ACTOR = `cli:${process.env.USERNAME || process.env.USER || 'local'}`;
const CTX = Object.freeze({ actor: CLI_ACTOR, source: 'cli' });

/* ------------------------------------------------------------------ *
 * Flag specs
 * ------------------------------------------------------------------ */

const GLOBAL_FLAGS = {
    json: { type: 'boolean', help: 'Print machine-readable JSON' },
    compact: { type: 'boolean', help: 'With --json, print on one line' },
    verbose: { type: 'boolean', alias: 'v', help: 'Echo event-log lines to the console' },
    force: { type: 'boolean', help: 'Run a mutating command even if a server appears to own the data directory' },
    help: { type: 'boolean', alias: 'h', help: 'Show help for a command' },
};

const RULE_FIELDS = {
    name: { type: 'string', alias: 'n', help: 'Unique rule name' },
    description: { type: 'string', help: 'Free-text description' },
    direction: { type: 'string', alias: 'd', choices: ['inbound', 'outbound'], help: 'inbound | outbound' },
    action: { type: 'string', alias: 'a', choices: ['allow', 'deny'], help: 'allow | deny' },
    protocol: { type: 'string', alias: 'p', choices: ['tcp', 'udp', 'icmp', 'icmpv6', 'any'], help: 'tcp | udp | icmp | icmpv6 | any' },
    src: { type: 'string', help: 'Source address spec (any, IP, CIDR, range, list)' },
    dst: { type: 'string', help: 'Destination address spec' },
    sport: { type: 'string', help: 'Source port spec (any, 443, 8000-8100, 80,443)' },
    dport: { type: 'string', help: 'Destination port spec' },
    iface: { type: 'string', help: 'Interface name, or any' },
    profiles: { type: 'list', help: 'Windows profiles: Domain,Private,Public,Any' },
    program: { type: 'string', help: 'Absolute executable path (Windows app-scoped rule)' },
    priority: { type: 'number', help: '1-65535, lower is evaluated first' },
    tags: { type: 'list', help: 'Comma-separated tags' },
    enabled: { type: 'boolean', help: 'Enable the rule (use --no-enabled to create it disabled)' },
};

const RULE_FLAG_TO_FIELD = {
    name: 'name', description: 'description', direction: 'direction', action: 'action',
    protocol: 'protocol', src: 'srcAddress', dst: 'dstAddress', sport: 'srcPort', dport: 'dstPort',
    iface: 'iface', profiles: 'profiles', program: 'program', priority: 'priority', tags: 'tags',
};

/* ------------------------------------------------------------------ *
 * Command table
 * ------------------------------------------------------------------ */

/**
 * @typedef {object} Command
 * @property {string} summary
 * @property {string} [usage]
 * @property {object} [flags]
 * @property {boolean} [mutates]   refuses to run while a server owns the data dir
 * @property {object} [boot]       bootstrap options
 * @property {Function} run        async ({flags, positional}) => exit code | undefined
 */

/** @type {Record<string, Command>} */
const COMMANDS = {
    serve: {
        summary: 'Start the web console and REST API',
        usage: 'fwctl serve [--host 127.0.0.1] [--port 8787] [--no-monitor]',
        flags: {
            host: { type: 'string', help: 'Bind address (default from config)' },
            port: { type: 'number', help: 'TCP port (default from config)' },
            monitor: { type: 'boolean', default: true, help: 'Start the traffic monitor' },
        },
        boot: false, // bootstraps itself with auth + monitor
        run: cmdServe,
    },
    status: {
        summary: 'Show provider, rule, blocklist and server status',
        run: cmdStatus,
    },

    'rules list': {
        summary: 'List rules',
        usage: 'fwctl rules list [-q text] [--direction inbound] [--action deny] [--disabled]',
        flags: {
            q: { type: 'string', help: 'Free-text filter' },
            direction: { type: 'string', choices: ['inbound', 'outbound'], help: 'Filter by direction' },
            action: { type: 'string', choices: ['allow', 'deny'], help: 'Filter by action' },
            protocol: { type: 'string', choices: ['tcp', 'udp', 'icmp', 'icmpv6', 'any'], help: 'Filter by protocol' },
            tag: { type: 'string', help: 'Filter by tag' },
            disabled: { type: 'boolean', help: 'Only disabled rules' },
            limit: { type: 'number', default: 200, help: 'Maximum rows' },
        },
        run: cmdRulesList,
    },
    'rules show': { summary: 'Show one rule in full', usage: 'fwctl rules show <id|name>', run: cmdRulesShow },
    'rules add': {
        summary: 'Create a rule',
        usage: 'fwctl rules add --name "Allow HTTPS" -d inbound -a allow -p tcp --dport 443',
        flags: RULE_FIELDS,
        mutates: true,
        run: cmdRulesAdd,
    },
    'rules update': {
        summary: 'Change fields on a rule',
        usage: 'fwctl rules update <id|name> --dport 8443 --priority 20',
        flags: RULE_FIELDS,
        mutates: true,
        run: cmdRulesUpdate,
    },
    'rules delete': {
        summary: 'Delete a rule',
        usage: 'fwctl rules delete <id|name> --yes',
        flags: { yes: { type: 'boolean', alias: 'y', help: 'Confirm the deletion' } },
        mutates: true,
        run: cmdRulesDelete,
    },
    'rules enable': { summary: 'Enable a rule', usage: 'fwctl rules enable <id|name>', mutates: true, run: (a) => cmdRulesToggle(a, true) },
    'rules disable': { summary: 'Disable a rule', usage: 'fwctl rules disable <id|name>', mutates: true, run: (a) => cmdRulesToggle(a, false) },
    'rules analyse': { summary: 'Find shadowed, duplicate and risky rules', run: cmdRulesAnalyse },
    'rules preview': { summary: 'Show the native OS command for a rule', usage: 'fwctl rules preview <id|name>', run: cmdRulesPreview },
    'rules apply': {
        summary: 'Write every rule into the OS firewall',
        flags: { yes: { type: 'boolean', alias: 'y', help: 'Confirm' } },
        mutates: true,
        run: cmdRulesApply,
    },
    'rules sync': {
        summary: 'Compare SentryFW rules with the OS firewall',
        flags: {
            repair: { type: 'boolean', help: 'Re-apply drifted rules and remove orphans' },
            yes: { type: 'boolean', alias: 'y', help: 'Confirm --repair' },
        },
        run: cmdRulesSync,
    },
    'rules export': {
        summary: 'Export the rule set as JSON',
        usage: 'fwctl rules export [--out rules.json]',
        flags: { out: { type: 'string', alias: 'o', help: 'Write to a file instead of stdout' } },
        run: cmdRulesExport,
    },
    'rules import': {
        summary: 'Replace the rule set from a JSON export',
        usage: 'fwctl rules import <file> --yes',
        flags: { yes: { type: 'boolean', alias: 'y', help: 'Confirm replacing every rule' } },
        mutates: true,
        run: cmdRulesImport,
    },

    test: {
        summary: 'Ask the policy what happens to a packet',
        usage: 'fwctl test -d inbound -p tcp --src 203.0.113.9 --dport 3389',
        flags: {
            direction: { type: 'string', alias: 'd', choices: ['inbound', 'outbound'], default: 'inbound', help: 'inbound | outbound' },
            protocol: { type: 'string', alias: 'p', choices: ['tcp', 'udp', 'icmp', 'icmpv6', 'any'], default: 'tcp', help: 'Packet protocol' },
            src: { type: 'string', help: 'Source IP' },
            dst: { type: 'string', help: 'Destination IP' },
            sport: { type: 'string', help: 'Source port' },
            dport: { type: 'string', help: 'Destination port' },
            iface: { type: 'string', help: 'Interface' },
        },
        run: cmdTest,
    },

    block: {
        summary: 'Block an IP address or CIDR',
        usage: 'fwctl block 203.0.113.9 --reason "SSH brute force" --ttl 24',
        flags: {
            reason: { type: 'string', alias: 'r', help: 'Why it is blocked' },
            ttl: { type: 'number', help: 'Hours until the block expires (0 = permanent)' },
            direction: { type: 'string', choices: ['inbound', 'outbound', 'both'], default: 'both', help: 'Which traffic to deny' },
        },
        mutates: true,
        run: cmdBlock,
    },
    unblock: { summary: 'Remove a blocklist entry', usage: 'fwctl unblock <ip|cidr>', mutates: true, run: cmdUnblock },
    blocklist: {
        summary: 'List blocklist entries',
        flags: { q: { type: 'string', help: 'Free-text filter' } },
        run: cmdBlocklist,
    },

    logs: {
        summary: 'Query the event log',
        usage: 'fwctl logs [--level warn,error] [--category auth] [-q text] [--follow]',
        flags: {
            level: { type: 'list', help: 'Levels: debug,info,warn,error,critical' },
            category: { type: 'list', help: 'Categories: system,auth,rule,firewall,traffic,detection,blocklist,config,backup,error' },
            q: { type: 'string', help: 'Free-text filter' },
            limit: { type: 'number', default: 50, help: 'Maximum rows' },
            follow: { type: 'boolean', alias: 'f', help: 'Keep printing new events as they are written' },
        },
        boot: { loadHistory: true },
        run: cmdLogs,
    },
    audit: {
        summary: 'Show the audit trail',
        flags: {
            q: { type: 'string', help: 'Free-text filter' },
            actor: { type: 'string', help: 'Only this actor' },
            limit: { type: 'number', default: 50, help: 'Maximum rows' },
        },
        run: cmdAudit,
    },
    'audit verify': { summary: 'Verify the audit hash chain', run: cmdAuditVerify },

    'backup create': {
        summary: 'Write a backup to data/backups',
        flags: { note: { type: 'string', help: 'Note stored in the backup' } },
        run: cmdBackupCreate,
        mutates: true,
    },
    'backup list': { summary: 'List backups', run: cmdBackupList },
    'backup restore': {
        summary: 'Restore rules (and optionally settings) from a backup',
        usage: 'fwctl backup restore <file|backup-name.json> --yes [--settings]',
        flags: {
            yes: { type: 'boolean', alias: 'y', help: 'Confirm replacing the current rule set' },
            settings: { type: 'boolean', help: 'Also restore settings' },
            blocklist: { type: 'boolean', default: true, help: 'Restore blocklist entries (--no-blocklist to skip)' },
        },
        mutates: true,
        run: cmdBackupRestore,
    },

    settings: { summary: 'Show editable settings', run: cmdSettings },
    'settings set': {
        summary: 'Change settings',
        usage: 'fwctl settings set monitoring.intervalSeconds=15 detection.autoBlockOnScan=true',
        mutates: true,
        run: cmdSettingsSet,
    },

    'user list': { summary: 'List console accounts', boot: { withAuth: true }, run: cmdUserList },
    'user add': {
        summary: 'Create an account (a one-time password is generated)',
        usage: 'fwctl user add <username> --role operator',
        flags: { role: { type: 'string', choices: ['admin', 'operator', 'auditor'], default: 'operator', help: 'admin | operator | auditor' } },
        boot: { withAuth: true },
        mutates: true,
        run: cmdUserAdd,
    },
    'user reset': {
        summary: 'Issue a new one-time password (also recovers a lost admin login)',
        usage: 'fwctl user reset <username>',
        boot: { withAuth: true },
        mutates: true,
        run: cmdUserReset,
    },
    'user disable': { summary: 'Disable an account', usage: 'fwctl user disable <username>', boot: { withAuth: true }, mutates: true, run: (a) => cmdUserSetDisabled(a, true) },
    'user enable': { summary: 'Re-enable an account', usage: 'fwctl user enable <username>', boot: { withAuth: true }, mutates: true, run: (a) => cmdUserSetDisabled(a, false) },
    'user delete': {
        summary: 'Delete an account',
        flags: { yes: { type: 'boolean', alias: 'y', help: 'Confirm' } },
        boot: { withAuth: true },
        mutates: true,
        run: cmdUserDelete,
    },

    traffic: {
        summary: 'Live connections from the OS socket table',
        flags: {
            q: { type: 'string', help: 'Free-text filter' },
            limit: { type: 'number', default: 50, help: 'Maximum rows' },
        },
        run: cmdTraffic,
    },
    'traffic listeners': { summary: 'Listening sockets and their exposure', run: cmdListeners },
    'traffic interfaces': { summary: 'Network interfaces', run: cmdInterfaces },

    help: { summary: 'Show this help', boot: false, run: async () => { printHelp(); } },
};

/** Groups with a default subcommand (`fwctl rules` == `fwctl rules list`). */
const GROUP_DEFAULTS = { rules: 'rules list', backup: 'backup list', user: 'user list' };

/* ------------------------------------------------------------------ *
 * Entry point
 * ------------------------------------------------------------------ */

async function main(argv) {
    const [first, second] = argv;
    if (!first || first === '--help' || first === '-h') {
        printHelp();
        return 0;
    }
    if (first === '--version' || first === '-V') {
        const pkg = JSON.parse(fs.readFileSync(path.join(PATHS.root, 'package.json'), 'utf8'));
        out(pkg.version);
        return 0;
    }

    let key;
    let rest;
    if (second && COMMANDS[`${first} ${second}`]) {
        key = `${first} ${second}`;
        rest = argv.slice(2);
    } else if (COMMANDS[first]) {
        key = first;
        rest = argv.slice(1);
    } else if (GROUP_DEFAULTS[first] && (!second || second.startsWith('-'))) {
        key = GROUP_DEFAULTS[first];
        rest = argv.slice(1);
    } else {
        const suggestion = suggest(second ? `${first} ${second}` : first);
        fail(`Unknown command: ${[first, second].filter(Boolean).join(' ')}`);
        if (suggestion) note(`Did you mean: fwctl ${suggestion}`);
        note('Run `fwctl help` for the command list.');
        return 2;
    }

    const cmd = COMMANDS[key];
    const spec = { ...GLOBAL_FLAGS, ...(cmd.flags ?? {}) };
    let parsed;
    try {
        parsed = parseArgs(rest, { flags: spec });
    } catch (e) {
        fail(e.message);
        note(`Usage: ${cmd.usage ?? `fwctl ${key}`}`);
        return 2;
    }

    if (parsed.flags.help) {
        printCommandHelp(key, cmd);
        return 0;
    }

    // Keep command output clean; event-log lines still go to logs/events.log.
    if (key !== 'serve' && !parsed.flags.verbose) process.env.FWCTL_LOG_CONSOLE = 'false';

    if (cmd.mutates && !parsed.flags.force) {
        const owner = await liveServerLock();
        if (owner) {
            fail(`A SentryFW server (pid ${owner.pid}, ${owner.address}) owns this data directory.`);
            note('Make the change in the web console, or stop the server first. The server keeps state in memory');
            note('and would overwrite changes made here. Use --force only if that process is no longer SentryFW.');
            return 1;
        }
    }

    if (cmd.boot !== false) {
        const { bootstrap } = await import('../src/bootstrap.js');
        // Not silent when auth is initialised: on a fresh install that is what
        // prints the one-time admin credential, which must never be swallowed.
        await bootstrap({ silent: !cmd.boot?.withAuth, loadHistory: false, ...(cmd.boot ?? {}) });
    }

    const code = await cmd.run(parsed);
    return typeof code === 'number' ? code : 0;
}

/* ------------------------------------------------------------------ *
 * serve
 * ------------------------------------------------------------------ */

async function cmdServe({ flags }) {
    const owner = await liveServerLock();
    if (owner && !flags.force) {
        fail(`Another SentryFW server (pid ${owner.pid}) is already running at ${owner.address} with this data directory.`);
        return 1;
    }

    const { bootstrap, installProcessHandlers, onShutdown } = await import('../src/bootstrap.js');
    const { ApiServer } = await import('../src/api/server.js');

    installProcessHandlers();
    await bootstrap({ withAuth: true, withMonitor: flags.monitor !== false });

    const server = new ApiServer({ host: flags.host ?? null, port: flags.port ?? null });
    try {
        await server.start();
    } catch (e) {
        if (e.code === 'EADDRINUSE') {
            fail(`Port ${server.port} on ${server.host} is already in use. Pick another with --port.`);
            process.exit(1);
        }
        throw e;
    }

    await writeJsonAtomic(PATHS.serverLock, {
        pid: process.pid,
        address: server.address,
        startedAt: new Date().toISOString(),
    });
    onShutdown(async () => {
        await server.stop();
        await fsp.unlink(PATHS.serverLock).catch(() => {});
    });

    out('');
    out(`  ${c.bold('SentryFW console')}   ${c.cyan(`${server.address}/`)}`);
    out(`  ${c.bold('Knowledge base')}     ${c.cyan(`${server.address}/kb/`)}`);
    out(`  ${c.dim('Press Ctrl+C to stop.')}`);
    out('');

    // Keep the process alive; shutdown is driven by the signal handlers.
    await new Promise(() => {});
}

/** The lock written by `serve`, if its process is still alive. */
async function liveServerLock() {
    const lock = await readJson(PATHS.serverLock, null).catch(() => null);
    if (!lock?.pid || lock.pid === process.pid) return null;
    try {
        process.kill(lock.pid, 0);
        return lock;
    } catch (e) {
        // EPERM means the process exists but belongs to someone else.
        return e.code === 'EPERM' ? lock : null;
    }
}

/* ------------------------------------------------------------------ *
 * status
 * ------------------------------------------------------------------ */

async function cmdStatus({ flags }) {
    const manager = await import('../src/firewall/manager.js');
    const blocklist = await import('../src/monitoring/blocklist.js');
    const { getConfig } = await import('../src/core/config.js');
    const { auditStats } = await import('../src/core/audit.js');

    const [provider, owner] = await Promise.all([manager.providerStatus(), liveServerLock()]);
    const rules = manager.stats();
    const findings = manager.analyse();
    const bl = blocklist.stats();
    const cfg = getConfig();
    const auditInfo = auditStats();

    const payload = { provider, rules, ruleFindings: findings.length, blocklist: bl, server: owner, audit: { entries: auditInfo.entries, chain: auditInfo.chain } };
    if (maybeJson(flags, payload)) return;

    heading('SentryFW status');
    kv([
        ['Provider', `${provider.label} (${provider.id})`],
        ['Apply to OS', cfg.firewall.applyToOS ? c.green('enabled') : c.yellow('disabled — rules are not enforced by the OS')],
        ['Default policy', `inbound ${policyWord(cfg.firewall.defaultPolicy.inbound)}, outbound ${policyWord(cfg.firewall.defaultPolicy.outbound)}`],
        ['Console', owner ? `${c.green('running')} at ${owner.address} (pid ${owner.pid})` : c.dim('not running — start with `fwctl serve`')],
        ['Data directory', PATHS.data],
    ]);

    heading('Rules');
    kv([
        ['Total', `${rules.total} (${rules.enabled} enabled, ${rules.disabled} disabled)`],
        ['Direction', `${rules.inbound} inbound, ${rules.outbound} outbound`],
        ['Action', `${rules.allow} allow, ${rules.deny} deny`],
        ['Applied to OS', `${rules.appliedToOS}${rules.withErrors ? c.red(` · ${rules.withErrors} with errors`) : ''}`],
        ['Analysis', findings.length ? c.yellow(`${findings.length} finding(s) — run \`fwctl rules analyse\``) : c.green('no issues')],
    ]);

    heading('Blocklist & audit');
    kv([
        ['Blocklist', `${bl.active} active, ${bl.expired} expired${bl.enabled ? '' : c.yellow(' (evaluation disabled)')}`],
        ['Audit entries', auditInfo.entries],
        ['Audit chain', auditInfo.chain.valid ? c.green('intact') : c.red(`BROKEN at #${auditInfo.chain.brokenAt}: ${auditInfo.chain.reason}`)],
    ]);
    out('');
}

function policyWord(p) {
    return p === 'allow' ? c.green('allow') : c.red('deny');
}

/* ------------------------------------------------------------------ *
 * rules
 * ------------------------------------------------------------------ */

async function resolveRule(ref) {
    if (!ref) throw new ValidationError('Specify a rule id or name');
    const store = await import('../src/firewall/rule-store.js');
    const rule = store.getRule(ref) ?? store.getRuleByName(ref);
    if (!rule) throw new NotFoundError('Rule', ref);
    return rule;
}

const RULE_COLUMNS = [
    { key: 'priority', label: 'PRI', align: 'right' },
    { key: 'enabled', label: 'ON', format: (v) => enabledBadge(v) },
    { key: 'action', label: 'ACTION', format: (v) => actionBadge(v) },
    { key: 'direction', label: 'DIR', format: (v) => (v === 'inbound' ? 'in ' : 'out') },
    { key: 'protocol', label: 'PROTO' },
    { key: 'srcAddress', label: 'SOURCE', width: 24, format: (v, r) => `${v}${r.srcPort !== 'any' ? `:${r.srcPort}` : ''}` },
    { key: 'dstAddress', label: 'DESTINATION', width: 24, format: (v, r) => `${v}${r.dstPort !== 'any' ? `:${r.dstPort}` : ''}` },
    { key: 'name', label: 'NAME', width: 36 },
    { key: 'osApplied', label: 'OS', format: (_v, r) => appliedBadge(r) },
    { key: 'hitCount', label: 'HITS', align: 'right' },
];

async function cmdRulesList({ flags }) {
    const manager = await import('../src/firewall/manager.js');
    const result = manager.listRules({
        text: flags.q ?? '',
        direction: flags.direction ?? null,
        action: flags.action ?? null,
        protocol: flags.protocol ?? null,
        tag: flags.tag ?? null,
        enabled: flags.disabled ? false : null,
        limit: flags.limit,
    });
    if (maybeJson(flags, result)) return;
    heading(`Rules (${result.total})`);
    table(RULE_COLUMNS, result.rules, { empty: 'No rules match. Create one with `fwctl rules add`.' });
}

async function cmdRulesShow({ flags, positional }) {
    const rule = await resolveRule(positional[0]);
    if (maybeJson(flags, rule)) return;
    heading(rule.name);
    out(`  ${describeRule(rule)}`);
    out('');
    kv([
        ['ID', rule.id],
        ['Description', rule.description],
        ['Enabled', rule.enabled],
        ['Priority', rule.priority],
        ['Direction', rule.direction],
        ['Action', actionBadge(rule.action)],
        ['Protocol', rule.protocol],
        ['Source', `${rule.srcAddress} port ${rule.srcPort}`],
        ['Destination', `${rule.dstAddress} port ${rule.dstPort}`],
        ['Interface', rule.iface],
        ['Profiles', rule.profiles],
        ['Program', rule.program],
        ['Tags', rule.tags],
        ['OS rule name', rule.osRuleName],
        ['OS state', appliedBadge(rule)],
        ['OS error', rule.osLastError],
        ['Hits', `${rule.hitCount}${rule.lastHitAt ? ` (last ${relativeTime(rule.lastHitAt)})` : ''}`],
        ['Created', `${shortTime(rule.createdAt)} by ${rule.createdBy}`],
        ['Updated', `${shortTime(rule.updatedAt)} by ${rule.updatedBy} (rev ${rule.revision})`],
    ]);
    out('');
}

function ruleInputFromFlags(flags) {
    const input = {};
    for (const [flag, field] of Object.entries(RULE_FLAG_TO_FIELD)) {
        if (flags[flag] !== undefined) input[field] = flags[flag];
    }
    if (flags.enabled !== undefined && process.argv.some((a) => a === '--enabled' || a === '--no-enabled' || a.startsWith('--enabled='))) {
        input.enabled = flags.enabled;
    }
    return input;
}

async function cmdRulesAdd({ flags }) {
    const manager = await import('../src/firewall/manager.js');
    const input = ruleInputFromFlags(flags);
    if (!input.name) throw new ValidationError('--name is required');
    const result = await manager.createRuleAndApply(input, CTX);
    if (maybeJson(flags, result)) return;
    ok(`Created ${c.bold(result.rule.name)} ${c.dim(result.rule.id)}`);
    note(describeRule(result.rule));
    reportOs(result.os);
}

async function cmdRulesUpdate({ flags, positional }) {
    const manager = await import('../src/firewall/manager.js');
    const rule = await resolveRule(positional[0]);
    const patch = ruleInputFromFlags(flags);
    if (Object.keys(patch).length === 0) throw new ValidationError('Nothing to change: pass at least one field flag (see --help)');
    const result = await manager.updateRule(rule.id, patch, CTX);
    if (maybeJson(flags, result)) return;
    ok(`Updated ${c.bold(result.rule.name)} (rev ${result.rule.revision})`);
    note(describeRule(result.rule));
    reportOs(result.os);
}

async function cmdRulesDelete({ flags, positional }) {
    const manager = await import('../src/firewall/manager.js');
    const rule = await resolveRule(positional[0]);
    if (!requireYes(flags, `delete rule "${rule.name}"`)) return 1;
    const result = await manager.deleteRule(rule.id, CTX);
    if (maybeJson(flags, result)) return;
    ok(`Deleted ${c.bold(rule.name)}`);
    reportOs(result.os);
}

async function cmdRulesToggle({ flags, positional }, enabled) {
    const manager = await import('../src/firewall/manager.js');
    const rule = await resolveRule(positional[0]);
    const result = await manager.setEnabled(rule.id, enabled, CTX);
    if (maybeJson(flags, result)) return;
    ok(`${enabled ? 'Enabled' : 'Disabled'} ${c.bold(rule.name)}`);
    reportOs(result.os);
}

async function cmdRulesAnalyse({ flags }) {
    const manager = await import('../src/firewall/manager.js');
    const findings = manager.analyse();
    if (maybeJson(flags, { findings })) return;
    heading(`Rule analysis (${findings.length} finding(s))`);
    table([
        { key: 'severity', label: 'SEV', format: (v) => severityBadge(v) },
        { key: 'type', label: 'TYPE' },
        { key: 'ruleName', label: 'RULE', width: 36 },
        { key: 'message', label: 'FINDING', width: 80 },
    ], findings, { empty: 'No shadowed, duplicate or risky rules found.' });
    return findings.some((f) => f.severity === 'critical' || f.severity === 'high') ? 1 : 0;
}

async function cmdRulesPreview({ flags, positional }) {
    const manager = await import('../src/firewall/manager.js');
    const rule = await resolveRule(positional[0]);
    const result = manager.preview(rule.id);
    if (maybeJson(flags, result)) return;
    heading(`Native command for "${rule.name}"`);
    note(result.summary);
    out('');
    const native = result.native ?? {};
    const printLines = (lines) => {
        for (const line of lines ?? []) out(String(line).split('\n').map((l) => `  ${c.cyan(l)}`).join('\n'));
    };
    out(c.bold(`  ${native.primary ?? native.kind ?? 'command'}`));
    printLines(native.lines);
    for (const alt of native.alternatives ?? []) {
        out('');
        out(c.bold(`  ${alt.label}`));
        printLines(alt.lines);
    }
    if (native.guiPath) { out(''); note(`GUI: ${native.guiPath}`); }
    if (native.note) { out(''); note(native.note); }
    out('');
}

async function cmdRulesApply({ flags }) {
    const manager = await import('../src/firewall/manager.js');
    if (!requireYes(flags, 'write every managed rule into the operating system firewall')) return 1;
    const result = await manager.applyAll(CTX);
    if (maybeJson(flags, result)) return result.failed.length ? 1 : 0;
    (result.failed.length ? warn : ok)(`Applied ${result.applied}/${result.total} rule(s) to the OS firewall`);
    for (const f of result.failed) fail(`${f.name}: ${f.error}${f.hint ? `\n    ${c.dim(f.hint)}` : ''}`);
    return result.failed.length ? 1 : 0;
}

async function cmdRulesSync({ flags }) {
    const manager = await import('../src/firewall/manager.js');
    if (flags.repair && !requireYes(flags, 'rewrite operating system firewall rules to match SentryFW')) return 1;
    const result = await manager.sync({ repair: !!flags.repair, ...CTX });
    if (maybeJson(flags, result)) return result.inSync ? 0 : 1;
    if (!result.supported) { warn(result.reason); return 1; }
    if (!result.ok) { fail(result.error); if (result.hint) note(result.hint); return 1; }
    if (result.inSync) {
        ok(`In sync: ${result.storeRuleCount} SentryFW rule(s), ${result.osRuleCount} OS rule(s)`);
        return 0;
    }
    warn(`${result.drift.length} discrepancy/ies between SentryFW and the OS firewall`);
    table([
        { key: 'type', label: 'TYPE' },
        { key: 'name', label: 'RULE', width: 36, format: (v, r) => v ?? r.osName },
        { key: 'detail', label: 'DETAIL', width: 90 },
    ], result.drift);
    if (result.repaired) ok(`Repair actions taken: ${result.repaired.length}`);
    else note('Run `fwctl rules sync --repair --yes` to re-apply drifted rules and remove orphans.');
    return 1;
}

async function cmdRulesExport({ flags }) {
    const manager = await import('../src/firewall/manager.js');
    const doc = manager.exportRules();
    const text = `${JSON.stringify(doc, null, 2)}\n`;
    if (flags.out) {
        await fsp.writeFile(flags.out, text, 'utf8');
        ok(`Exported ${doc.count} rule(s) to ${flags.out}`);
    } else {
        process.stdout.write(text);
    }
}

async function cmdRulesImport({ flags, positional }) {
    const manager = await import('../src/firewall/manager.js');
    const file = positional[0];
    if (!file) throw new ValidationError('Specify the JSON file to import');
    const doc = await readJsonFile(file);
    const count = (Array.isArray(doc) ? doc : doc.rules ?? []).length;
    if (!requireYes(flags, `replace the entire rule set with ${count} rule(s) from ${file}`)) return 1;
    const result = await manager.importRules(doc, CTX);
    if (maybeJson(flags, result)) return;
    ok(`Imported ${result.imported} rule(s), replacing ${result.replaced}`);
    note('Imported rules are not applied to the OS until you run `fwctl rules apply`.');
}

/* ------------------------------------------------------------------ *
 * test
 * ------------------------------------------------------------------ */

async function cmdTest({ flags }) {
    const manager = await import('../src/firewall/manager.js');
    const result = manager.testPacket({
        direction: flags.direction,
        protocol: flags.protocol,
        srcAddress: flags.src,
        dstAddress: flags.dst,
        srcPort: flags.sport,
        dstPort: flags.dport,
        iface: flags.iface,
    });
    if (maybeJson(flags, result)) return;
    out('');
    out(`  ${result.decision === 'allow' ? c.green(c.bold('ALLOW')) : c.red(c.bold('DENY'))}  ${result.explanation}`);
    if (result.matchCount > 1) note(`${result.matchCount} rules match this packet; only the first one decides.`);
    if (result.note) { out(''); warn(result.note); }
    out('');
}

/* ------------------------------------------------------------------ *
 * blocklist
 * ------------------------------------------------------------------ */

async function cmdBlock({ flags, positional }) {
    const blocklist = await import('../src/monitoring/blocklist.js');
    const target = positional[0];
    if (!target) throw new ValidationError('Specify an IP address or CIDR to block');
    const result = await blocklist.block({
        target, reason: flags.reason ?? '', ttlHours: flags.ttl ?? null, direction: flags.direction, source: 'manual',
    }, CTX);
    if (maybeJson(flags, result)) return;
    ok(`Blocked ${c.bold(result.entry.target)}${result.entry.expiresAt ? ` until ${shortTime(result.entry.expiresAt)}` : ' permanently'}`);
    for (const w of result.entry.warnings ?? []) warn(w);
    for (const r of result.rules) {
        if (r.error) fail(`${r.direction} rule not created: ${r.error}`);
        else note(`${r.direction} deny rule ${r.ruleId}`);
    }
}

async function cmdUnblock({ flags, positional }) {
    const blocklist = await import('../src/monitoring/blocklist.js');
    if (!positional[0]) throw new ValidationError('Specify the blocked IP address or CIDR');
    const result = await blocklist.unblock(positional[0], CTX);
    if (maybeJson(flags, result)) return;
    ok(`Unblocked ${c.bold(positional[0])}`);
}

async function cmdBlocklist({ flags }) {
    const blocklist = await import('../src/monitoring/blocklist.js');
    const result = blocklist.listEntries({ text: flags.q ?? '' });
    if (maybeJson(flags, result)) return;
    heading(`Blocklist (${result.total})`);
    table([
        { key: 'target', label: 'TARGET' },
        { key: 'active', label: 'STATE', format: (v) => (v ? c.red('blocked') : c.dim('expired')) },
        { key: 'source', label: 'SOURCE' },
        { key: 'expiresAt', label: 'EXPIRES', format: (v) => (v ? shortTime(v) : c.dim('never')) },
        { key: 'addedBy', label: 'BY' },
        { key: 'reason', label: 'REASON', width: 50 },
    ], result.entries, { empty: 'Nothing is blocked.' });
}

/* ------------------------------------------------------------------ *
 * logs & audit
 * ------------------------------------------------------------------ */

function printEvent(e) {
    out(`${c.dim(shortTime(e.ts))} ${levelBadge(e.level)} ${c.cyan(e.category.padEnd(9))} ${e.message}`);
}

async function cmdLogs({ flags }) {
    const { queryEvents, EVENT_LOG_PATH } = await import('../src/core/logger.js');
    const filter = {
        text: flags.q ?? '',
        levels: flags.level ?? null,
        categories: flags.category ?? null,
    };
    const result = queryEvents({ ...filter, limit: flags.limit, order: 'desc' });
    if (!flags.follow && maybeJson(flags, result)) return;

    for (const e of result.events.slice().reverse()) printEvent(e);
    if (!flags.follow) {
        note(`${result.events.length} of ${result.total} matching event(s) · ${EVENT_LOG_PATH}`);
        return;
    }

    // Tail the JSON-lines file: works whether events come from this process or a running server.
    const matches = (e) => (!filter.levels?.length || filter.levels.includes(e.level))
        && (!filter.categories?.length || filter.categories.includes(e.category))
        && (!filter.text || `${e.message} ${e.action}`.toLowerCase().includes(filter.text.toLowerCase()));
    let position = fs.existsSync(EVENT_LOG_PATH) ? fs.statSync(EVENT_LOG_PATH).size : 0;
    let carry = '';
    note('Following new events — Ctrl+C to stop.');
    fs.watchFile(EVENT_LOG_PATH, { interval: 750 }, (cur) => {
        if (cur.size < position) position = 0; // rotated
        if (cur.size === position) return;
        const stream = fs.createReadStream(EVENT_LOG_PATH, { start: position, end: cur.size - 1, encoding: 'utf8' });
        position = cur.size;
        stream.on('data', (chunk) => {
            const lines = (carry + chunk).split('\n');
            carry = lines.pop();
            for (const line of lines) {
                try {
                    const e = JSON.parse(line);
                    if (!matches(e)) continue;
                    if (flags.json) out(JSON.stringify(e)); else printEvent(e);
                } catch { /* partial or malformed line */ }
            }
        });
    });
    await new Promise(() => {});
}

async function cmdAudit({ flags }) {
    const { queryAudit } = await import('../src/core/audit.js');
    const result = queryAudit({ text: flags.q ?? '', actor: flags.actor ?? null, limit: flags.limit });
    if (maybeJson(flags, result)) return;
    heading(`Audit trail (${result.total})`);
    table([
        { key: 'seq', label: '#', align: 'right' },
        { key: 'ts', label: 'TIME', format: (v) => shortTime(v) },
        { key: 'actor', label: 'ACTOR' },
        { key: 'action', label: 'ACTION' },
        { key: 'outcome', label: 'OUTCOME', format: (v) => (v === 'success' ? c.green(v) : c.yellow(v)) },
        { key: 'target', label: 'TARGET', width: 60 },
    ], result.entries, { empty: 'No audit entries yet.' });
}

async function cmdAuditVerify({ flags }) {
    const { verifyChain } = await import('../src/core/audit.js');
    const result = verifyChain();
    if (maybeJson(flags, result)) return result.valid ? 0 : 1;
    if (result.valid) {
        ok(`Audit chain intact (${result.checked} entries verified)`);
        return 0;
    }
    fail(`Audit chain BROKEN at entry #${result.brokenAt}: ${result.reason}`);
    return 1;
}

/* ------------------------------------------------------------------ *
 * backup
 * ------------------------------------------------------------------ */

async function cmdBackupCreate({ flags }) {
    const backup = await import('../src/config/backup.js');
    const result = await backup.createBackup({ note: flags.note ?? '' }, CTX);
    if (maybeJson(flags, result)) return;
    ok(`Backup written: ${c.bold(result.filename)} (${result.rules} rule(s), ${result.blocklist} blocklist entry/ies)`);
    note(result.file);
}

async function cmdBackupList({ flags }) {
    const backup = await import('../src/config/backup.js');
    const list = await backup.listBackups();
    if (maybeJson(flags, { backups: list })) return;
    heading(`Backups (${list.length})`);
    table([
        { key: 'filename', label: 'FILE' },
        { key: 'createdAt', label: 'CREATED', format: (v) => shortTime(v) },
        { key: 'counts', label: 'RULES', align: 'right', format: (v) => v?.rules ?? '' },
        { key: 'bytes', label: 'SIZE', align: 'right', format: (v) => bytes(v) },
        { key: 'valid', label: 'VALID', format: (v) => (v ? c.green('yes') : c.red('no')) },
        { key: 'note', label: 'NOTE', width: 40 },
    ], list, { empty: 'No backups yet. Create one with `fwctl backup create`.' });
}

async function cmdBackupRestore({ flags, positional }) {
    const backup = await import('../src/config/backup.js');
    const ref = positional[0];
    if (!ref) throw new ValidationError('Specify a backup file path or a name from `fwctl backup list`');
    const doc = fs.existsSync(ref) ? await readJsonFile(ref) : await backup.readBackupFile(ref);
    const check = backup.validateBackup(doc);
    for (const w of check.warnings) warn(w);
    if (!requireYes(flags, `replace the current rule set with ${check.counts.rules} rule(s) from this backup`)) return 1;
    const result = await backup.restoreBackup(doc, { rules: true, blocklist: flags.blocklist !== false, settings: !!flags.settings }, CTX);
    if (maybeJson(flags, result)) return;
    ok(`Restored ${result.rules?.imported ?? 0} rule(s)`);
    note(`Rollback snapshot: ${result.rollback} — restore it with \`fwctl backup restore ${result.rollback} --yes\``);
}

/* ------------------------------------------------------------------ *
 * settings
 * ------------------------------------------------------------------ */

async function cmdSettings({ flags }) {
    const { publicConfig } = await import('../src/core/config.js');
    const cfg = publicConfig();
    if (maybeJson(flags, cfg.editableSettings)) return;
    heading('Editable settings');
    table([
        { key: 'key', label: 'SETTING' },
        { key: 'current', label: 'VALUE', format: (v) => (typeof v === 'boolean' ? (v ? c.green('true') : c.dim('false')) : String(v)) },
        { key: 'hint', label: 'ALLOWED', width: 40 },
    ], Object.entries(cfg.editableSettings).map(([key, s]) => ({
        key,
        current: s.current,
        hint: s.values ? s.values.join(' | ') : s.type === 'int' ? `${s.min}–${s.max}` : s.type === 'bool' ? 'true | false' : s.type,
    })));
    note('Change with `fwctl settings set key=value …`');
}

async function cmdSettingsSet({ flags, positional }) {
    const { updateSettings } = await import('../src/core/config.js');
    const { audit } = await import('../src/core/audit.js');
    if (positional.length === 0) throw new ValidationError('Pass one or more key=value pairs');
    const patch = {};
    for (const pair of positional) {
        const idx = pair.indexOf('=');
        if (idx < 1) throw new ValidationError(`Expected key=value, got "${pair}"`);
        patch[pair.slice(0, idx).trim()] = pair.slice(idx + 1).trim();
    }
    const result = await updateSettings(patch);
    await audit({ ...CTX, action: 'config.update', target: Object.keys(result.applied).join(', '), after: result.applied });
    if (maybeJson(flags, { applied: result.applied, restartRequired: result.restartRequired })) return;
    for (const [k, v] of Object.entries(result.applied)) ok(`${k} = ${v}`);
    if (result.restartRequired) warn('Restart the server for this change to take effect.');
}

/* ------------------------------------------------------------------ *
 * users
 * ------------------------------------------------------------------ */

function oneTimePassword() {
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
    for (;;) {
        const raw = crypto.randomBytes(20);
        let pwd = '';
        for (let i = 0; i < 20; i++) {
            if (i > 0 && i % 5 === 0) pwd += '-';
            pwd += alphabet[raw[i] % alphabet.length];
        }
        // Must satisfy the password policy: lower, upper, digit (plus the '-' symbol).
        if (/[a-z]/.test(pwd) && /[A-Z]/.test(pwd) && /[0-9]/.test(pwd)) return pwd;
    }
}

function printOneTimePassword(username, password) {
    out('');
    out(`  ${c.bold('username')}  ${username}`);
    out(`  ${c.bold('password')}  ${c.yellow(password)}`);
    out(c.dim('  Shown once. The user must change it at first sign-in.'));
    out('');
}

async function cmdUserList({ flags }) {
    const { listUsers } = await import('../src/core/auth.js');
    const users = listUsers();
    if (maybeJson(flags, { users })) return;
    heading(`Accounts (${users.length})`);
    table([
        { key: 'username', label: 'USER' },
        { key: 'role', label: 'ROLE' },
        { key: 'disabled', label: 'STATE', format: (v, u) => (v ? c.red('disabled') : u.mustChangePassword ? c.yellow('must change password') : c.green('active')) },
        { key: 'lastLoginAt', label: 'LAST LOGIN', format: (v) => (v ? relativeTime(v) : c.dim('never')) },
        { key: 'lastLoginFrom', label: 'FROM' },
    ], users);
}

async function cmdUserAdd({ flags, positional }) {
    const { createUser, updateUser } = await import('../src/core/auth.js');
    const username = positional[0];
    if (!username) throw new ValidationError('Specify a username');
    const password = oneTimePassword();
    const created = await createUser({ username, password, role: flags.role }, CLI_ACTOR, 'cli');
    await updateUser(created.username, { password, mustChangePassword: true }, CLI_ACTOR, 'cli');
    if (maybeJson(flags, { user: created, password })) return;
    ok(`Created ${c.bold(created.username)} (${created.role})`);
    printOneTimePassword(created.username, password);
}

async function cmdUserReset({ flags, positional }) {
    const { updateUser } = await import('../src/core/auth.js');
    const username = positional[0];
    if (!username) throw new ValidationError('Specify a username');
    const password = oneTimePassword();
    const user = await updateUser(username, { password, mustChangePassword: true, disabled: false }, CLI_ACTOR, 'cli');
    if (maybeJson(flags, { user, password })) return;
    ok(`Reset credentials for ${c.bold(user.username)} and re-enabled the account`);
    printOneTimePassword(user.username, password);
}

async function cmdUserSetDisabled({ flags, positional }, disabled) {
    const { updateUser } = await import('../src/core/auth.js');
    if (!positional[0]) throw new ValidationError('Specify a username');
    const user = await updateUser(positional[0], { disabled }, CLI_ACTOR, 'cli');
    if (maybeJson(flags, { user })) return;
    ok(`${disabled ? 'Disabled' : 'Enabled'} ${c.bold(user.username)}`);
}

async function cmdUserDelete({ flags, positional }) {
    const { deleteUser } = await import('../src/core/auth.js');
    if (!positional[0]) throw new ValidationError('Specify a username');
    if (!requireYes(flags, `delete account "${positional[0]}"`)) return 1;
    const result = await deleteUser(positional[0], CLI_ACTOR, 'cli');
    if (maybeJson(flags, result)) return;
    ok(`Deleted ${c.bold(result.username)}`);
}

/* ------------------------------------------------------------------ *
 * traffic
 * ------------------------------------------------------------------ */

async function cmdTraffic({ flags }) {
    const { listConnections } = await import('../src/network/inspector.js');
    const { evaluate } = await import('../src/firewall/rule-model.js');
    const store = await import('../src/firewall/rule-store.js');
    const { getConfig } = await import('../src/core/config.js');

    const live = await listConnections({ limit: 4000 });
    const rules = store.allRules();
    const policy = getConfig().firewall.defaultPolicy;
    const needle = String(flags.q ?? '').toLowerCase();

    const rows = live.connections
        .filter((conn) => conn.state !== 'listen' && conn.state !== 'bound')
        .map((conn) => ({ ...conn, decision: evaluate(rules, conn, policy).decision }))
        .filter((conn) => !needle || `${conn.localAddress}:${conn.localPort} ${conn.remoteAddress}:${conn.remotePort} ${conn.process ?? ''} ${conn.state}`.toLowerCase().includes(needle));

    if (maybeJson(flags, { source: live.source, total: rows.length, connections: rows.slice(0, flags.limit) })) return;
    heading(`Connections (${rows.length}) · source: ${live.source}`);
    if (live.reason) warn(live.reason);
    table([
        { key: 'protocol', label: 'PROTO' },
        { key: 'direction', label: 'DIR', format: (v) => (v === 'inbound' ? 'in ' : 'out') },
        { key: 'localAddress', label: 'LOCAL', format: (v, r) => `${v}:${r.localPort}` },
        { key: 'remoteAddress', label: 'REMOTE', format: (v, r) => `${v}:${r.remotePort}` },
        { key: 'state', label: 'STATE' },
        { key: 'process', label: 'PROCESS', width: 24 },
        { key: 'decision', label: 'POLICY', format: (v) => actionBadge(v) },
    ], rows.slice(0, flags.limit), { empty: 'No active connections.' });
    if (rows.length > flags.limit) note(`Showing ${flags.limit} of ${rows.length}. Use --limit or -q to narrow.`);
}

async function cmdListeners({ flags }) {
    const { listListeners } = await import('../src/network/inspector.js');
    const result = await listListeners();
    if (maybeJson(flags, result)) return;
    heading(`Listening sockets (${result.listeners.length}) · source: ${result.source}`);
    table([
        { key: 'protocol', label: 'PROTO' },
        { key: 'localAddress', label: 'ADDRESS' },
        { key: 'localPort', label: 'PORT', align: 'right' },
        { key: 'wellKnown', label: 'SERVICE' },
        { key: 'exposure', label: 'EXPOSURE', format: (v) => (v === 'all-interfaces' ? c.yellow(v) : v === 'loopback-only' ? c.dim(v) : v) },
        { key: 'process', label: 'PROCESS', width: 28 },
    ], result.listeners.slice().sort((a, b) => a.localPort - b.localPort));
}

async function cmdInterfaces({ flags }) {
    const { listInterfaces } = await import('../src/network/inspector.js');
    const result = await listInterfaces();
    if (maybeJson(flags, result)) return;
    heading(`Interfaces (${result.interfaces.length}) · source: ${result.source}`);
    table([
        { key: 'name', label: 'NAME', width: 28 },
        { key: 'status', label: 'STATUS', format: (v) => (v === 'up' ? c.green(v) : c.dim(v)) },
        { key: 'primaryIPv4', label: 'IPv4' },
        { key: 'primaryIPv6', label: 'IPv6', width: 30 },
        { key: 'mac', label: 'MAC' },
    ], result.interfaces);
}

/* ------------------------------------------------------------------ *
 * Helpers
 * ------------------------------------------------------------------ */

function reportOs(os) {
    if (!os) return;
    if (os.skipped) { note(`OS: not applied (${os.reason})`); return; }
    if (os.ok) { note(`OS: applied as ${os.osName ?? 'rule'}${os.simulated ? ' (simulated)' : ''}`); return; }
    warn(`OS apply failed: ${os.error}`);
    if (os.hint) note(os.hint);
}

function requireYes(flags, what) {
    if (flags.yes) return true;
    fail(`This will ${what}.`);
    note('Re-run with --yes to confirm.');
    return false;
}

async function readJsonFile(file) {
    try {
        return JSON.parse((await fsp.readFile(file, 'utf8')).replace(/^﻿/, ''));
    } catch (e) {
        if (e.code === 'ENOENT') throw new NotFoundError('File', file);
        throw new ValidationError(`${file} is not valid JSON: ${e.message}`);
    }
}

function suggest(input) {
    const names = [...Object.keys(COMMANDS), ...Object.keys(GROUP_DEFAULTS)];
    let best = null;
    let bestScore = Infinity;
    for (const name of names) {
        const d = levenshtein(input, name);
        if (d < bestScore) { bestScore = d; best = name; }
    }
    return bestScore <= Math.max(2, Math.floor(input.length / 3)) ? best : null;
}

function levenshtein(a, b) {
    const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
    for (let j = 1; j <= b.length; j++) dp[0][j] = j;
    for (let i = 1; i <= a.length; i++) {
        for (let j = 1; j <= b.length; j++) {
            dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
        }
    }
    return dp[a.length][b.length];
}

function printHelp() {
    out('');
    out(`${c.bold('fwctl')} — SentryFW firewall management`);
    out('');
    out(`${c.bold('Usage')}  fwctl <command> [subcommand] [options]`);
    const groups = new Map();
    for (const [name, cmd] of Object.entries(COMMANDS)) {
        const group = name.includes(' ') ? name.split(' ')[0] : name;
        if (!groups.has(group)) groups.set(group, []);
        groups.get(group).push([name, cmd.summary]);
    }
    const width = Math.max(...Object.keys(COMMANDS).map((n) => n.length));
    out('');
    for (const entries of groups.values()) {
        for (const [name, summary] of entries) out(`  ${c.cyan(name.padEnd(width))}  ${summary}`);
    }
    out('');
    out(c.bold('Global options'));
    for (const line of formatFlags(GLOBAL_FLAGS, 2)) out(line);
    out('');
    out(c.dim('Run `fwctl <command> --help` for command options.'));
    out('');
}

function printCommandHelp(name, cmd) {
    out('');
    out(`${c.bold(`fwctl ${name}`)} — ${cmd.summary}`);
    if (cmd.usage) { out(''); out(`  ${cmd.usage}`); }
    const lines = formatFlags(cmd.flags ?? {}, 2);
    if (lines.length) { out(''); out(c.bold('Options')); for (const l of lines) out(l); }
    if (cmd.mutates) { out(''); note('Modifies state: refuses to run while `fwctl serve` owns the data directory.'); }
    out('');
}

/* ------------------------------------------------------------------ */

main(process.argv.slice(2)).then(
    (code) => {
        if (code !== null) process.exitCode = code;
    },
    (e) => {
        if (e instanceof AppError) {
            fail(e.message);
            for (const d of Array.isArray(e.details) ? e.details : []) note(`${d.field}: ${d.message}`);
            if (e.details?.hint) note(e.details.hint);
            process.exitCode = e instanceof ValidationError ? 2 : 1;
        } else {
            fail(e?.stack ?? String(e));
            process.exitCode = 1;
        }
    },
);

