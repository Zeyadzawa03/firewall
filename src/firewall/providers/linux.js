/**
 * Linux provider — iptables / nftables / ufw / firewalld.
 *
 * All four backends are driven by argv arrays through safe-exec (never a shell),
 * so shell metacharacters in a rule field cannot be interpreted. The backend is
 * chosen by `firewall.linux.backend`; `auto` probes in order of preference:
 * nftables (modern default) -> iptables -> ufw -> firewalld.
 *
 * Managed rules are tagged with an iptables/nft comment containing the rule id,
 * which is how `sync` correlates OS state back to the canonical store — the same
 * role the group + `[rule_id]` name plays on Windows.
 *
 * This provider is implemented and exercised by the unit tests through its
 * translation layer on every platform; the command-executing paths only run on
 * Linux hosts.
 */

import { FirewallProvider } from './base.js';
import { run, runChecked, isElevated, elevationHint } from '../../core/safe-exec.js';
import { getConfig } from '../../core/config.js';
import { PrivilegeError, UnsupportedError, ProviderError } from '../../core/errors.js';
import { expandPortSpec } from '../../core/validate.js';

const BACKEND_PREFERENCE = ['nftables', 'iptables', 'ufw', 'firewalld'];

export class LinuxProvider extends FirewallProvider {
    static id = 'linux';

    constructor() {
        super();
        this.backend = null;
        this.available = null;
    }

    get label() {
        return `Linux netfilter${this.backend ? ` (${this.backend})` : ''}`;
    }

    capabilities() {
        return {
            read: true,
            write: true,
            enableDisable: true,
            interfaces: true,
            profiles: false,
            programRules: false, // netfilter matches packets, not executables
            priorities: true,    // chain order is explicit and meaningful
            requiresElevation: true,
            notes: [
                'Rules are inserted into the filter table (INPUT/OUTPUT) and tagged with a comment holding the SentryFW rule id.',
                'netfilter is first-match-wins, so SentryFW rule priority maps directly onto rule position.',
                'Requires root or CAP_NET_ADMIN. Reading the ruleset also requires privileges on most distributions.',
                'Application/program-scoped rules are not supported by netfilter; use cgroup or owner matching instead.',
            ],
        };
    }

    async detectBackend() {
        if (this.backend) return this.backend;
        const configured = getConfig().firewall.linux?.backend ?? 'auto';
        if (configured !== 'auto') {
            this.backend = configured;
            return this.backend;
        }
        for (const candidate of BACKEND_PREFERENCE) {
            if (await backendPresent(candidate)) {
                this.backend = candidate;
                return this.backend;
            }
        }
        this.backend = 'iptables';
        return this.backend;
    }

    async probe() {
        if (process.platform === 'win32') {
            return { available: false, reason: 'Linux provider requires a Linux host', elevated: false };
        }
        const backend = await this.detectBackend();
        const present = await backendPresent(backend);
        const elevated = await isElevated();
        return {
            available: present,
            elevated,
            backend,
            reason: present ? (elevated ? null : 'Process is not root — read-only') : `${backend} tooling was not found on PATH`,
            hint: elevated ? null : elevationHint(),
        };
    }

    async listNative() {
        const backend = await this.detectBackend();
        const cfg = getConfig().firewall.linux;
        if (backend === 'nftables') {
            const res = await run('nft', ['-j', 'list', 'table', 'inet', 'filter']);
            if (res.code !== 0) throw new ProviderError('nft list failed', { provider: 'nft', exitCode: res.code, stderr: res.stderr });
            return parseNftJson(res.stdout);
        }
        if (backend === 'iptables') {
            const rules = [];
            for (const chain of [cfg.chainIn ?? 'INPUT', cfg.chainOut ?? 'OUTPUT']) {
                const res = await run('iptables', ['-t', cfg.table ?? 'filter', '-S', chain]);
                if (res.code === 0) rules.push(...parseIptablesSave(res.stdout, chain));
            }
            return rules;
        }
        if (backend === 'ufw') {
            const res = await run('ufw', ['status', 'numbered']);
            if (res.code !== 0) throw new ProviderError('ufw status failed', { provider: 'ufw', exitCode: res.code, stderr: res.stderr });
            return parseUfwStatus(res.stdout);
        }
        if (backend === 'firewalld') {
            const res = await run('firewall-cmd', ['--list-all']);
            if (res.code !== 0) throw new ProviderError('firewall-cmd failed', { provider: 'firewalld', exitCode: res.code, stderr: res.stderr });
            return parseFirewalldList(res.stdout);
        }
        throw new UnsupportedError(`Unsupported Linux backend: ${backend}`);
    }

    async applyRule(rule) {
        await this.#requireRoot('create or modify firewall rules');
        const plan = await this.#plan(rule, 'add');
        for (const cmd of plan.commands) {
            await runChecked(cmd.file, cmd.args, { timeout: 20_000 });
        }
        return { osName: managedComment(rule), applied: true, backend: plan.backend, commands: plan.commands.length };
    }

    async removeRule(rule) {
        await this.#requireRoot('remove firewall rules');
        const plan = await this.#plan(rule, 'delete');
        let removed = false;
        for (const cmd of plan.commands) {
            const res = await run(cmd.file, cmd.args, { timeout: 20_000 });
            if (res.code === 0) removed = true;
        }
        return { osName: managedComment(rule), removed, backend: plan.backend };
    }

    async setEnabled(rule, enabled) {
        // netfilter has no disabled state: absence is the disabled state.
        return enabled ? this.applyRule({ ...rule, enabled: true }) : this.removeRule(rule);
    }

    async defaultPolicy() {
        const backend = await this.detectBackend();
        if (backend !== 'iptables') {
            return { inbound: null, outbound: null, source: `${backend}-unavailable` };
        }
        const res = await run('iptables', ['-t', 'filter', '-S']);
        if (res.code !== 0) return { inbound: null, outbound: null, source: 'unavailable' };
        const map = {};
        for (const line of res.stdout.split('\n')) {
            const m = /^-P\s+(\S+)\s+(\S+)/.exec(line.trim());
            if (m) map[m[1]] = m[2].toLowerCase() === 'drop' || m[2].toLowerCase() === 'reject' ? 'deny' : 'allow';
        }
        return { inbound: map.INPUT ?? null, outbound: map.OUTPUT ?? null, source: 'iptables-policy' };
    }

    translate(rule) {
        return translateLinux(rule, this.backend ?? getConfig().firewall.linux?.backend ?? 'iptables');
    }

    async #plan(rule, mode) {
        const backend = await this.detectBackend();
        const native = translateLinux(rule, backend, mode);
        if (!native.commands || native.commands.length === 0) {
            throw new UnsupportedError(`Cannot express this rule with the ${backend} backend`, { rule: rule.id });
        }
        return { backend, commands: native.commands };
    }

    async #requireRoot(what) {
        if (await isElevated()) return true;
        throw new PrivilegeError(`Root privileges (or CAP_NET_ADMIN) are required to ${what}`, elevationHint());
    }
}

/* ------------------------------------------------------------------ *
 * Translation
 * ------------------------------------------------------------------ */

async function backendPresent(backend) {
    if (process.platform === 'win32') return false;
    const probe = {
        nftables: ['nft', ['--version']],
        iptables: ['iptables', ['--version']],
        ufw: ['ufw', ['version']],
        firewalld: ['firewall-cmd', ['--version']],
    }[backend];
    if (!probe) return false;
    try {
        const res = await run(probe[0], probe[1], { timeout: 8000 });
        return res.code === 0;
    } catch {
        return false;
    }
}

export function managedComment(rule) {
    const prefix = (getConfig().firewall.rulePrefix ?? 'SentryFW').replace(/[^A-Za-z0-9_.\-]/g, '');
    return `${prefix}:${rule.id}`;
}

const PROTO_NUM = Object.freeze({ icmp: 'icmp', icmpv6: 'icmpv6', tcp: 'tcp', udp: 'udp' });

/**
 * Canonical rule -> native Linux commands.
 * Returns { kind, backend, lines, commands, alternatives, guiPath, note }.
 * `commands` are argv arrays ready for safe-exec; `lines` are the same commands
 * rendered for display.
 */
export function translateLinux(rule, backend = 'iptables', mode = 'add') {
    const cfg = getConfig().firewall.linux ?? {};
    const table = cfg.table ?? 'filter';
    const chain = rule.direction === 'inbound' ? (cfg.chainIn ?? 'INPUT') : (cfg.chainOut ?? 'OUTPUT');
    const comment = managedComment(rule);
    const target = rule.action === 'allow' ? 'ACCEPT' : 'DROP';

    if (backend === 'nftables') return translateNft(rule, { chain, comment, mode });
    if (backend === 'ufw') return translateUfw(rule, { comment, mode });
    if (backend === 'firewalld') return translateFirewalld(rule, { mode });

    // ---- iptables ----
    const ip6 = looksIPv6(rule);
    const binary = ip6 ? 'ip6tables' : 'iptables';
    const commands = [];

    const portTokens = rule.protocol === 'tcp' || rule.protocol === 'udp'
        ? { src: splitSpec(rule.srcPort), dst: splitSpec(rule.dstPort) }
        : { src: ['any'], dst: ['any'] };

    for (const srcAddr of splitSpec(rule.srcAddress)) {
        for (const dstAddr of splitSpec(rule.dstAddress)) {
            for (const sport of portTokens.src) {
                for (const dport of portTokens.dst) {
                    const args = [
                        '-t', table,
                        mode === 'delete' ? '-D' : '-I', chain,
                    ];
                    if (mode !== 'delete') args.push(String(rule.priority ?? 100));
                    if (rule.protocol !== 'any') args.push('-p', PROTO_NUM[rule.protocol] ?? rule.protocol);
                    if (srcAddr !== 'any') args.push('-s', srcAddr);
                    if (dstAddr !== 'any') args.push('-d', dstAddr);
                    if (sport !== 'any') args.push('--sport', normaliseRange(sport));
                    if (dport !== 'any') args.push('--dport', normaliseRange(dport));
                    if (rule.iface && rule.iface !== 'any') {
                        args.push(rule.direction === 'inbound' ? '-i' : '-o', rule.iface);
                    }
                    args.push('-m', 'comment', '--comment', comment);
                    args.push('-j', target);
                    commands.push({ file: binary, args });
                }
            }
        }
    }

    const lines = commands.map((c) => `${c.file} ${c.args.map(shellQuoteForDisplay).join(' ')}`);

    return {
        kind: 'linux',
        backend: 'iptables',
        primary: binary,
        lines,
        commands,
        alternatives: [
            { label: 'List managed rules', lines: [`${binary} -t ${table} -S ${chain} | grep ${comment.split(':')[0]}`] },
            { label: 'Persist across reboot (Debian/Ubuntu)', lines: ['apt-get install iptables-persistent', 'netfilter-persistent save'] },
            { label: 'Persist across reboot (RHEL/Fedora)', lines: ['service iptables save'] },
        ],
        guiPath: 'gufw (Ubuntu) or firewall-config (RHEL/Fedora) — see docs/FIREWALL-GUI.md',
        note: 'netfilter is first-match-wins; -I inserts at the position given by the rule priority.',
    };
}

function translateNft(rule, { chain, comment, mode }) {
    const family = looksIPv6(rule) ? 'ip6' : 'ip';
    const nftChain = chain.toLowerCase();
    const verdict = rule.action === 'allow' ? 'accept' : 'drop';
    const parts = [];

    if (rule.protocol !== 'any') {
        if (rule.protocol === 'icmp') parts.push('ip protocol icmp');
        else if (rule.protocol === 'icmpv6') parts.push('ip6 nexthdr icmpv6');
        else parts.push(`meta l4proto ${rule.protocol}`);
    }
    if (rule.srcAddress !== 'any') parts.push(`${family} saddr { ${splitSpec(rule.srcAddress).join(', ')} }`);
    if (rule.dstAddress !== 'any') parts.push(`${family} daddr { ${splitSpec(rule.dstAddress).join(', ')} }`);
    if ((rule.protocol === 'tcp' || rule.protocol === 'udp')) {
        if (rule.srcPort !== 'any') parts.push(`${rule.protocol} sport { ${splitSpec(rule.srcPort).map(nftRange).join(', ')} }`);
        if (rule.dstPort !== 'any') parts.push(`${rule.protocol} dport { ${splitSpec(rule.dstPort).map(nftRange).join(', ')} }`);
    }
    if (rule.iface && rule.iface !== 'any') {
        parts.push(`${rule.direction === 'inbound' ? 'iifname' : 'oifname'} "${rule.iface}"`);
    }
    parts.push(`comment "${comment}"`);
    parts.push(verdict);

    const expression = parts.join(' ');
    const argv = mode === 'delete'
        // Deleting by expression requires the handle; the documented flow is to
        // look the handle up and delete by handle.
        ? [{ file: 'nft', args: ['-a', 'list', 'chain', 'inet', 'filter', nftChain] }]
        : [{ file: 'nft', args: ['add', 'rule', 'inet', 'filter', nftChain, ...expression.split(' ').filter(Boolean)] }];

    return {
        kind: 'linux',
        backend: 'nftables',
        primary: 'nft',
        lines: [`nft add rule inet filter ${nftChain} ${expression}`],
        commands: argv,
        alternatives: [
            { label: 'List with handles', lines: [`nft -a list chain inet filter ${nftChain}`] },
            { label: 'Delete by handle', lines: [`nft delete rule inet filter ${nftChain} handle <handle>`] },
            { label: 'Persist', lines: ['nft list ruleset > /etc/nftables.conf', 'systemctl enable --now nftables'] },
        ],
        guiPath: 'firewall-config (firewalld front-end) or nft-based distro tooling — see docs/FIREWALL-GUI.md',
        note: mode === 'delete'
            ? 'nftables deletes by handle: list the chain with -a, then delete the handle shown for the comment.'
            : 'nftables is first-match-wins within a chain; ordering follows insertion order.',
    };
}

function translateUfw(rule, { mode }) {
    const action = rule.action === 'allow' ? 'allow' : 'deny';
    const dir = rule.direction === 'inbound' ? 'in' : 'out';
    const args = [];
    if (mode === 'delete') args.push('delete');
    args.push(action, dir);
    if (rule.iface && rule.iface !== 'any') args.push('on', rule.iface);
    if (rule.srcAddress !== 'any') args.push('from', splitSpec(rule.srcAddress)[0]);
    else args.push('from', 'any');
    if (rule.srcPort !== 'any' && (rule.protocol === 'tcp' || rule.protocol === 'udp')) {
        args.push('port', normaliseRange(splitSpec(rule.srcPort)[0]));
    }
    if (rule.dstAddress !== 'any') args.push('to', splitSpec(rule.dstAddress)[0]);
    else args.push('to', 'any');
    if (rule.dstPort !== 'any' && (rule.protocol === 'tcp' || rule.protocol === 'udp')) {
        args.push('port', normaliseRange(splitSpec(rule.dstPort)[0]));
    }
    if (rule.protocol === 'tcp' || rule.protocol === 'udp') args.push('proto', rule.protocol);

    return {
        kind: 'linux',
        backend: 'ufw',
        primary: 'ufw',
        lines: [`ufw ${args.join(' ')}`],
        commands: [{ file: 'ufw', args }],
        alternatives: [
            { label: 'List', lines: ['ufw status numbered'] },
            { label: 'Delete by number', lines: ['ufw delete <number>'] },
        ],
        guiPath: 'gufw — Ubuntu graphical front-end for ufw (see docs/FIREWALL-GUI.md)',
        note: 'ufw collapses multi-value specs; SentryFW uses the first token of each list. Prefer iptables/nftables for complex rules.',
    };
}

function translateFirewalld(rule, { mode }) {
    const family = looksIPv6(rule) ? 'ipv6' : 'ipv4';
    const bits = [`rule family="${family}"`];
    if (rule.srcAddress !== 'any') bits.push(`source address="${splitSpec(rule.srcAddress)[0]}"`);
    if (rule.dstAddress !== 'any') bits.push(`destination address="${splitSpec(rule.dstAddress)[0]}"`);
    if (rule.protocol === 'tcp' || rule.protocol === 'udp') {
        if (rule.dstPort !== 'any') bits.push(`port port="${normaliseRange(splitSpec(rule.dstPort)[0])}" protocol="${rule.protocol}"`);
    } else if (rule.protocol === 'icmp' || rule.protocol === 'icmpv6') {
        bits.push('icmp-block-inversion');
    }
    bits.push(rule.action === 'allow' ? 'accept' : 'drop');
    const richRule = bits.join(' ');
    const flag = mode === 'delete' ? '--remove-rich-rule' : '--add-rich-rule';

    return {
        kind: 'linux',
        backend: 'firewalld',
        primary: 'firewall-cmd',
        lines: [`firewall-cmd --permanent ${flag}='${richRule}'`, 'firewall-cmd --reload'],
        commands: [
            { file: 'firewall-cmd', args: ['--permanent', `${flag}=${richRule}`] },
            { file: 'firewall-cmd', args: ['--reload'] },
        ],
        alternatives: [
            { label: 'List rich rules', lines: ['firewall-cmd --list-rich-rules'] },
            { label: 'Runtime only (not persisted)', lines: [`firewall-cmd ${flag}='${richRule}'`] },
        ],
        guiPath: 'firewall-config — the official firewalld GUI (see docs/FIREWALL-GUI.md)',
        note: 'firewalld rich rules are zone-scoped; --permanent plus --reload makes the change survive a reboot.',
    };
}

/* ------------------------------------------------------------------ *
 * Parsers
 * ------------------------------------------------------------------ */

export function parseIptablesSave(text, chain = 'INPUT') {
    const out = [];
    for (const raw of String(text ?? '').split('\n')) {
        const line = raw.trim();
        if (!line.startsWith('-A ') && !line.startsWith('-I ')) continue;
        const commentMatch = /--comment\s+("([^"]*)"|(\S+))/.exec(line);
        const comment = commentMatch ? (commentMatch[2] ?? commentMatch[3]) : '';
        const get = (flag) => {
            const m = new RegExp(`${flag}\\s+(\\S+)`).exec(line);
            return m ? m[1] : null;
        };
        const target = get('-j') ?? '';
        out.push({
            osName: comment,
            chain: get('-A') ?? get('-I') ?? chain,
            direction: (get('-A') ?? chain) === 'OUTPUT' ? 'outbound' : 'inbound',
            action: target === 'ACCEPT' ? 'allow' : (target === 'DROP' || target === 'REJECT' ? 'deny' : target.toLowerCase()),
            protocol: get('-p') ?? 'any',
            srcAddress: get('-s') ?? 'any',
            dstAddress: get('-d') ?? 'any',
            srcPort: get('--sport') ?? 'any',
            dstPort: get('--dport') ?? 'any',
            iface: get('-i') ?? get('-o') ?? 'any',
            enabled: true,
            raw: line,
        });
    }
    return out;
}

export function parseNftJson(text) {
    let doc;
    try {
        doc = JSON.parse(text);
    } catch {
        return [];
    }
    const items = Array.isArray(doc?.nftables) ? doc.nftables : [];
    const out = [];
    for (const item of items) {
        const rule = item?.rule;
        if (!rule) continue;
        const expr = Array.isArray(rule.expr) ? rule.expr : [];
        const comment = rule.comment ?? '';
        const verdict = expr.find((e) => e.accept !== undefined || e.drop !== undefined || e.reject !== undefined);
        const match = (field) => {
            for (const e of expr) {
                const left = e?.match?.left;
                const right = e?.match?.right;
                if (left?.payload?.field === field) return typeof right === 'object' ? JSON.stringify(right) : String(right);
            }
            return 'any';
        };
        out.push({
            osName: comment,
            chain: rule.chain,
            direction: String(rule.chain ?? '').toLowerCase() === 'output' ? 'outbound' : 'inbound',
            action: verdict?.accept !== undefined ? 'allow' : 'deny',
            protocol: match('protocol'),
            srcAddress: match('saddr'),
            dstAddress: match('daddr'),
            srcPort: match('sport'),
            dstPort: match('dport'),
            iface: 'any',
            handle: rule.handle,
            enabled: true,
        });
    }
    return out;
}

export function parseUfwStatus(text) {
    const out = [];
    for (const raw of String(text ?? '').split('\n')) {
        const line = raw.trim();
        const m = /^\[\s*(\d+)\]\s+(.+?)\s{2,}(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT)\s*(.*)$/i.exec(line);
        if (!m) continue;
        const [, num, to, action, dir, from] = m;
        out.push({
            osName: `ufw:${num}`,
            number: Number(num),
            direction: dir.toUpperCase() === 'OUT' ? 'outbound' : 'inbound',
            action: action.toUpperCase() === 'ALLOW' ? 'allow' : 'deny',
            dstAddress: to.trim(),
            srcAddress: (from || 'any').trim() || 'any',
            protocol: /\/(tcp|udp)\b/i.exec(to)?.[1]?.toLowerCase() ?? 'any',
            enabled: true,
            raw: line,
        });
    }
    return out;
}

export function parseFirewalldList(text) {
    const out = [];
    const richSection = /rich rules:\s*([\s\S]*)$/i.exec(String(text ?? ''));
    if (!richSection) return out;
    for (const raw of richSection[1].split('\n')) {
        const line = raw.trim();
        if (!line.startsWith('rule ')) continue;
        const src = /source address="([^"]+)"/.exec(line)?.[1] ?? 'any';
        const port = /port port="([^"]+)"/.exec(line)?.[1] ?? 'any';
        const proto = /protocol="([^"]+)"/.exec(line)?.[1] ?? 'any';
        out.push({
            osName: `firewalld:${out.length + 1}`,
            direction: 'inbound',
            action: /\baccept\b/.test(line) ? 'allow' : 'deny',
            srcAddress: src,
            dstAddress: 'any',
            srcPort: 'any',
            dstPort: port,
            protocol: proto,
            enabled: true,
            raw: line,
        });
    }
    return out;
}

/* ------------------------------------------------------------------ *
 * Small helpers
 * ------------------------------------------------------------------ */

function splitSpec(spec) {
    if (!spec || spec === 'any') return ['any'];
    return String(spec).split(',').map((s) => s.trim()).filter(Boolean);
}

function normaliseRange(token) {
    return String(token).includes('-') ? String(token).replace('-', ':') : String(token);
}

function nftRange(token) {
    return String(token).includes('-') ? String(token).replace('-', '-') : String(token);
}

function looksIPv6(rule) {
    const probe = `${rule.srcAddress ?? ''}${rule.dstAddress ?? ''}`;
    return rule.protocol === 'icmpv6' || (probe.includes(':') && !probe.includes('.'));
}

function shellQuoteForDisplay(arg) {
    return /[^A-Za-z0-9_.\-:/,=]/.test(arg) ? `'${arg}'` : arg;
}

/** Exported for tests: how many iptables commands a rule expands into. */
export function iptablesExpansionCount(rule) {
    const ports = rule.protocol === 'tcp' || rule.protocol === 'udp'
        ? splitSpec(rule.srcPort).length * splitSpec(rule.dstPort).length
        : 1;
    return splitSpec(rule.srcAddress).length * splitSpec(rule.dstAddress).length * ports;
}

/** Exported for tests: guard against pathological expansion. */
export const MAX_IPTABLES_EXPANSION = 256;

export function assertExpansionSafe(rule) {
    const n = iptablesExpansionCount(rule);
    if (n > MAX_IPTABLES_EXPANSION) {
        throw new UnsupportedError(
            `This rule expands to ${n} iptables commands (limit ${MAX_IPTABLES_EXPANSION}). Use CIDR ranges or port ranges instead of long lists.`,
            { expansion: n, limit: MAX_IPTABLES_EXPANSION },
        );
    }
    return n;
}

export { expandPortSpec };
