/**
 * Windows provider — Windows Defender Firewall with Advanced Security.
 *
 * Mechanism: the NetSecurity PowerShell module (New/Remove/Enable/Disable-
 * NetFirewallRule), driven through scripts/windows-firewall.ps1. Parameters
 * travel as a JSON document on stdin, so no user-controlled value is ever part
 * of a command line. The same rules are visible in wf.msc under the group name
 * configured by `firewall.rulePrefix` — see docs/FIREWALL-GUI.md.
 *
 * Direction mapping (the detail that most tools get wrong):
 *   inbound  : srcAddress -> RemoteAddress, srcPort -> RemotePort
 *              dstAddress -> LocalAddress,  dstPort -> LocalPort
 *   outbound : srcAddress -> LocalAddress,  srcPort -> LocalPort
 *              dstAddress -> RemoteAddress, dstPort -> RemotePort
 *
 * Windows Filtering Platform evaluation is not first-match-wins: an explicit
 * Block beats an Allow regardless of ordering, and there is no rule priority
 * field. `capabilities().priorities` is therefore false, and the rule model's
 * `evaluate()` reports both interpretations so the GUI can flag disagreements.
 */

import { FirewallProvider } from './base.js';
import { runPowerShellScript, isElevated, elevationHint } from '../../core/safe-exec.js';
import { PATHS } from '../../core/paths.js';
import { getConfig } from '../../core/config.js';
import { PrivilegeError, ProviderError } from '../../core/errors.js';
import { osRuleName } from '../rule-model.js';

export class WindowsProvider extends FirewallProvider {
    static id = 'windows';

    get label() {
        return 'Windows Defender Firewall (NetSecurity)';
    }

    capabilities() {
        return {
            read: true,
            write: true,
            enableDisable: true,
            interfaces: true,
            profiles: true,
            programRules: true,
            // WFP has no user-visible rule order; priority is a SentryFW concept
            // used for evaluation preview and documentation only.
            priorities: false,
            requiresElevation: true,
            notes: [
                'Rules are created in Windows Defender Firewall with Advanced Security and appear in wf.msc.',
                `All managed rules carry the group "${safeGroup()}" so they are easy to find, audit and bulk-remove.`,
                'Windows evaluates an explicit Block ahead of any Allow; SentryFW rule priority does not change that.',
                'Reading rules works unprivileged; creating, changing or deleting them requires an elevated process.',
            ],
        };
    }

    async probe() {
        if (process.platform !== 'win32') {
            return { available: false, reason: 'Windows provider requires a Windows host', elevated: false };
        }
        try {
            const data = await runPowerShellScript(PATHS.psWindows, { op: 'probe', ...storeArgs() }, { timeout: 25_000 });
            const elevated = !!data.elevated;
            return {
                available: true,
                elevated,
                reason: elevated ? null : 'Process is not elevated — read-only',
                hint: elevated ? null : elevationHint(),
                service: { name: data.serviceName, status: data.serviceStatus },
                policyStore: data.policyStore,
                group: data.group,
                psVersion: data.psVersion,
            };
        } catch (err) {
            return {
                available: false,
                elevated: false,
                reason: err.message,
                hint: 'Verify that the MpsSvc (Windows Defender Firewall) service is running and the NetSecurity module is present.',
            };
        }
    }

    async listNative({ scope = 'managed', limit = 2000, onlyEnabled = false } = {}) {
        const op = scope === 'all' ? 'listAll' : 'listManaged';
        const data = await runPowerShellScript(
            PATHS.psWindows,
            { op, limit, onlyEnabled, ...storeArgs() },
            { timeout: scope === 'all' ? 120_000 : 45_000 },
        );
        const rules = Array.isArray(data.rules) ? data.rules : [];
        return scope === 'all'
            ? { rules, total: data.total ?? rules.length, truncated: !!data.truncated }
            : rules;
    }

    async applyRule(rule) {
        await this.#requireElevation('create or modify firewall rules');
        const payload = {
            op: 'apply',
            rule: nativeRulePayload(rule),
            ...storeArgs(),
        };
        const data = await runPowerShellScript(PATHS.psWindows, payload, { timeout: 45_000 });
        return {
            osName: data.osName,
            applied: true,
            replaced: !!data.replaced,
            store: data.store,
        };
    }

    async removeRule(rule) {
        await this.#requireElevation('remove firewall rules');
        const name = rule.osRuleName || osRuleName(rule, safeGroup());
        const data = await runPowerShellScript(
            PATHS.psWindows,
            { op: 'remove', osName: name, ...storeArgs() },
            { timeout: 45_000 },
        );
        return { osName: data.osName, removed: !!data.removed, reason: data.reason ?? null };
    }

    async setEnabled(rule, enabled) {
        await this.#requireElevation('change firewall rule state');
        const name = rule.osRuleName || osRuleName(rule, safeGroup());
        try {
            const data = await runPowerShellScript(
                PATHS.psWindows,
                { op: 'setEnabled', osName: name, enabled: !!enabled, ...storeArgs() },
                { timeout: 45_000 },
            );
            return { osName: data.osName, enabled: !!data.enabled };
        } catch (err) {
            // Not yet programmed into the OS: apply it in the requested state.
            if (err instanceof ProviderError && err.details?.providerCode === 'NOT_PRESENT') {
                const res = await this.applyRule({ ...rule, enabled });
                return { osName: res.osName, enabled: !!enabled, created: true };
            }
            throw err;
        }
    }

    async removeAllManaged() {
        await this.#requireElevation('bulk-remove firewall rules');
        const data = await runPowerShellScript(PATHS.psWindows, { op: 'removeGroup', ...storeArgs() }, { timeout: 120_000 });
        return { group: data.group, removed: data.removed ?? 0 };
    }

    async profiles() {
        const data = await runPowerShellScript(PATHS.psWindows, { op: 'profiles', ...storeArgs() }, { timeout: 30_000 });
        return Array.isArray(data.profiles) ? data.profiles : [];
    }

    async defaultPolicy() {
        try {
            const profiles = await this.profiles();
            const active = profiles.filter((p) => p.enabled);
            const pick = (key, fallback) => {
                const values = active.map((p) => String(p[key] ?? '').toLowerCase()).filter((v) => v && v !== 'notconfigured');
                if (values.length === 0) return fallback;
                // Any profile that blocks makes the effective posture "deny".
                return values.some((v) => v === 'block') ? 'deny' : 'allow';
            };
            return {
                // Windows defaults: inbound blocked, outbound allowed, when a
                // profile reports NotConfigured.
                inbound: pick('defaultInboundAction', 'deny'),
                outbound: pick('defaultOutboundAction', 'allow'),
                source: 'windows-profiles',
                profiles: profiles.map((p) => ({
                    name: p.name,
                    enabled: p.enabled,
                    inbound: p.defaultInboundAction,
                    outbound: p.defaultOutboundAction,
                    logBlocked: p.logBlocked,
                    logAllowed: p.logAllowed,
                    logFileName: p.logFileName,
                })),
            };
        } catch (err) {
            return { inbound: null, outbound: null, source: 'unavailable', error: err.message };
        }
    }

    translate(rule) {
        return translateWindows(rule);
    }

    async #requireElevation(what) {
        if (await isElevated()) return true;
        throw new PrivilegeError(`Administrator privileges are required to ${what}`, elevationHint());
    }
}

/* ------------------------------------------------------------------ *
 * Translation helpers (exported: used by the simulated provider and docs)
 * ------------------------------------------------------------------ */

function safeGroup() {
    const prefix = getConfig().firewall.rulePrefix ?? 'SentryFW';
    return String(prefix).replace(/[^A-Za-z0-9 _.\-]/g, '') || 'SentryFW';
}

function storeArgs() {
    const cfg = getConfig().firewall.windows;
    return {
        group: safeGroup(),
        policyStore: cfg?.policyStore ?? 'PersistentStore',
    };
}

/** Canonical rule -> the exact payload the PowerShell helper consumes. */
export function nativeRulePayload(rule) {
    return {
        osName: rule.osRuleName || osRuleName(rule, safeGroup()),
        displayName: rule.name,
        description: rule.description ?? '',
        direction: rule.direction,
        action: rule.action,
        protocol: rule.protocol,
        srcAddress: rule.srcAddress,
        dstAddress: rule.dstAddress,
        srcPort: rule.srcPort,
        dstPort: rule.dstPort,
        iface: rule.iface,
        profiles: rule.profiles ?? ['Any'],
        program: rule.program ?? '',
        enabled: rule.enabled !== false,
    };
}

const PROTOCOL_MAP = Object.freeze({ tcp: 'TCP', udp: 'UDP', icmp: 'ICMPv4', icmpv6: 'ICMPv6', any: 'Any' });

/**
 * Produce the equivalent PowerShell and netsh commands. Used by the GUI preview
 * pane, `fwctl rules preview`, and the documentation, so an operator can see and
 * reproduce exactly what SentryFW programs.
 */
export function translateWindows(rule) {
    const group = safeGroup();
    const name = rule.osRuleName || osRuleName(rule, group);
    const direction = rule.direction === 'outbound' ? 'Outbound' : 'Inbound';
    const action = rule.action === 'allow' ? 'Allow' : 'Block';
    const protocol = PROTOCOL_MAP[rule.protocol] ?? 'Any';

    const inbound = rule.direction === 'inbound';
    const localAddress = inbound ? rule.dstAddress : rule.srcAddress;
    const remoteAddress = inbound ? rule.srcAddress : rule.dstAddress;
    const localPort = inbound ? rule.dstPort : rule.srcPort;
    const remotePort = inbound ? rule.srcPort : rule.dstPort;

    const ps = [
        'New-NetFirewallRule',
        `  -Name '${name}'`,
        `  -DisplayName '${rule.name}'`,
        `  -Group '${group}'`,
        `  -Direction ${direction}`,
        `  -Action ${action}`,
        `  -Enabled ${rule.enabled === false ? 'False' : 'True'}`,
        `  -Profile ${(rule.profiles ?? ['Any']).join(',')}`,
    ];
    if (protocol !== 'Any') ps.push(`  -Protocol ${protocol}`);
    if (localAddress !== 'any') ps.push(`  -LocalAddress ${quoteList(localAddress)}`);
    if (remoteAddress !== 'any') ps.push(`  -RemoteAddress ${quoteList(remoteAddress)}`);
    if ((protocol === 'TCP' || protocol === 'UDP')) {
        if (localPort !== 'any') ps.push(`  -LocalPort ${quoteList(localPort)}`);
        if (remotePort !== 'any') ps.push(`  -RemotePort ${quoteList(remotePort)}`);
    }
    if (rule.iface && rule.iface !== 'any') ps.push(`  -InterfaceAlias '${rule.iface}'`);
    if (rule.program) ps.push(`  -Program '${rule.program}'`);
    if (rule.description) ps.push(`  -Description '${rule.description.replace(/'/g, "''")}'`);
    ps.push(`  -PolicyStore ${getConfig().firewall.windows?.policyStore ?? 'PersistentStore'}`);

    const netshParts = [
        'netsh advfirewall firewall add rule',
        `name="${name}"`,
        `dir=${inbound ? 'in' : 'out'}`,
        `action=${rule.action === 'allow' ? 'allow' : 'block'}`,
        `enable=${rule.enabled === false ? 'no' : 'yes'}`,
        `profile=${(rule.profiles ?? ['Any']).join(',').toLowerCase()}`,
    ];
    if (protocol !== 'Any') netshParts.push(`protocol=${protocol === 'ICMPv4' ? 'icmpv4' : protocol.toLowerCase()}`);
    if (localAddress !== 'any') netshParts.push(`localip=${localAddress}`);
    if (remoteAddress !== 'any') netshParts.push(`remoteip=${remoteAddress}`);
    if (protocol === 'TCP' || protocol === 'UDP') {
        if (localPort !== 'any') netshParts.push(`localport=${localPort}`);
        if (remotePort !== 'any') netshParts.push(`remoteport=${remotePort}`);
    }
    if (rule.program) netshParts.push(`program="${rule.program}"`);
    if (rule.description) netshParts.push(`description="${rule.description}"`);

    return {
        kind: 'windows',
        primary: 'powershell',
        lines: [ps.join(' `\n')],
        alternatives: [
            { label: 'netsh (legacy, still supported)', lines: [netshParts.join(' ')] },
            { label: 'Verify', lines: [`Get-NetFirewallRule -Name '${name}' | Format-List Name,DisplayName,Enabled,Direction,Action,Profile`] },
            { label: 'Remove', lines: [`Remove-NetFirewallRule -Name '${name}'`] },
        ],
        guiPath: 'wf.msc → ' + (inbound ? 'Inbound Rules' : 'Outbound Rules') + ` → group "${group}" → "${rule.name}"`,
        note: 'Requires an elevated shell. Windows evaluates Block rules before Allow rules regardless of order.',
    };
}

function quoteList(spec) {
    const parts = String(spec).split(',').map((p) => p.trim()).filter(Boolean);
    return parts.length === 1 ? parts[0] : parts.join(',');
}
