/**
 * Simulated provider — the default.
 *
 * Purpose: let the whole application (GUI, CLI, API, monitoring, detection,
 * tests) run end-to-end without touching the host firewall and without
 * requiring elevation. It keeps a shadow copy of what *would* be programmed
 * into the OS, so `sync`, drift detection, previews and the rule editor all
 * behave exactly as they do against a real provider.
 *
 * It is deliberately not a no-op: it validates the same way, records the same
 * shadow state, and produces the same native command preview the real providers
 * would run. That is what makes it a safe default rather than a fake.
 */

import { FirewallProvider } from './base.js';
import { getConfig } from '../../core/config.js';
import { osRuleName } from '../rule-model.js';
import { translateWindows } from './windows.js';
import { translateLinux } from './linux.js';

export class SimulatedProvider extends FirewallProvider {
    static id = 'simulated';

    constructor() {
        super();
        /** @type {Map<string, object>} osName -> native rule projection */
        this.shadow = new Map();
    }

    get label() {
        return 'Simulated (no OS changes)';
    }

    capabilities() {
        return {
            read: true,
            write: true,
            enableDisable: true,
            interfaces: false,
            profiles: false,
            programRules: true,
            priorities: true,
            requiresElevation: false,
            notes: [
                'Rules are stored and evaluated inside SentryFW only; the host firewall is never modified.',
                'Use this mode for development, demos, training and CI.',
                'Switch to the windows or linux provider (and enable firewall.applyToOS) to program real rules.',
            ],
        };
    }

    async probe() {
        return {
            available: true,
            elevated: false,
            reason: null,
            shadowRules: this.shadow.size,
            note: 'Simulation active — no operating system firewall calls are made.',
        };
    }

    async listNative() {
        return [...this.shadow.values()].map((r) => ({ ...r }));
    }

    async applyRule(rule) {
        const prefix = getConfig().firewall.rulePrefix;
        const name = rule.osRuleName || osRuleName(rule, prefix);
        const existed = this.shadow.has(name);
        this.shadow.set(name, {
            osName: name,
            displayName: rule.name,
            description: rule.description,
            direction: rule.direction,
            action: rule.action,
            protocol: rule.protocol,
            srcAddress: rule.srcAddress,
            dstAddress: rule.dstAddress,
            srcPort: rule.srcPort,
            dstPort: rule.dstPort,
            iface: rule.iface,
            profiles: [...(rule.profiles ?? ['Any'])],
            program: rule.program ?? '',
            enabled: rule.enabled !== false,
            group: prefix,
            simulated: true,
            appliedAt: new Date().toISOString(),
        });
        return { osName: name, applied: true, replaced: existed, simulated: true };
    }

    async removeRule(rule) {
        const name = rule.osRuleName || osRuleName(rule, getConfig().firewall.rulePrefix);
        const removed = this.shadow.delete(name);
        return { osName: name, removed, simulated: true };
    }

    async setEnabled(rule, enabled) {
        const name = rule.osRuleName || osRuleName(rule, getConfig().firewall.rulePrefix);
        const existing = this.shadow.get(name);
        if (!existing) {
            // Mirror the real providers: enabling an unapplied rule applies it.
            await this.applyRule({ ...rule, enabled });
            return { osName: name, enabled, created: true, simulated: true };
        }
        existing.enabled = !!enabled;
        existing.appliedAt = new Date().toISOString();
        return { osName: name, enabled: !!enabled, simulated: true };
    }

    /**
     * Show what the platform-appropriate provider would run. This is what makes
     * the simulator useful for learning: the preview is the real command.
     */
    translate(rule) {
        const native = process.platform === 'win32' ? translateWindows(rule) : translateLinux(rule);
        return {
            ...native,
            simulated: true,
            note: `Simulation mode: this command is shown for reference and is not executed. ${native.note ?? ''}`.trim(),
        };
    }

    async defaultPolicy() {
        const cfg = getConfig().firewall.defaultPolicy;
        return { inbound: cfg.inbound, outbound: cfg.outbound, source: 'sentryfw-config' };
    }

    /** Test/demo seam. */
    reset() {
        this.shadow.clear();
    }
}
