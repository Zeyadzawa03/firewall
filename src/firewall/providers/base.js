/**
 * Provider contract.
 *
 * A provider is the only component allowed to touch an OS firewall. Every method
 * receives already-validated canonical rules (src/firewall/rule-model.js) and is
 * responsible for translating them into native form.
 *
 * Contract:
 *   id                 -> stable identifier ('simulated' | 'windows' | 'linux')
 *   label              -> human name for the GUI
 *   capabilities()     -> what this provider can actually do here and now
 *   probe()            -> health/permission check, cheap, never throws for
 *                         "not available"; returns { available, reason, ... }
 *   listNative(opts)   -> rules as they exist in the OS
 *   applyRule(rule)    -> create/replace the OS rule for a canonical rule
 *   removeRule(rule)   -> delete the OS rule
 *   setEnabled(rule,b) -> enable/disable without changing match criteria
 *   translate(rule)    -> the native command/parameters, for preview + docs
 *   defaultPolicy()    -> current OS default inbound/outbound behaviour
 */

import { UnsupportedError } from '../../core/errors.js';

export class FirewallProvider {
    /** @type {string} */
    static id = 'abstract';

    get id() {
        return this.constructor.id;
    }

    get label() {
        return 'Abstract provider';
    }

    /**
     * @returns {{
     *   read:boolean, write:boolean, enableDisable:boolean, interfaces:boolean,
     *   profiles:boolean, programRules:boolean, priorities:boolean,
     *   requiresElevation:boolean, notes:string[]
     * }}
     */
    capabilities() {
        return {
            read: false,
            write: false,
            enableDisable: false,
            interfaces: false,
            profiles: false,
            programRules: false,
            priorities: false,
            requiresElevation: false,
            notes: [],
        };
    }

    async probe() {
        return { available: false, reason: 'not implemented', elevated: false };
    }

    async listNative() {
        throw new UnsupportedError(`${this.id} provider cannot list OS rules`);
    }

    async applyRule() {
        throw new UnsupportedError(`${this.id} provider cannot apply OS rules`);
    }

    async removeRule() {
        throw new UnsupportedError(`${this.id} provider cannot remove OS rules`);
    }

    async setEnabled() {
        throw new UnsupportedError(`${this.id} provider cannot change OS rule state`);
    }

    /** Native representation of a rule, shown in the GUI "Preview" panel. */
    translate() {
        return { kind: 'none', lines: [], note: 'This provider has no native representation.' };
    }

    async defaultPolicy() {
        return { inbound: null, outbound: null, source: 'unknown' };
    }
}
