/**
 * Provider registry / factory.
 *
 * Keeps a single live provider instance so shadow state (simulated) and cached
 * probes (windows/linux) are not rebuilt on every request. `resolveProvider`
 * turns the configured value — including `auto` — into a concrete provider and
 * records the decision in the event log.
 */

import { SimulatedProvider } from './simulated.js';
import { WindowsProvider } from './windows.js';
import { LinuxProvider } from './linux.js';
import { getConfig } from '../../core/config.js';
import { logEvent } from '../../core/logger.js';
import { ValidationError } from '../../core/errors.js';

const CONSTRUCTORS = Object.freeze({
    simulated: SimulatedProvider,
    windows: WindowsProvider,
    linux: LinuxProvider,
});

export const PROVIDER_IDS = Object.freeze(Object.keys(CONSTRUCTORS));

let current = null;
let currentId = null;

/** Which provider does `auto` mean on this host? */
export function autoProviderId() {
    if (process.platform === 'win32') return 'windows';
    if (process.platform === 'linux') return 'linux';
    return 'simulated';
}

/**
 * Get (or build) the active provider.
 * @param {{ id?: string, refresh?: boolean }} [opts]
 */
export function getProvider({ id = null, refresh = false } = {}) {
    const configured = id ?? getConfig().firewall.provider ?? 'simulated';
    const resolved = configured === 'auto' ? autoProviderId() : configured;

    if (!CONSTRUCTORS[resolved]) {
        throw new ValidationError(`Unknown firewall provider: ${configured}`, [
            { field: 'firewall.provider', message: `must be one of: auto, ${PROVIDER_IDS.join(', ')}` },
        ]);
    }

    if (!refresh && current && currentId === resolved) return current;

    current = new CONSTRUCTORS[resolved]();
    currentId = resolved;
    logEvent({
        level: 'info', category: 'system', action: 'provider.select',
        message: `Firewall provider: ${current.label}${configured === 'auto' ? ' (auto-detected)' : ''}`,
        details: { requested: configured, resolved, capabilities: current.capabilities() },
    });
    return current;
}

/** Provider metadata for the GUI settings page. */
export async function describeProviders() {
    const out = [];
    for (const pid of PROVIDER_IDS) {
        const instance = pid === currentId && current ? current : new CONSTRUCTORS[pid]();
        let probe;
        try {
            probe = await instance.probe();
        } catch (err) {
            probe = { available: false, reason: err.message, elevated: false };
        }
        out.push({
            id: pid,
            label: instance.label,
            active: pid === currentId,
            capabilities: instance.capabilities(),
            probe,
        });
    }
    return out;
}

export function activeProviderId() {
    if (!current) getProvider();
    return currentId;
}

/** Test seam. */
export function __setProviderForTests(instance, id = 'test') {
    current = instance;
    currentId = id;
}

export function __resetProvider() {
    current = null;
    currentId = null;
}
