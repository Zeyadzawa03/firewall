/**
 * Application bootstrap.
 *
 * One place where subsystem start-up order is defined, used by both the server
 * and the CLI so they always initialise identically:
 *
 *   config → logging → audit chain → rule store → blocklist → provider
 *          → auth (server only) → monitor (optional)
 *
 * The rule store must exist before the blocklist, because a blocklist entry
 * creates backing firewall rules.
 */

import { loadConfig, getConfig } from './core/config.js';
import { ensureRuntimeDirs } from './core/paths.js';
import { logEvent, loadRecentFromDisk, logSync } from './core/logger.js';
import { initAudit } from './core/audit.js';
import { initRules, flushRules } from './firewall/rule-store.js';
import { initBlocklist, expireStale } from './monitoring/blocklist.js';
import { getProvider, activeProviderId } from './firewall/providers/index.js';
import { initAuth, stopAuth } from './core/auth.js';
import { monitor } from './monitoring/monitor.js';
import { platformInfo, isElevated, elevationHint } from './core/safe-exec.js';

let state = {
    started: false,
    flushTimer: null,
    expiryTimer: null,
    shutdownHandlers: [],
};

/**
 * @param {{ withAuth?:boolean, withMonitor?:boolean, loadHistory?:boolean, silent?:boolean }} [opts]
 */
export async function bootstrap({
    withAuth = false,
    withMonitor = false,
    loadHistory = true,
    silent = false,
} = {}) {
    if (state.started) return summary();

    ensureRuntimeDirs();
    const cfg = loadConfig({ refresh: true });

    if (loadHistory) {
        await loadRecentFromDisk(2000);
    }
    await initAudit();

    const ruleCount = await initRules();
    const blockCount = await initBlocklist();

    const provider = getProvider({ refresh: true });
    const probe = await provider.probe().catch((err) => ({ available: false, reason: err.message }));
    // Probing elevation spawns PowerShell on Windows (~1s), so only pay for it
    // when the answer matters: rules are about to be pushed into the OS.
    const elevated = cfg.firewall.applyToOS ? await isElevated() : null;

    if (!silent) {
        logEvent({
            level: 'info', category: 'system', action: 'app.start',
            message: `SentryFW starting — provider "${activeProviderId()}", ${ruleCount} rule(s), ${blockCount} blocklist entry/ies`,
            details: {
                platform: platformInfo(),
                provider: { id: activeProviderId(), label: provider.label, probe },
                applyToOS: cfg.firewall.applyToOS,
                elevated,
            },
        });
    }

    // Tell the operator plainly when rules will not reach the OS.
    if (cfg.firewall.applyToOS && !elevated && provider.capabilities().requiresElevation) {
        logEvent({
            level: 'warn', category: 'system', action: 'app.privilege_warning',
            message: `firewall.applyToOS is enabled but this process is not elevated, so rule changes cannot reach the ${provider.label}. ${elevationHint()}`,
        });
    }
    if (!cfg.firewall.applyToOS) {
        logEvent({
            level: 'info', category: 'system', action: 'app.simulation_notice',
            message: 'firewall.applyToOS is disabled: rules are stored and evaluated by SentryFW but are not written into the operating system firewall. Enable it in Settings when you are ready to enforce.',
        });
    }

    if (withAuth) {
        await initAuth({ silent });
    }

    if (withMonitor && cfg.monitoring.enabled !== false) {
        monitor.start();
    }

    // Periodic durability for hit counters, and blocklist TTL expiry.
    state.flushTimer = setInterval(() => {
        flushRules().catch(() => { /* logged by the store */ });
    }, 60_000);
    state.flushTimer.unref?.();

    state.expiryTimer = setInterval(() => {
        expireStale().catch(() => { /* logged by the blocklist */ });
    }, 300_000);
    state.expiryTimer.unref?.();

    state.started = true;
    return summary();
}

function summary() {
    const cfg = getConfig();
    return {
        provider: activeProviderId(),
        applyToOS: cfg.firewall.applyToOS,
        monitor: monitor.status().running,
        platform: process.platform,
    };
}

/** Register a callback to run during shutdown (e.g. server.stop). */
export function onShutdown(fn) {
    state.shutdownHandlers.push(fn);
}

export async function shutdown(reason = 'shutdown') {
    if (!state.started) return;
    logEvent({ level: 'info', category: 'system', action: 'app.stop', message: `SentryFW shutting down (${reason})` });

    monitor.stop();
    stopAuth();
    if (state.flushTimer) clearInterval(state.flushTimer);
    if (state.expiryTimer) clearInterval(state.expiryTimer);

    for (const fn of state.shutdownHandlers.reverse()) {
        try {
            await fn();
        } catch (err) {
            logEvent({ level: 'warn', category: 'error', action: 'app.shutdown_handler_failed', message: err.message });
        }
    }

    try {
        await flushRules();
    } catch { /* best effort */ }

    state.started = false;
    state.shutdownHandlers = [];
}

/** Install signal and crash handlers. Called by the CLI entry point. */
export function installProcessHandlers({ exitOnSignal = true } = {}) {
    const handle = (signal) => {
        process.on(signal, () => {
            shutdown(signal).finally(() => {
                if (exitOnSignal) process.exit(0);
            });
        });
    };
    handle('SIGINT');
    handle('SIGTERM');
    if (process.platform === 'win32') handle('SIGHUP');

    process.on('uncaughtException', (err) => {
        logSync({ category: 'error', message: `Uncaught exception: ${err.message}`, details: { stack: err.stack?.split('\n').slice(0, 8).join('\n') } });
        shutdown('uncaughtException').finally(() => process.exit(1));
    });

    process.on('unhandledRejection', (reason) => {
        const message = reason instanceof Error ? reason.message : String(reason);
        logSync({ category: 'error', message: `Unhandled promise rejection: ${message}` });
    });
}
