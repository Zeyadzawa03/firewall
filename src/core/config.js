/**
 * Configuration: shipped defaults <- runtime overrides <- environment.
 *
 * `config/default.json` is treated as read-only baseline. Operator changes made
 * in the GUI/CLI are persisted to `data/config.json` as a sparse override tree,
 * so upgrading the shipped defaults does not clobber local settings.
 *
 * Environment variables always win, which is what a service manager or a
 * container expects.
 */

import { PATHS, readJsonSync, writeJsonAtomic, ensureRuntimeDirs } from './paths.js';
import { ValidationError } from './errors.js';
import { validateEnum, validateInteger, validateBoolean } from './validate.js';

const ENV_MAP = Object.freeze({
    FWCTL_HOST: { path: 'server.host', type: 'string' },
    FWCTL_PORT: { path: 'server.port', type: 'int', min: 1, max: 65535 },
    FWCTL_REQUIRE_AUTH: { path: 'server.requireAuth', type: 'bool' },
    FWCTL_SESSION_TTL: { path: 'server.sessionTtlMinutes', type: 'int', min: 1, max: 10080 },
    FWCTL_PROVIDER: { path: 'firewall.provider', type: 'enum', values: ['simulated', 'windows', 'linux', 'auto'] },
    FWCTL_APPLY_TO_OS: { path: 'firewall.applyToOS', type: 'bool' },
    FWCTL_RULE_PREFIX: { path: 'firewall.rulePrefix', type: 'string' },
    FWCTL_LINUX_BACKEND: { path: 'firewall.linux.backend', type: 'enum', values: ['auto', 'iptables', 'nftables', 'ufw', 'firewalld'] },
    FWCTL_LOG_LEVEL: { path: 'logging.level', type: 'enum', values: ['debug', 'info', 'warn', 'error'] },
    FWCTL_LOG_CONSOLE: { path: 'logging.console', type: 'bool' },
    FWCTL_MONITOR: { path: 'monitoring.enabled', type: 'bool' },
    FWCTL_MONITOR_INTERVAL: { path: 'monitoring.intervalSeconds', type: 'int', min: 2, max: 3600 },
    FWCTL_DETECTION: { path: 'detection.enabled', type: 'bool' },
});

/** Settings an authenticated admin is allowed to change through the API. */
export const MUTABLE_SETTINGS = Object.freeze({
    'firewall.provider': { type: 'enum', values: ['simulated', 'windows', 'linux', 'auto'], restartRequired: true },
    'firewall.applyToOS': { type: 'bool', restartRequired: false },
    'firewall.rulePrefix': { type: 'string', maxLength: 24, restartRequired: false },
    'firewall.defaultPolicy.inbound': { type: 'enum', values: ['allow', 'deny'], restartRequired: false },
    'firewall.defaultPolicy.outbound': { type: 'enum', values: ['allow', 'deny'], restartRequired: false },
    'monitoring.enabled': { type: 'bool', restartRequired: false },
    'monitoring.intervalSeconds': { type: 'int', min: 2, max: 3600, restartRequired: false },
    'detection.enabled': { type: 'bool', restartRequired: false },
    'detection.portScan.enabled': { type: 'bool', restartRequired: false },
    'detection.portScan.distinctPorts': { type: 'int', min: 2, max: 1000, restartRequired: false },
    'detection.portScan.windowSeconds': { type: 'int', min: 5, max: 3600, restartRequired: false },
    'detection.connectionFlood.enabled': { type: 'bool', restartRequired: false },
    'detection.connectionFlood.connections': { type: 'int', min: 5, max: 100000, restartRequired: false },
    'detection.connectionFlood.windowSeconds': { type: 'int', min: 5, max: 3600, restartRequired: false },
    'detection.deniedBurst.enabled': { type: 'bool', restartRequired: false },
    'detection.deniedBurst.denies': { type: 'int', min: 2, max: 10000, restartRequired: false },
    'detection.beaconing.enabled': { type: 'bool', restartRequired: false },
    'detection.autoBlockOnScan': { type: 'bool', restartRequired: false },
    'logging.level': { type: 'enum', values: ['debug', 'info', 'warn', 'error'], restartRequired: false },
    'logging.logAllowed': { type: 'bool', restartRequired: false },
    'logging.logDenied': { type: 'bool', restartRequired: false },
    'blocklist.enabled': { type: 'bool', restartRequired: false },
    'security.requireConfirmForDestructive': { type: 'bool', restartRequired: false },
});

let cache = null;
let overrides = null;

function deepClone(v) {
    return v === undefined ? v : JSON.parse(JSON.stringify(v));
}

function isPlainObject(v) {
    return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function deepMerge(base, patch) {
    const out = deepClone(base) ?? {};
    for (const [k, v] of Object.entries(patch ?? {})) {
        if (isPlainObject(v) && isPlainObject(out[k])) out[k] = deepMerge(out[k], v);
        else out[k] = deepClone(v);
    }
    return out;
}

export function getAtPath(obj, dotted) {
    return dotted.split('.').reduce((acc, k) => (acc === undefined || acc === null ? undefined : acc[k]), obj);
}

export function setAtPath(obj, dotted, value) {
    const keys = dotted.split('.');
    let node = obj;
    for (const k of keys.slice(0, -1)) {
        if (!isPlainObject(node[k])) node[k] = {};
        node = node[k];
    }
    node[keys.at(-1)] = value;
    return obj;
}

function applyEnv(cfg) {
    for (const [envName, spec] of Object.entries(ENV_MAP)) {
        const raw = process.env[envName];
        if (raw === undefined || raw === '') continue;
        let value;
        switch (spec.type) {
            case 'int': value = validateInteger(raw, envName, { min: spec.min, max: spec.max }); break;
            case 'bool': value = validateBoolean(raw, envName); break;
            case 'enum': value = validateEnum(raw, envName, spec.values); break;
            default: value = String(raw).trim();
        }
        setAtPath(cfg, spec.path, value);
    }
    return cfg;
}

/** Load (and memoise) the effective configuration. */
export function loadConfig({ refresh = false } = {}) {
    if (cache && !refresh) return cache;
    const defaults = readJsonSync(PATHS.defaultConfig, null);
    if (!defaults) {
        throw new Error(`Missing shipped configuration: ${PATHS.defaultConfig}`);
    }
    delete defaults.$comment;
    overrides = readJsonSync(PATHS.runtimeConfig, {}) ?? {};
    cache = applyEnv(deepMerge(defaults, overrides));
    return cache;
}

export function getConfig() {
    return cache ?? loadConfig();
}

/** Sparse override tree currently persisted in data/config.json. */
export function getOverrides() {
    if (overrides === null) loadConfig();
    return deepClone(overrides);
}

function coerceSetting(key, spec, value) {
    switch (spec.type) {
        case 'int': return validateInteger(value, key, { min: spec.min, max: spec.max });
        case 'bool': return validateBoolean(value, key);
        case 'enum': return validateEnum(value, key, spec.values);
        case 'string': {
            const s = String(value ?? '').trim();
            if (spec.maxLength && s.length > spec.maxLength) {
                throw ValidationError.field(key, `must be at most ${spec.maxLength} characters`);
            }
            if (!/^[A-Za-z0-9_.\- ]*$/.test(s)) {
                throw ValidationError.field(key, 'may only contain letters, digits, space, underscore, dot and hyphen');
            }
            return s;
        }
        default:
            throw ValidationError.field(key, 'has an unsupported type');
    }
}

/**
 * Validate + persist a patch of settings. Only keys in MUTABLE_SETTINGS are
 * accepted; everything else is rejected rather than ignored.
 * Returns { applied, restartRequired }.
 */
export async function updateSettings(patch) {
    if (!isPlainObject(patch)) throw new ValidationError('Settings payload must be an object');
    const entries = Object.entries(patch);
    if (entries.length === 0) throw new ValidationError('No settings supplied');

    const unknown = entries.filter(([k]) => !MUTABLE_SETTINGS[k]).map(([k]) => k);
    if (unknown.length > 0) {
        throw new ValidationError(`Setting(s) not editable: ${unknown.join(', ')}`, unknown.map((f) => ({ field: f, message: 'not an editable setting' })));
    }

    ensureRuntimeDirs();
    const nextOverrides = deepClone(getOverrides());
    const applied = {};
    let restartRequired = false;

    for (const [key, rawValue] of entries) {
        const spec = MUTABLE_SETTINGS[key];
        const value = coerceSetting(key, spec, rawValue);
        setAtPath(nextOverrides, key, value);
        applied[key] = value;
        if (spec.restartRequired) restartRequired = true;
    }

    await writeJsonAtomic(PATHS.runtimeConfig, nextOverrides);
    overrides = nextOverrides;
    cache = applyEnv(deepMerge(stripComment(readJsonSync(PATHS.defaultConfig, {})), overrides));
    return { applied, restartRequired, config: getConfig() };
}

function stripComment(obj) {
    const c = deepClone(obj) ?? {};
    delete c.$comment;
    return c;
}

/** Public, non-sensitive view of the configuration for the GUI. */
export function publicConfig() {
    const c = getConfig();
    return {
        server: {
            host: c.server.host,
            port: c.server.port,
            requireAuth: c.server.requireAuth,
            sessionTtlMinutes: c.server.sessionTtlMinutes,
        },
        firewall: {
            provider: c.firewall.provider,
            applyToOS: c.firewall.applyToOS,
            defaultPolicy: { ...c.firewall.defaultPolicy },
            rulePrefix: c.firewall.rulePrefix,
            windows: { profiles: [...c.firewall.windows.profiles], policyStore: c.firewall.windows.policyStore },
            linux: { backend: c.firewall.linux.backend },
        },
        monitoring: { ...c.monitoring },
        detection: deepClone(c.detection),
        logging: {
            level: c.logging.level,
            logAllowed: c.logging.logAllowed,
            logDenied: c.logging.logDenied,
        },
        blocklist: { ...c.blocklist },
        security: {
            requireConfirmForDestructive: c.security.requireConfirmForDestructive,
            loginMaxAttempts: c.security.loginMaxAttempts,
        },
        editableSettings: Object.fromEntries(
            Object.entries(MUTABLE_SETTINGS).map(([k, v]) => [k, { ...v, current: getAtPath(c, k) }]),
        ),
    };
}

/** Test seam. */
export function __setConfigForTests(cfg) {
    cache = cfg;
    overrides = {};
}
