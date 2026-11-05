/**
 * Argument parser.
 *
 * Deliberately small and explicit: no dependency, no magic type coercion, and
 * unknown flags are an error rather than being silently ignored (a firewall tool
 * that quietly drops `--src` would be dangerous).
 *
 * Supports:
 *   --flag              -> true
 *   --flag=value        -> "value"
 *   --flag value        -> "value"
 *   --no-flag           -> false
 *   -abc                -> short flags, expanded via aliases
 *   --                  -> everything after is a positional
 */

import { ValidationError } from '../core/errors.js';

/**
 * @param {string[]} argv
 * @param {{ flags?:Record<string,{type:string, alias?:string, default?:any, help?:string, choices?:string[]}>, allowUnknown?:boolean }} spec
 */
export function parseArgs(argv, spec = {}) {
    const definitions = spec.flags ?? {};
    const aliases = {};
    for (const [name, def] of Object.entries(definitions)) {
        if (def.alias) aliases[def.alias] = name;
    }

    const flags = {};
    const positional = [];
    for (const [name, def] of Object.entries(definitions)) {
        if (def.default !== undefined) flags[name] = def.default;
        else if (def.type === 'boolean') flags[name] = false;
    }

    let i = 0;
    let passthrough = false;

    while (i < argv.length) {
        const token = argv[i];

        if (passthrough) {
            positional.push(token);
            i += 1;
            continue;
        }

        if (token === '--') {
            passthrough = true;
            i += 1;
            continue;
        }

        if (token.startsWith('--')) {
            let name = token.slice(2);
            let value = null;
            const eq = name.indexOf('=');
            if (eq !== -1) {
                value = name.slice(eq + 1);
                name = name.slice(0, eq);
            }

            let negated = false;
            if (name.startsWith('no-') && definitions[name.slice(3)]?.type === 'boolean') {
                negated = true;
                name = name.slice(3);
            }

            const camel = toCamel(name);
            const def = definitions[camel] ?? definitions[name];
            const key = definitions[camel] ? camel : name;

            if (!def) {
                if (spec.allowUnknown) {
                    flags[camel] = value === null ? true : value;
                    i += 1;
                    continue;
                }
                throw new ValidationError(`Unknown option: --${name}`, [{ field: name, message: 'not a recognised option' }]);
            }

            if (def.type === 'boolean') {
                if (value !== null) {
                    flags[key] = ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
                } else {
                    flags[key] = !negated;
                }
                i += 1;
                continue;
            }

            if (value === null) {
                value = argv[i + 1];
                if (value === undefined || (typeof value === 'string' && value.startsWith('--'))) {
                    throw new ValidationError(`Option --${name} requires a value`, [{ field: name, message: 'missing value' }]);
                }
                i += 1;
            }

            if (def.choices && !def.choices.includes(String(value))) {
                throw new ValidationError(
                    `Invalid value for --${name}: "${value}". Expected one of: ${def.choices.join(', ')}`,
                    [{ field: name, message: `must be one of: ${def.choices.join(', ')}` }],
                );
            }

            if (def.type === 'number') {
                const n = Number(value);
                if (!Number.isFinite(n)) {
                    throw new ValidationError(`Option --${name} must be a number`, [{ field: name, message: 'must be numeric' }]);
                }
                flags[key] = n;
            } else if (def.type === 'list') {
                const existing = Array.isArray(flags[key]) ? flags[key] : [];
                flags[key] = [...existing, ...String(value).split(',').map((s) => s.trim()).filter(Boolean)];
            } else {
                flags[key] = String(value);
            }
            i += 1;
            continue;
        }

        if (token.startsWith('-') && token.length > 1 && token !== '-') {
            const shorts = token.slice(1).split('');
            for (const [idx, ch] of shorts.entries()) {
                const name = aliases[ch];
                if (!name) {
                    throw new ValidationError(`Unknown option: -${ch}`, [{ field: ch, message: 'not a recognised short option' }]);
                }
                const def = definitions[name];
                if (def.type === 'boolean') {
                    flags[name] = true;
                    continue;
                }
                // A value-taking short flag must be last in the cluster.
                if (idx !== shorts.length - 1) {
                    throw new ValidationError(`Option -${ch} requires a value and must be last in "${token}"`);
                }
                const value = argv[i + 1];
                if (value === undefined || value.startsWith('-')) {
                    throw new ValidationError(`Option -${ch} requires a value`);
                }
                if (def.choices && !def.choices.includes(value)) {
                    throw new ValidationError(`Invalid value for -${ch}: "${value}". Expected one of: ${def.choices.join(', ')}`);
                }
                flags[name] = def.type === 'number' ? Number(value) : value;
                i += 1;
            }
            i += 1;
            continue;
        }

        positional.push(token);
        i += 1;
    }

    return { flags, positional };
}

function toCamel(name) {
    return name.replace(/-([a-z0-9])/g, (_m, ch) => ch.toUpperCase());
}

/** Render a flag spec as help text lines. */
export function formatFlags(definitions, indent = 4) {
    const rows = Object.entries(definitions)
        .filter(([, def]) => def.help)
        .map(([name, def]) => {
            const dashed = name.replace(/[A-Z]/g, (m) => `-${m.toLowerCase()}`);
            const left = `${def.alias ? `-${def.alias}, ` : '    '}--${dashed}${def.type && def.type !== 'boolean' ? ` <${def.type}>` : ''}`;
            return [left, def.help + (def.default !== undefined && def.default !== false ? ` (default: ${JSON.stringify(def.default)})` : '')];
        });
    if (rows.length === 0) return [];
    const width = Math.max(...rows.map(([left]) => left.length));
    const prefix = ' '.repeat(indent);
    return rows.map(([left, help]) => `${prefix}${left.padEnd(width)}  ${help}`);
}
