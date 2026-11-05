/**
 * Terminal output helpers: colour, tables, key/value blocks, spinners-free
 * status lines. Colour is disabled automatically when stdout is not a TTY or
 * when NO_COLOR / FWCTL_NO_COLOR is set, so piped output stays parseable.
 */

const useColor = (() => {
    if (process.env.NO_COLOR !== undefined || process.env.FWCTL_NO_COLOR !== undefined) return false;
    if (process.env.FORCE_COLOR !== undefined) return true;
    return !!process.stdout.isTTY;
})();

const CODES = {
    reset: 0, bold: 1, dim: 2, italic: 3, underline: 4,
    red: 31, green: 32, yellow: 33, blue: 34, magenta: 35, cyan: 36, white: 37, gray: 90,
    bgRed: 41, bgGreen: 42, bgYellow: 43,
};

function wrap(code, text) {
    if (!useColor) return String(text);
    return `\u001b[${code}m${text}\u001b[0m`;
}

export const c = {
    bold: (t) => wrap(CODES.bold, t),
    dim: (t) => wrap(CODES.dim, t),
    underline: (t) => wrap(CODES.underline, t),
    red: (t) => wrap(CODES.red, t),
    green: (t) => wrap(CODES.green, t),
    yellow: (t) => wrap(CODES.yellow, t),
    blue: (t) => wrap(CODES.blue, t),
    magenta: (t) => wrap(CODES.magenta, t),
    cyan: (t) => wrap(CODES.cyan, t),
    gray: (t) => wrap(CODES.gray, t),
    enabled: useColor,
};

export function out(text = '') {
    process.stdout.write(`${text}\n`);
}

export function err(text = '') {
    process.stderr.write(`${text}\n`);
}

export function heading(text) {
    out('');
    out(c.bold(text));
    out(c.dim('─'.repeat(Math.min(80, Math.max(8, visibleLength(text))))));
}

export function ok(text) {
    out(`${c.green('✓')} ${text}`);
}

export function warn(text) {
    out(`${c.yellow('!')} ${text}`);
}

export function fail(text) {
    err(`${c.red('✗')} ${text}`);
}

export function info(text) {
    out(`${c.blue('·')} ${text}`);
}

export function note(text) {
    out(c.dim(`  ${text}`));
}

/** Strip ANSI so padding maths stays correct. */
export function visibleLength(text) {
    // eslint-disable-next-line no-control-regex
    return String(text).replace(/\u001b\[[0-9;]*m/g, '').length;
}

function pad(text, width, align = 'left') {
    const len = visibleLength(text);
    if (len >= width) return String(text);
    const filler = ' '.repeat(width - len);
    return align === 'right' ? `${filler}${text}` : `${text}${filler}`;
}

/**
 * Render a table.
 * @param {Array<{key:string, label:string, align?:string, format?:Function, width?:number}>} columns
 * @param {Array<object>} rows
 */
export function table(columns, rows, { empty = 'No rows.' } = {}) {
    if (!rows || rows.length === 0) {
        out(c.dim(`  ${empty}`));
        return;
    }

    const cells = rows.map((row) => columns.map((col) => {
        const raw = col.format ? col.format(row[col.key], row) : row[col.key];
        return raw === null || raw === undefined ? '' : String(raw);
    }));

    const widths = columns.map((col, i) => {
        const max = Math.max(visibleLength(col.label), ...cells.map((r) => visibleLength(r[i])));
        return col.width ? Math.min(col.width, max) : max;
    });

    out(`  ${columns.map((col, i) => c.bold(pad(col.label, widths[i], col.align))).join('  ')}`);
    out(`  ${widths.map((w) => c.dim('─'.repeat(w))).join('  ')}`);
    for (const row of cells) {
        out(`  ${row.map((cell, i) => pad(truncate(cell, widths[i]), widths[i], columns[i].align)).join('  ')}`);
    }
    out(c.dim(`  ${rows.length} row(s)`));
}

function truncate(text, width) {
    const len = visibleLength(text);
    if (len <= width) return text;
    if (width <= 1) return '…';
    return `${String(text).slice(0, width - 1)}…`;
}

/** Aligned key/value block. */
export function kv(pairs, { indent = 2 } = {}) {
    const entries = Array.isArray(pairs) ? pairs : Object.entries(pairs);
    const width = Math.max(0, ...entries.map(([k]) => visibleLength(k)));
    const prefix = ' '.repeat(indent);
    for (const [key, value] of entries) {
        if (value === undefined) continue;
        out(`${prefix}${c.dim(pad(`${key}`, width))}  ${formatValue(value)}`);
    }
}

function formatValue(value) {
    if (value === null) return c.dim('—');
    if (typeof value === 'boolean') return value ? c.green('yes') : c.dim('no');
    if (Array.isArray(value)) return value.length ? value.join(', ') : c.dim('—');
    if (typeof value === 'object') return JSON.stringify(value);
    if (value === '') return c.dim('—');
    return String(value);
}

/* ------------------------------------------------------------------ *
 * Domain-specific formatting
 * ------------------------------------------------------------------ */

export function actionBadge(action) {
    return action === 'allow' ? c.green('ALLOW') : c.red('DENY ');
}

export function enabledBadge(enabled) {
    return enabled ? c.green('on ') : c.dim('off');
}

export function appliedBadge(rule) {
    if (rule.osLastError) return c.red('error');
    if (rule.osApplied) return c.green('os');
    return c.dim('pending');
}

export function severityBadge(severity) {
    switch (severity) {
        case 'critical': return c.red(c.bold('CRIT'));
        case 'high': return c.red('HIGH');
        case 'medium': return c.yellow('MED ');
        default: return c.dim('LOW ');
    }
}

export function levelBadge(level) {
    switch (level) {
        case 'critical': return c.red(c.bold('CRT'));
        case 'error': return c.red('ERR');
        case 'warn': return c.yellow('WRN');
        case 'info': return c.blue('INF');
        default: return c.dim('DBG');
    }
}

export function shortTime(iso) {
    if (!iso) return '';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return String(iso);
    return d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z');
}

export function relativeTime(iso) {
    if (!iso) return '';
    const ms = Date.now() - Date.parse(iso);
    if (!Number.isFinite(ms)) return String(iso);
    const s = Math.round(ms / 1000);
    if (s < 60) return `${s}s ago`;
    const m = Math.round(s / 60);
    if (m < 60) return `${m}m ago`;
    const h = Math.round(m / 60);
    if (h < 48) return `${h}h ago`;
    return `${Math.round(h / 24)}d ago`;
}

export function bytes(n) {
    const value = Number(n) || 0;
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    let v = value;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
    return `${i === 0 ? v : v.toFixed(1)} ${units[i]}`;
}

/** Simple horizontal bar for CLI charts. */
export function bar(value, max, width = 24) {
    const ratio = max > 0 ? Math.min(1, value / max) : 0;
    const filled = Math.round(ratio * width);
    return `${'█'.repeat(filled)}${c.dim('░'.repeat(width - filled))}`;
}

/** Print JSON when --json was requested. Returns true when it handled output. */
export function maybeJson(flags, payload) {
    if (!flags.json) return false;
    out(JSON.stringify(payload, null, flags.compact ? 0 : 2));
    return true;
}
