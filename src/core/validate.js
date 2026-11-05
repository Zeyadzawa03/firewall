/**
 * Input validation and normalisation.
 *
 * This module is the single trust boundary for every value that can reach an
 * OS firewall command. Nothing is passed to a provider before it goes through
 * here. Validators are strict allow-lists: they either return a normalised
 * value or throw a ValidationError. There is deliberately no "best effort"
 * coercion of unrecognised input.
 */

import { ValidationError } from './errors.js';

export const PROTOCOLS = Object.freeze(['tcp', 'udp', 'icmp', 'icmpv6', 'any']);
export const DIRECTIONS = Object.freeze(['inbound', 'outbound']);
export const ACTIONS = Object.freeze(['allow', 'deny']);
export const WINDOWS_PROFILES = Object.freeze(['Domain', 'Private', 'Public', 'Any']);

/** Protocols that carry port numbers. */
export const PORT_PROTOCOLS = Object.freeze(['tcp', 'udp']);

const MAX_STRING = 512;
const MAX_NAME = 96;
const MAX_DESCRIPTION = 400;

/**
 * Safe characters for free-text fields that may be embedded in an OS command
 * argument. Deliberately excludes: quotes, backticks, $ ; & | < > \ % ! ^ ( ) { }
 * newline and control characters. Anything outside this set is rejected rather
 * than silently stripped, so an operator cannot be surprised by a mangled rule
 * name that no longer matches what they typed.
 */
const SAFE_TEXT = /^[A-Za-z0-9 _.,:/#+\-[\]@]*$/;

/** Characters allowed in a rule name / identifier segment. */
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9 _.\-]*$/;

/** Detects shell / PowerShell metacharacters. Used as a defence-in-depth assertion. */
const DANGEROUS_CHARS = /[`$;&|<>"'\\\r\n\0%!^(){}*?~]/;

/* ------------------------------------------------------------------ *
 * Primitives
 * ------------------------------------------------------------------ */

export function assertNoShellMeta(value, field = 'value') {
    if (typeof value !== 'string') return;
    if (DANGEROUS_CHARS.test(value)) {
        throw ValidationError.field(field, 'contains characters that are not permitted in firewall parameters');
    }
    // eslint-disable-next-line no-control-regex
    if (/[\u0000-\u001f\u007f]/.test(value)) {
        throw ValidationError.field(field, 'contains control characters');
    }
}

export function validateString(value, field, { min = 0, max = MAX_STRING, pattern = SAFE_TEXT, optional = false, fallback = '' } = {}) {
    if (value === undefined || value === null || value === '') {
        if (optional) return fallback;
        throw ValidationError.field(field, 'is required');
    }
    if (typeof value !== 'string') throw ValidationError.field(field, 'must be a string');
    const trimmed = value.trim();
    if (trimmed.length < min) throw ValidationError.field(field, `must be at least ${min} characters`);
    if (trimmed.length > max) throw ValidationError.field(field, `must be at most ${max} characters`);
    if (pattern && !pattern.test(trimmed)) {
        throw ValidationError.field(field, 'contains unsupported characters (allowed: letters, digits, space, _ . , : / # + - [ ] @)');
    }
    assertNoShellMeta(trimmed, field);
    return trimmed;
}

export function validateEnum(value, field, allowed, { optional = false, fallback = null, caseInsensitive = true } = {}) {
    if (value === undefined || value === null || value === '') {
        if (optional) return fallback;
        throw ValidationError.field(field, `is required (one of: ${allowed.join(', ')})`);
    }
    if (typeof value !== 'string') throw ValidationError.field(field, 'must be a string');
    const needle = caseInsensitive ? value.trim().toLowerCase() : value.trim();
    const match = allowed.find((a) => (caseInsensitive ? a.toLowerCase() === needle : a === needle));
    if (!match) throw ValidationError.field(field, `must be one of: ${allowed.join(', ')}`);
    return match;
}

export function validateBoolean(value, field, { optional = false, fallback = false } = {}) {
    if (value === undefined || value === null || value === '') {
        if (optional) return fallback;
        throw ValidationError.field(field, 'is required');
    }
    if (typeof value === 'boolean') return value;
    if (value === 'true' || value === 1 || value === '1') return true;
    if (value === 'false' || value === 0 || value === '0') return false;
    throw ValidationError.field(field, 'must be a boolean');
}

export function validateInteger(value, field, { min = -Infinity, max = Infinity, optional = false, fallback = null } = {}) {
    if (value === undefined || value === null || value === '') {
        if (optional) return fallback;
        throw ValidationError.field(field, 'is required');
    }
    const n = typeof value === 'number' ? value : Number(String(value).trim());
    if (!Number.isFinite(n) || !Number.isInteger(n)) throw ValidationError.field(field, 'must be an integer');
    if (n < min || n > max) throw ValidationError.field(field, `must be between ${min} and ${max}`);
    return n;
}

/* ------------------------------------------------------------------ *
 * IP addresses / CIDR / ranges
 * ------------------------------------------------------------------ */

/** Strict dotted-quad IPv4, no leading zeros, no shorthand. */
export function isIPv4(value) {
    if (typeof value !== 'string') return false;
    const parts = value.split('.');
    if (parts.length !== 4) return false;
    return parts.every((p) => /^(0|[1-9]\d{0,2})$/.test(p) && Number(p) <= 255);
}

/** IPv6 including compressed form and IPv4-mapped tail. */
export function isIPv6(value) {
    if (typeof value !== 'string' || value.length === 0 || value.length > 45) return false;
    if (!/^[0-9A-Fa-f:.]+$/.test(value)) return false;
    if ((value.match(/::/g) || []).length > 1) return false;

    let work = value;
    let embeddedV4 = 0;
    const lastColon = work.lastIndexOf(':');
    const tail = work.slice(lastColon + 1);
    if (tail.includes('.')) {
        if (!isIPv4(tail)) return false;
        work = work.slice(0, lastColon + 1) + '0:0';
        embeddedV4 = 0; // already accounted for by the two groups above
    }
    if (work.includes('.')) return false;

    const hasCompression = work.includes('::');
    const [head, rest] = hasCompression ? work.split('::') : [work, null];
    const headGroups = head === '' ? [] : head.split(':');
    const tailGroups = rest === undefined || rest === null || rest === '' ? [] : rest.split(':');
    const groups = [...headGroups, ...tailGroups];
    if (groups.some((g) => g === '' || !/^[0-9A-Fa-f]{1,4}$/.test(g))) return false;
    const total = groups.length + embeddedV4;
    return hasCompression ? total <= 7 : total === 8;
}

export function ipFamily(value) {
    if (isIPv4(value)) return 'ipv4';
    if (isIPv6(value)) return 'ipv6';
    return null;
}

export function validateIP(value, field = 'ip') {
    const raw = validateString(value, field, { max: 45, pattern: /^[0-9A-Fa-f:.]+$/ });
    const family = ipFamily(raw);
    if (!family) throw ValidationError.field(field, 'must be a valid IPv4 or IPv6 address');
    return raw;
}

export function validateCIDR(value, field = 'cidr') {
    const raw = validateString(value, field, { max: 49, pattern: /^[0-9A-Fa-f:./]+$/ });
    const slash = raw.indexOf('/');
    if (slash === -1) throw ValidationError.field(field, 'must include a prefix length, e.g. 10.0.0.0/8');
    const addr = raw.slice(0, slash);
    const prefixText = raw.slice(slash + 1);
    const family = ipFamily(addr);
    if (!family) throw ValidationError.field(field, 'network part must be a valid IP address');
    if (!/^\d{1,3}$/.test(prefixText)) throw ValidationError.field(field, 'prefix length must be numeric');
    const prefix = Number(prefixText);
    const maxPrefix = family === 'ipv4' ? 32 : 128;
    if (prefix < 0 || prefix > maxPrefix) throw ValidationError.field(field, `prefix length must be 0-${maxPrefix}`);
    return `${addr}/${prefix}`;
}

/**
 * Address specification for a rule endpoint. Accepts:
 *   "any" | single IP | CIDR | "a.b.c.d-e.f.g.h" range | comma-separated list.
 * Returns a normalised, de-duplicated string.
 */
export function validateAddressSpec(value, field = 'address') {
    if (value === undefined || value === null || value === '' || value === '*') return 'any';
    const raw = validateString(value, field, { max: 400, pattern: /^[0-9A-Fa-f:./,\- a-zA-Z]+$/ });
    if (raw.toLowerCase() === 'any') return 'any';

    const tokens = raw.split(',').map((t) => t.trim()).filter(Boolean);
    if (tokens.length === 0) throw ValidationError.field(field, 'must not be empty');
    if (tokens.length > 32) throw ValidationError.field(field, 'may not contain more than 32 entries');

    const normalised = tokens.map((token) => {
        if (token.toLowerCase() === 'any') {
            throw ValidationError.field(field, '"any" cannot be combined with specific addresses');
        }
        if (token.includes('/')) return validateCIDR(token, field);
        if (token.includes('-')) {
            const [from, to] = token.split('-').map((s) => s.trim());
            const a = validateIP(from, `${field} range start`);
            const b = validateIP(to, `${field} range end`);
            if (ipFamily(a) !== ipFamily(b)) {
                throw ValidationError.field(field, 'range endpoints must be the same address family');
            }
            if (ipFamily(a) === 'ipv4' && ipv4ToInt(a) > ipv4ToInt(b)) {
                throw ValidationError.field(field, 'range start must not be greater than range end');
            }
            return `${a}-${b}`;
        }
        return validateIP(token, field);
    });

    return [...new Set(normalised)].join(',');
}

export function ipv4ToInt(ip) {
    return ip.split('.').reduce((acc, part) => acc * 256 + Number(part), 0);
}

export function intToIPv4(n) {
    return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

/** True when `ip` falls inside a single address / CIDR / range token. */
export function ipMatchesToken(ip, token) {
    if (!token || token === 'any') return true;
    const family = ipFamily(ip);
    if (!family) return false;

    if (token.includes('/')) {
        const [net, prefixText] = token.split('/');
        const prefix = Number(prefixText);
        if (ipFamily(net) !== family) return false;
        if (family === 'ipv4') {
            if (prefix === 0) return true;
            const mask = prefix === 32 ? 0xffffffff : (0xffffffff << (32 - prefix)) >>> 0;
            return (ipv4ToInt(ip) & mask) === (ipv4ToInt(net) & mask);
        }
        return ipv6PrefixMatch(ip, net, prefix);
    }

    if (token.includes('-')) {
        const [from, to] = token.split('-');
        if (family !== 'ipv4' || ipFamily(from) !== 'ipv4' || ipFamily(to) !== 'ipv4') {
            return ip === from.trim() || ip === to.trim();
        }
        const n = ipv4ToInt(ip);
        return n >= ipv4ToInt(from.trim()) && n <= ipv4ToInt(to.trim());
    }

    if (family === 'ipv6') return normaliseIPv6(ip) === normaliseIPv6(token);
    return ip === token;
}

/** True when `ip` matches any token of an address spec. */
export function ipMatchesSpec(ip, spec) {
    if (!spec || spec === 'any') return true;
    return spec.split(',').some((token) => ipMatchesToken(ip, token.trim()));
}

export function normaliseIPv6(value) {
    if (!isIPv6(value)) return value;
    const groups = expandIPv6(value);
    return groups.map((g) => g.replace(/^0+(?=.)/, '').toLowerCase()).join(':');
}

function expandIPv6(value) {
    let work = value;
    const lastColon = work.lastIndexOf(':');
    const tail = work.slice(lastColon + 1);
    if (tail.includes('.') && isIPv4(tail)) {
        const [a, b, c, d] = tail.split('.').map(Number);
        const hex1 = ((a << 8) | b).toString(16).padStart(4, '0');
        const hex2 = ((c << 8) | d).toString(16).padStart(4, '0');
        work = `${work.slice(0, lastColon + 1)}${hex1}:${hex2}`;
    }
    if (work.includes('::')) {
        const [head, rest] = work.split('::');
        const headGroups = head ? head.split(':') : [];
        const tailGroups = rest ? rest.split(':') : [];
        const missing = 8 - headGroups.length - tailGroups.length;
        return [...headGroups, ...Array(Math.max(0, missing)).fill('0'), ...tailGroups].map((g) => g.padStart(4, '0'));
    }
    return work.split(':').map((g) => g.padStart(4, '0'));
}

function ipv6PrefixMatch(ip, net, prefix) {
    const a = expandIPv6(ip).map((g) => parseInt(g, 16));
    const b = expandIPv6(net).map((g) => parseInt(g, 16));
    let bits = prefix;
    for (let i = 0; i < 8 && bits > 0; i++) {
        const take = Math.min(16, bits);
        const mask = take === 16 ? 0xffff : (0xffff << (16 - take)) & 0xffff;
        if ((a[i] & mask) !== (b[i] & mask)) return false;
        bits -= take;
    }
    return true;
}

/** RFC1918 / loopback / link-local / CGNAT check, used by detection heuristics. */
export function isPrivateIP(ip) {
    if (isIPv4(ip)) {
        const n = ipv4ToInt(ip);
        const inRange = (from, to) => n >= ipv4ToInt(from) && n <= ipv4ToInt(to);
        return (
            inRange('10.0.0.0', '10.255.255.255') ||
            inRange('172.16.0.0', '172.31.255.255') ||
            inRange('192.168.0.0', '192.168.255.255') ||
            inRange('127.0.0.0', '127.255.255.255') ||
            inRange('169.254.0.0', '169.254.255.255') ||
            inRange('100.64.0.0', '100.127.255.255') ||
            inRange('0.0.0.0', '0.255.255.255')
        );
    }
    if (isIPv6(ip)) {
        const norm = normaliseIPv6(ip);
        return norm === '::1' || norm === '::' || /^f[cd]/.test(norm) || /^fe8/.test(norm);
    }
    return false;
}

/* ------------------------------------------------------------------ *
 * Ports
 * ------------------------------------------------------------------ */

/** A port in a rule: 0 is not addressable and every OS backend rejects it. */
export function validatePort(value, field = 'port') {
    return validateInteger(value, field, { min: 1, max: 65535 });
}

/**
 * Port specification. Accepts:
 *   "any" | "443" | "8000-8100" | "80,443,8080-8090"
 * Returns a normalised string. Ranges are validated for ordering.
 */
export function validatePortSpec(value, field = 'port') {
    if (value === undefined || value === null || value === '' || value === '*') return 'any';
    const raw = validateString(value, field, { max: 200, pattern: /^[0-9,\-a-zA-Z ]+$/ });
    if (raw.toLowerCase() === 'any') return 'any';

    const tokens = raw.split(',').map((t) => t.trim()).filter(Boolean);
    if (tokens.length === 0) throw ValidationError.field(field, 'must not be empty');
    if (tokens.length > 32) throw ValidationError.field(field, 'may not contain more than 32 entries');

    const normalised = tokens.map((token) => {
        if (token.toLowerCase() === 'any') {
            throw ValidationError.field(field, '"any" cannot be combined with specific ports');
        }
        if (token.includes('-')) {
            const parts = token.split('-');
            if (parts.length !== 2) throw ValidationError.field(field, 'range must be written as start-end');
            const from = validatePort(parts[0], `${field} range start`);
            const to = validatePort(parts[1], `${field} range end`);
            if (from > to) throw ValidationError.field(field, 'range start must not be greater than range end');
            return from === to ? String(from) : `${from}-${to}`;
        }
        return String(validatePort(token, field));
    });

    return [...new Set(normalised)].join(',');
}

/** True when a numeric port matches a port spec. */
export function portMatchesSpec(port, spec) {
    if (!spec || spec === 'any') return true;
    const n = Number(port);
    if (!Number.isFinite(n)) return false;
    return spec.split(',').some((token) => {
        const t = token.trim();
        if (t.includes('-')) {
            const [a, b] = t.split('-').map(Number);
            return n >= a && n <= b;
        }
        return n === Number(t);
    });
}

/** Expand a port spec into individual ports, bounded to avoid memory blowups. */
export function expandPortSpec(spec, limit = 4096) {
    if (!spec || spec === 'any') return [];
    const out = [];
    for (const token of spec.split(',')) {
        const t = token.trim();
        if (t.includes('-')) {
            const [a, b] = t.split('-').map(Number);
            for (let p = a; p <= b && out.length < limit; p++) out.push(p);
        } else if (out.length < limit) {
            out.push(Number(t));
        }
    }
    return out;
}

/* ------------------------------------------------------------------ *
 * Rule-level fields
 * ------------------------------------------------------------------ */

export function validateProtocol(value, field = 'protocol') {
    return validateEnum(value, field, PROTOCOLS, { optional: true, fallback: 'any' });
}

export function validateDirection(value, field = 'direction') {
    return validateEnum(value, field, DIRECTIONS, { optional: true, fallback: 'inbound' });
}

export function validateAction(value, field = 'action') {
    return validateEnum(value, field, ACTIONS, { optional: true, fallback: 'deny' });
}

export function validateRuleName(value, field = 'name') {
    const name = validateString(value, field, { min: 1, max: MAX_NAME, pattern: SAFE_NAME });
    if (/^[-.\s]/.test(name)) throw ValidationError.field(field, 'must start with a letter or digit');
    return name;
}

export function validateDescription(value, field = 'description') {
    return validateString(value, field, { max: MAX_DESCRIPTION, optional: true, fallback: '' });
}

export function validateInterface(value, field = 'iface') {
    if (value === undefined || value === null || value === '' || String(value).toLowerCase() === 'any') return 'any';
    return validateString(value, field, { max: 64, pattern: /^[A-Za-z0-9][A-Za-z0-9 _.\-#()]*$/ });
}

export function validatePriority(value, field = 'priority') {
    return validateInteger(value, field, { min: 1, max: 65535, optional: true, fallback: 100 });
}

export function validateProfiles(value, field = 'profiles') {
    if (value === undefined || value === null || value === '') return ['Any'];
    const list = Array.isArray(value) ? value : String(value).split(',');
    const out = list
        .map((p) => String(p).trim())
        .filter(Boolean)
        .map((p) => validateEnum(p, field, WINDOWS_PROFILES, { caseInsensitive: true }));
    if (out.length === 0) return ['Any'];
    return out.includes('Any') ? ['Any'] : [...new Set(out)];
}

/**
 * Full rule payload validation. `partial` mode is used for PATCH: only the
 * supplied keys are validated, and defaults are not injected.
 */
export function validateRuleInput(input, { partial = false } = {}) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
        throw new ValidationError('Rule payload must be an object');
    }

    const known = new Set([
        'name', 'description', 'direction', 'action', 'protocol',
        'srcAddress', 'dstAddress', 'srcPort', 'dstPort',
        'iface', 'priority', 'enabled', 'profiles', 'tags', 'program',
    ]);
    const unknown = Object.keys(input).filter((k) => !known.has(k));
    if (unknown.length > 0) {
        throw new ValidationError(
            `Unknown rule field(s): ${unknown.join(', ')}`,
            unknown.map((f) => ({ field: f, message: 'not a recognised rule field' })),
        );
    }

    const out = {};
    const has = (k) => Object.prototype.hasOwnProperty.call(input, k);
    const want = (k) => (partial ? has(k) : true);

    if (want('name')) out.name = validateRuleName(input.name);
    if (want('description')) out.description = validateDescription(input.description);
    if (want('direction')) out.direction = validateDirection(input.direction);
    if (want('action')) out.action = validateAction(input.action);
    if (want('protocol')) out.protocol = validateProtocol(input.protocol);
    if (want('srcAddress')) out.srcAddress = validateAddressSpec(input.srcAddress, 'srcAddress');
    if (want('dstAddress')) out.dstAddress = validateAddressSpec(input.dstAddress, 'dstAddress');
    if (want('srcPort')) out.srcPort = validatePortSpec(input.srcPort, 'srcPort');
    if (want('dstPort')) out.dstPort = validatePortSpec(input.dstPort, 'dstPort');
    if (want('iface')) out.iface = validateInterface(input.iface);
    if (want('priority')) out.priority = validatePriority(input.priority);
    if (want('enabled')) out.enabled = validateBoolean(input.enabled, 'enabled', { optional: true, fallback: true });
    if (want('profiles')) out.profiles = validateProfiles(input.profiles);
    if (want('program')) out.program = validateProgramPath(input.program);
    if (want('tags')) out.tags = validateTags(input.tags);

    // Cross-field rules: ports only make sense for TCP/UDP.
    const protocol = out.protocol ?? null;
    const portsGiven = [out.srcPort, out.dstPort].some((p) => p && p !== 'any');
    if (protocol && !PORT_PROTOCOLS.includes(protocol) && portsGiven) {
        throw new ValidationError('Ports may only be specified for TCP or UDP rules', [
            { field: 'protocol', message: `protocol "${protocol}" does not carry ports` },
        ]);
    }

    return out;
}

export function validateTags(value, field = 'tags') {
    if (value === undefined || value === null || value === '') return [];
    const list = Array.isArray(value) ? value : String(value).split(',');
    const out = list
        .map((t) => String(t).trim())
        .filter(Boolean)
        .map((t) => validateString(t, field, { max: 32, pattern: /^[A-Za-z0-9_.\-]+$/ }));
    if (out.length > 16) throw ValidationError.field(field, 'may not contain more than 16 tags');
    return [...new Set(out)];
}

/**
 * Program path for application-scoped rules. Windows and POSIX absolute paths
 * only; no wildcards, no environment expansion, no shell metacharacters.
 */
export function validateProgramPath(value, field = 'program') {
    if (value === undefined || value === null || value === '') return '';
    if (typeof value !== 'string') throw ValidationError.field(field, 'must be a string');
    const p = value.trim();
    if (p.length > 260) throw ValidationError.field(field, 'must be at most 260 characters');
    assertNoShellMeta(p, field);
    const windowsAbs = /^[A-Za-z]:[\\/][^\\/:*?"<>|]*(?:[\\/][^\\/:*?"<>|]+)*$/;
    const posixAbs = /^\/[^\0]*$/;
    if (!windowsAbs.test(p) && !posixAbs.test(p)) {
        throw ValidationError.field(field, 'must be an absolute path without wildcards');
    }
    return p;
}

/* ------------------------------------------------------------------ *
 * Misc
 * ------------------------------------------------------------------ */

export function validateId(value, field = 'id') {
    return validateString(value, field, { min: 4, max: 64, pattern: /^[A-Za-z0-9_-]+$/ });
}

export function validateUsername(value, field = 'username') {
    const u = validateString(value, field, { min: 2, max: 32, pattern: /^[A-Za-z0-9][A-Za-z0-9_.\-]*$/ });
    return u.toLowerCase();
}

export function validatePassword(value, field = 'password') {
    if (typeof value !== 'string') throw ValidationError.field(field, 'must be a string');
    if (value.length < 10) throw ValidationError.field(field, 'must be at least 10 characters');
    if (value.length > 200) throw ValidationError.field(field, 'must be at most 200 characters');
    const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(value)).length;
    if (classes < 3) {
        throw ValidationError.field(field, 'must contain at least three of: lowercase, uppercase, digit, symbol');
    }
    return value;
}

export function validateISODate(value, field = 'date') {
    if (value === undefined || value === null || value === '') return null;
    const s = String(value).trim();
    const t = Date.parse(s);
    if (Number.isNaN(t)) throw ValidationError.field(field, 'must be an ISO-8601 date/time');
    return new Date(t).toISOString();
}
