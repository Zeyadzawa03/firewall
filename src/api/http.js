/**
 * Tiny HTTP router + request/response helpers.
 *
 * No web framework is used: the API surface is small, and adding Express-style
 * dependencies to a security tool means adding transitive supply-chain risk for
 * no functional gain. This file provides the pieces a framework would: pattern
 * routing, JSON body parsing with a hard size cap, cookies, security headers and
 * a consistent error envelope.
 */

import { AppError, ValidationError, toAppError } from '../core/errors.js';
import { logEvent } from '../core/logger.js';

export class Router {
    constructor() {
        /** @type {Array<{method:string, path:string, pattern:RegExp, keys:string[], handler:Function, meta:object}>} */
        this.routes = [];
    }

    /**
     * @param {string} method
     * @param {string} path  e.g. '/api/rules/:id/enable'
     * @param {Function} handler async (ctx) => body | undefined
     * @param {object} [meta] { permission, csrf, auth }
     */
    add(method, path, handler, meta = {}) {
        const keys = [];
        // Build segment by segment: `:name` segments capture, everything else is
        // matched literally. (Escaping the whole path first and then searching
        // for "/:" never matched, so every parameterised route 404'd.)
        const source = path
            .replace(/\/+$/, '')
            .split('/')
            .map((segment) => {
                const param = /^:([A-Za-z_][A-Za-z0-9_]*)$/.exec(segment);
                if (param) {
                    keys.push(param[1]);
                    return '([^/]+)';
                }
                return segment.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            })
            .join('\\/');
        const pattern = new RegExp(`^${source}\\/?$`);
        this.routes.push({ method: method.toUpperCase(), path: path.replace(/\/+$/, '') || '/', pattern, keys, handler, meta });
        return this;
    }

    get(path, handler, meta) { return this.add('GET', path, handler, meta); }
    post(path, handler, meta) { return this.add('POST', path, handler, meta); }
    patch(path, handler, meta) { return this.add('PATCH', path, handler, meta); }
    put(path, handler, meta) { return this.add('PUT', path, handler, meta); }
    delete(path, handler, meta) { return this.add('DELETE', path, handler, meta); }

    /** Find a route; returns { route, params } or { allowed } when only the method mismatched. */
    match(method, pathname) {
        const clean = pathname.replace(/\/+$/, '') || '/';
        const allowed = new Set();
        for (const route of this.routes) {
            const m = route.pattern.exec(clean);
            if (!m) continue;
            if (route.method !== method.toUpperCase()) {
                allowed.add(route.method);
                continue;
            }
            const params = {};
            route.keys.forEach((key, i) => { params[key] = decodeURIComponent(m[i + 1]); });
            return { route, params };
        }
        return allowed.size > 0 ? { allowed: [...allowed] } : null;
    }

    /** Route inventory, used by GET /api and the docs. */
    describe() {
        return this.routes.map((r) => ({
            method: r.method,
            path: r.path,
            permission: r.meta.permission ?? null,
            auth: r.meta.auth !== false,
        }));
    }
}

/* ------------------------------------------------------------------ *
 * Body parsing
 * ------------------------------------------------------------------ */

/**
 * Read and JSON-parse a request body with a hard byte cap. Oversized bodies are
 * rejected before buffering more than the limit, so a large upload cannot be
 * used to exhaust memory.
 */
export async function readJsonBody(req, { maxBytes = 262_144 } = {}) {
    const contentLength = Number(req.headers['content-length'] ?? 0);
    if (Number.isFinite(contentLength) && contentLength > maxBytes) {
        throw new AppError(`Request body exceeds ${maxBytes} bytes`, { code: 'PAYLOAD_TOO_LARGE', status: 413 });
    }

    const type = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
    const chunks = [];
    let total = 0;

    for await (const chunk of req) {
        total += chunk.length;
        if (total > maxBytes) {
            throw new AppError(`Request body exceeds ${maxBytes} bytes`, { code: 'PAYLOAD_TOO_LARGE', status: 413 });
        }
        chunks.push(chunk);
    }

    if (total === 0) return {};

    const text = Buffer.concat(chunks).toString('utf8');

    if (type === 'application/x-www-form-urlencoded') {
        return Object.fromEntries(new URLSearchParams(text));
    }
    if (type && type !== 'application/json' && type !== 'text/json') {
        throw new AppError(`Unsupported content type: ${type}. Use application/json.`, { code: 'UNSUPPORTED_MEDIA_TYPE', status: 415 });
    }

    try {
        const parsed = JSON.parse(text);
        if (parsed === null || typeof parsed !== 'object') {
            throw new ValidationError('Request body must be a JSON object or array');
        }
        return parsed;
    } catch (err) {
        if (err instanceof ValidationError) throw err;
        throw new ValidationError('Request body is not valid JSON');
    }
}

/* ------------------------------------------------------------------ *
 * Responses
 * ------------------------------------------------------------------ */

export const SECURITY_HEADERS = Object.freeze({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), usb=()',
    'Cache-Control': 'no-store',
});

export function sendJson(res, status, body, extraHeaders = {}) {
    const payload = JSON.stringify(body ?? null);
    res.writeHead(status, {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Length': Buffer.byteLength(payload),
        ...SECURITY_HEADERS,
        ...extraHeaders,
    });
    res.end(payload);
}

export function sendText(res, status, text, contentType = 'text/plain; charset=utf-8', extraHeaders = {}) {
    const payload = String(text ?? '');
    res.writeHead(status, {
        'Content-Type': contentType,
        'Content-Length': Buffer.byteLength(payload),
        ...SECURITY_HEADERS,
        ...extraHeaders,
    });
    res.end(payload);
}

export function sendNoContent(res) {
    res.writeHead(204, SECURITY_HEADERS);
    res.end();
}

export function sendError(res, err, { requestId = null, path: reqPath = null, method = null } = {}) {
    const appErr = toAppError(err);
    const status = appErr.status ?? 500;

    if (status >= 500) {
        logEvent({
            level: 'error', category: 'error', action: 'api.error',
            message: `${method ?? ''} ${reqPath ?? ''} failed: ${appErr.message}`.trim(),
            details: { code: appErr.code, stack: appErr.stack?.split('\n').slice(0, 6).join('\n'), requestId },
        });
    }

    const body = {
        error: {
            code: appErr.code,
            message: status >= 500 ? 'Internal server error' : appErr.message,
            ...(appErr.details && status < 500 ? { details: appErr.details } : {}),
            ...(requestId ? { requestId } : {}),
        },
    };

    const headers = {};
    if (appErr.retryAfterSeconds) headers['Retry-After'] = String(appErr.retryAfterSeconds);
    sendJson(res, status, body, headers);
}

/* ------------------------------------------------------------------ *
 * Cookies
 * ------------------------------------------------------------------ */

export function parseCookies(header) {
    const out = Object.create(null);
    if (!header) return out;
    for (const part of String(header).split(';')) {
        const idx = part.indexOf('=');
        if (idx === -1) continue;
        const key = part.slice(0, idx).trim();
        const value = part.slice(idx + 1).trim();
        if (!key) continue;
        try {
            out[key] = decodeURIComponent(value);
        } catch {
            out[key] = value;
        }
    }
    return out;
}

export function serializeCookie(name, value, {
    maxAge = null, httpOnly = true, sameSite = 'Strict', secure = false, path = '/',
} = {}) {
    const parts = [`${name}=${encodeURIComponent(value)}`, `Path=${path}`];
    if (maxAge !== null) parts.push(`Max-Age=${Math.max(0, Math.floor(maxAge))}`);
    if (httpOnly) parts.push('HttpOnly');
    if (sameSite) parts.push(`SameSite=${sameSite}`);
    if (secure) parts.push('Secure');
    return parts.join('; ');
}

/* ------------------------------------------------------------------ *
 * Query parsing
 * ------------------------------------------------------------------ */

/** Coerce URLSearchParams into the shapes the query helpers expect. */
export function parseQuery(searchParams) {
    const q = {};
    for (const [key, value] of searchParams) {
        if (value === '') continue;
        if (key in q) {
            q[key] = Array.isArray(q[key]) ? [...q[key], value] : [q[key], value];
        } else {
            q[key] = value;
        }
    }
    return {
        raw: q,
        str: (key, fallback = '') => (q[key] === undefined ? fallback : String(Array.isArray(q[key]) ? q[key][0] : q[key])),
        int: (key, fallback = null, { min = -Infinity, max = Infinity } = {}) => {
            if (q[key] === undefined) return fallback;
            const n = Number(Array.isArray(q[key]) ? q[key][0] : q[key]);
            if (!Number.isFinite(n)) return fallback;
            return Math.min(max, Math.max(min, Math.trunc(n)));
        },
        bool: (key, fallback = null) => {
            if (q[key] === undefined) return fallback;
            const v = String(Array.isArray(q[key]) ? q[key][0] : q[key]).toLowerCase();
            if (['1', 'true', 'yes', 'on'].includes(v)) return true;
            if (['0', 'false', 'no', 'off'].includes(v)) return false;
            return fallback;
        },
        list: (key) => {
            if (q[key] === undefined) return [];
            const v = Array.isArray(q[key]) ? q[key] : [q[key]];
            return v.flatMap((item) => String(item).split(',')).map((s) => s.trim()).filter(Boolean);
        },
        enum: (key, allowed, fallback = null) => {
            if (q[key] === undefined) return fallback;
            const v = String(Array.isArray(q[key]) ? q[key][0] : q[key]).toLowerCase();
            return allowed.includes(v) ? v : fallback;
        },
    };
}

/* ------------------------------------------------------------------ *
 * Rate limiting
 * ------------------------------------------------------------------ */

/** Fixed-window counter keyed by client address. Adequate for a local console. */
export class RateLimiter {
    constructor({ windowSeconds = 60, maxRequests = 600 } = {}) {
        this.windowMs = windowSeconds * 1000;
        this.max = maxRequests;
        /** @type {Map<string, {count:number, resetAt:number}>} */
        this.buckets = new Map();
    }

    check(key) {
        const now = Date.now();
        let bucket = this.buckets.get(key);
        if (!bucket || bucket.resetAt <= now) {
            bucket = { count: 0, resetAt: now + this.windowMs };
            this.buckets.set(key, bucket);
        }
        bucket.count += 1;
        if (this.buckets.size > 10_000) {
            for (const [k, b] of this.buckets) {
                if (b.resetAt <= now) this.buckets.delete(k);
            }
        }
        return {
            ok: bucket.count <= this.max,
            remaining: Math.max(0, this.max - bucket.count),
            retryAfter: Math.ceil((bucket.resetAt - now) / 1000),
            limit: this.max,
        };
    }
}

/** Client address, honouring X-Forwarded-For only when explicitly trusted. */
export function clientAddress(req, { trustProxy = false } = {}) {
    if (trustProxy) {
        const fwd = req.headers['x-forwarded-for'];
        if (fwd) {
            const first = String(fwd).split(',')[0].trim();
            if (first) return normaliseAddress(first);
        }
    }
    return normaliseAddress(req.socket?.remoteAddress ?? 'unknown');
}

function normaliseAddress(addr) {
    if (!addr) return 'unknown';
    // ::ffff:127.0.0.1 -> 127.0.0.1
    return String(addr).replace(/^::ffff:/i, '');
}
