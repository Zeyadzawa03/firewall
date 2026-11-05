/**
 * HTTP server: authentication gate, static file serving, REST API, live events.
 *
 * Security posture:
 *  - Binds to 127.0.0.1 by default. Binding to a routable address is allowed but
 *    logged as a warning, because this console can change host firewall policy.
 *  - Authentication is mandatory unless `server.requireAuth` is explicitly off,
 *    which is itself logged as a warning on every start.
 *  - Session cookie is HttpOnly + SameSite=Strict, and Secure when the request
 *    arrived over TLS. State-changing requests need a matching CSRF header.
 *  - Origin/Host are checked on state-changing requests to blunt DNS rebinding.
 *  - Response headers include a strict CSP; the GUI ships no inline scripts.
 *  - Static serving resolves inside the allowed roots only (no path traversal).
 */

import http from 'node:http';
import fsp from 'node:fs/promises';
import fs from 'node:fs';
import path from 'node:path';
import { createReadStream } from 'node:fs';
import crypto from 'node:crypto';

import { router } from './routes.js';
import {
    readJsonBody, sendJson, sendText, sendError, sendNoContent,
    parseCookies, serializeCookie, parseQuery, RateLimiter, clientAddress, SECURITY_HEADERS,
} from './http.js';
import { getConfig } from '../core/config.js';
import { PATHS, safeResolve } from '../core/paths.js';
import { logEvent, onEvent } from '../core/logger.js';
import {
    login, logout, getSession, publicUser, findUser, requirePermission, verifyCsrf,
} from '../core/auth.js';
import { AppError, AuthError, ForbiddenError, RateLimitError, ValidationError } from '../core/errors.js';
import { randomId } from '../core/ids.js';

const SESSION_COOKIE = 'sentryfw_session';
const CSRF_HEADER = 'x-sentryfw-csrf';

/** The only API calls a session with `mustChangePassword` may make. */
const PASSWORD_CHANGE_ALLOWED = new Set([
    'GET /api/account',
    'POST /api/account/password',
    'GET /api/health',
    'GET /api',
]);

const MIME = Object.freeze({
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.mjs': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.ico': 'image/x-icon',
    '.woff': 'font/woff',
    '.woff2': 'font/woff2',
    '.txt': 'text/plain; charset=utf-8',
    '.md': 'text/markdown; charset=utf-8',
    '.map': 'application/json; charset=utf-8',
});

/**
 * Content-Security-Policy.
 * The console itself needs no external origins. The knowledge-base pages load
 * Google Fonts and the Mermaid bundle from jsDelivr, which is why those two
 * origins are present; everything else is same-origin only. 'unsafe-inline' for
 * styles is required by Mermaid's generated SVG styling.
 */
const CSP = [
    "default-src 'self'",
    "script-src 'self' https://cdn.jsdelivr.net",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com data:",
    "img-src 'self' data:",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "object-src 'none'",
].join('; ');

export class ApiServer {
    constructor({ host = null, port = null } = {}) {
        const cfg = getConfig().server;
        this.host = host ?? cfg.host;
        this.port = port ?? cfg.port;
        this.server = null;
        this.rateLimiter = new RateLimiter(getConfig().security.apiRateLimit);
        this.loginLimiter = new RateLimiter({ windowSeconds: 300, maxRequests: 30 });
        /** @type {Set<import('node:http').ServerResponse>} */
        this.eventClients = new Set();
        this.unsubscribeLog = null;
        this.startedAt = null;
    }

    async start() {
        this.server = http.createServer((req, res) => {
            this.#handle(req, res).catch((err) => {
                try {
                    sendError(res, err, { method: req.method, path: req.url });
                } catch {
                    try { res.destroy(); } catch { /* socket already gone */ }
                }
            });
        });

        this.server.headersTimeout = 20_000;
        this.server.requestTimeout = 60_000;
        this.server.keepAliveTimeout = 15_000;
        this.server.maxHeadersCount = 64;

        this.unsubscribeLog = onEvent((event) => this.#broadcast(event));

        await new Promise((resolve, reject) => {
            this.server.once('error', reject);
            this.server.listen(this.port, this.host, () => {
                this.server.removeListener('error', reject);
                resolve();
            });
        });

        this.startedAt = new Date().toISOString();
        const cfg = getConfig();

        logEvent({
            level: 'info', category: 'system', action: 'server.start',
            message: `Console listening on http://${formatHost(this.host)}:${this.port}`,
            details: { host: this.host, port: this.port, requireAuth: cfg.server.requireAuth },
        });

        if (this.host !== '127.0.0.1' && this.host !== 'localhost' && this.host !== '::1') {
            logEvent({
                level: 'warn', category: 'system', action: 'server.exposed',
                message: `The console is bound to ${this.host}, so it is reachable from the network. This interface can change host firewall policy — put it behind TLS and restrict access to management addresses.`,
            });
        }
        if (cfg.server.requireAuth === false) {
            logEvent({
                level: 'critical', category: 'system', action: 'server.auth_disabled',
                message: 'server.requireAuth is FALSE: every request is treated as an administrator. Never run this way outside an isolated lab.',
            });
        }

        return this;
    }

    async stop() {
        for (const res of this.eventClients) {
            try { res.end(); } catch { /* client already gone */ }
        }
        this.eventClients.clear();
        this.unsubscribeLog?.();
        if (!this.server) return;
        await new Promise((resolve) => this.server.close(resolve));
        this.server = null;
        logEvent({ level: 'info', category: 'system', action: 'server.stop', message: 'Console stopped' });
    }

    get address() {
        return `http://${formatHost(this.host)}:${this.port}`;
    }

    /* -------------------------------------------------------------- */

    async #handle(req, res) {
        const requestId = randomId('req', 8);
        const cfg = getConfig();
        const source = clientAddress(req, { trustProxy: cfg.server.trustProxy });

        let url;
        try {
            url = new URL(req.url, `http://${req.headers.host ?? 'localhost'}`);
        } catch {
            sendError(res, new ValidationError('Malformed request URL'), { requestId });
            return;
        }
        // Static paths are matched decoded; API routing uses the raw path so an
        // encoded slash inside a parameter (a CIDR such as 10.0.0.0%2F8) stays
        // part of that parameter instead of splitting the route.
        let pathname;
        try {
            pathname = decodeURIComponent(url.pathname);
        } catch {
            sendError(res, new ValidationError('Malformed percent-encoding in request path'), { requestId });
            return;
        }

        // Rate limit only the API; static assets are local files.
        if (pathname.startsWith('/api/')) {
            const verdict = this.rateLimiter.check(source);
            if (!verdict.ok) {
                sendError(res, new RateLimitError(verdict.retryAfter), { requestId, path: pathname, method: req.method });
                return;
            }
            res.setHeader('X-RateLimit-Remaining', String(verdict.remaining));
        }

        if (req.method === 'OPTIONS') {
            res.writeHead(204, {
                ...SECURITY_HEADERS,
                Allow: 'GET, POST, PATCH, DELETE, OPTIONS',
            });
            res.end();
            return;
        }

        // ---- authentication endpoints (no session required) ----
        if (pathname === '/api/auth/login' && req.method === 'POST') {
            await this.#login(req, res, { source, requestId });
            return;
        }
        if (pathname === '/api/auth/logout' && req.method === 'POST') {
            const cookies = parseCookies(req.headers.cookie);
            logout(cookies[SESSION_COOKIE], { source });
            res.setHeader('Set-Cookie', serializeCookie(SESSION_COOKIE, '', { maxAge: 0, secure: isSecure(req) }));
            sendJson(res, 200, { ok: true });
            return;
        }
        if (pathname === '/api/auth/session' && req.method === 'GET') {
            const session = this.#session(req);
            sendJson(res, 200, session
                ? { authenticated: true, user: publicUser(findUser(session.username)) ?? { username: session.username, role: session.role }, csrf: session.csrf, expiresAt: new Date(session.expiresAt).toISOString() }
                : { authenticated: false, requireAuth: cfg.server.requireAuth !== false });
            return;
        }

        // ---- live event stream ----
        if (pathname === '/api/events/stream' && req.method === 'GET') {
            const principal = this.#principal(req);
            if (!principal) {
                sendError(res, new AuthError(), { requestId, path: pathname, method: req.method });
                return;
            }
            try {
                requirePermission(principal, 'logs:read');
            } catch (err) {
                sendError(res, err, { requestId, path: pathname, method: req.method });
                return;
            }
            this.#openEventStream(req, res);
            return;
        }

        // ---- REST API ----
        if (pathname === '/api' || pathname.startsWith('/api/')) {
            await this.#api(req, res, { url, pathname, source, requestId });
            return;
        }

        // ---- static ----
        await this.#static(req, res, { pathname, requestId });
    }

    async #login(req, res, { source, requestId }) {
        const verdict = this.loginLimiter.check(source);
        if (!verdict.ok) {
            sendError(res, new RateLimitError(verdict.retryAfter), { requestId, path: '/api/auth/login', method: 'POST' });
            return;
        }
        let body;
        try {
            body = await readJsonBody(req, { maxBytes: 4096 });
        } catch (err) {
            sendError(res, err, { requestId });
            return;
        }
        try {
            const result = await login(
                { username: body.username, password: body.password },
                { source, userAgent: req.headers['user-agent'] },
            );
            res.setHeader('Set-Cookie', serializeCookie(SESSION_COOKIE, result.token, {
                maxAge: getConfig().server.sessionTtlMinutes * 60,
                secure: isSecure(req),
            }));
            sendJson(res, 200, {
                user: result.user,
                csrf: result.csrf,
                expiresAt: result.expiresAt,
                mustChangePassword: result.user.mustChangePassword,
            });
        } catch (err) {
            sendError(res, err, { requestId, path: '/api/auth/login', method: 'POST' });
        }
    }

    #session(req) {
        const cookies = parseCookies(req.headers.cookie);
        return getSession(cookies[SESSION_COOKIE]);
    }

    /**
     * Resolve the caller. When `server.requireAuth` is false the caller is
     * treated as a local administrator — only sensible for an isolated lab, and
     * loudly logged at startup.
     */
    #principal(req) {
        const session = this.#session(req);
        if (session) return { username: session.username, role: session.role, session };
        if (getConfig().server.requireAuth === false) {
            return { username: 'anonymous', role: 'admin', session: null, unauthenticated: true };
        }
        return null;
    }

    async #api(req, res, { url, pathname, source, requestId }) {
        const cfg = getConfig();
        let matched;
        try {
            matched = router.match(req.method, url.pathname);
        } catch {
            sendError(res, new ValidationError('Malformed percent-encoding in request path'), { requestId });
            return;
        }

        if (!matched) {
            sendError(res, new AppError(`No such endpoint: ${req.method} ${pathname}`, { code: 'NOT_FOUND', status: 404 }), { requestId });
            return;
        }
        if (matched.allowed) {
            res.setHeader('Allow', matched.allowed.join(', '));
            sendError(res, new AppError(`${req.method} is not allowed for ${pathname}`, { code: 'METHOD_NOT_ALLOWED', status: 405 }), { requestId });
            return;
        }

        const { route, params } = matched;
        const needsAuth = route.meta.auth !== false;
        const principal = this.#principal(req);

        if (needsAuth && !principal) {
            sendError(res, new AuthError(), { requestId, path: pathname, method: req.method });
            return;
        }

        // A bootstrap/reset credential must be replaced before the account can do
        // anything else. Enforced here, not only in the GUI, so the API and
        // scripted clients cannot skip it.
        if (principal?.session && findUser(principal.username)?.mustChangePassword && !PASSWORD_CHANGE_ALLOWED.has(`${req.method} ${pathname}`)) {
            sendError(res, new AppError('You must change your password before using the console', { code: 'PASSWORD_CHANGE_REQUIRED', status: 403 }), { requestId, path: pathname, method: req.method });
            return;
        }

        const mutating = ['POST', 'PATCH', 'PUT', 'DELETE'].includes(req.method);

        // Cross-origin / DNS-rebinding guard for state-changing requests.
        if (mutating && needsAuth) {
            const originError = checkOrigin(req);
            if (originError) {
                logEvent({
                    level: 'warn', category: 'auth', action: 'api.origin_rejected',
                    message: `Rejected ${req.method} ${pathname}: ${originError}`,
                    source, actor: principal?.username ?? null, outcome: 'denied',
                });
                sendError(res, new ForbiddenError(originError), { requestId, path: pathname, method: req.method });
                return;
            }
        }

        // CSRF: required for every mutating request made with a session cookie.
        if (mutating && principal?.session) {
            const provided = req.headers[CSRF_HEADER];
            if (!verifyCsrf(principal.session, Array.isArray(provided) ? provided[0] : provided)) {
                logEvent({
                    level: 'warn', category: 'auth', action: 'api.csrf_failed',
                    message: `CSRF token missing or invalid for ${req.method} ${pathname}`,
                    source, actor: principal.username, outcome: 'denied',
                });
                sendError(res, new ForbiddenError('CSRF token missing or invalid. Reload the console and try again.'), { requestId, path: pathname, method: req.method });
                return;
            }
        }

        if (route.meta.permission && principal) {
            try {
                requirePermission(principal, route.meta.permission);
            } catch (err) {
                logEvent({
                    level: 'warn', category: 'auth', action: 'api.forbidden',
                    message: `${principal.username} (${principal.role}) was denied ${route.meta.permission} on ${req.method} ${pathname}`,
                    source, actor: principal.username, outcome: 'denied',
                });
                sendError(res, err, { requestId, path: pathname, method: req.method });
                return;
            }
        }

        let body = {};
        if (mutating) {
            try {
                body = await readJsonBody(req, { maxBytes: cfg.server.maxBodyBytes ?? 262_144 });
            } catch (err) {
                sendError(res, err, { requestId, path: pathname, method: req.method });
                return;
            }
        }

        const ctx = {
            req,
            res,
            params,
            query: parseQuery(url.searchParams),
            body,
            principal,
            session: principal?.session ?? null,
            actor: principal?.username ?? 'anonymous',
            source,
            requestId,
        };

        const started = Date.now();
        try {
            const result = await route.handler(ctx);

            if (res.writableEnded) return; // handler streamed its own response

            if (result && typeof result === 'object' && result.__raw) {
                const { body: raw, contentType, headers } = result.__raw;
                sendText(res, 200, raw, contentType, headers);
            } else if (result === undefined || result === null) {
                sendNoContent(res);
            } else {
                sendJson(res, req.method === 'POST' && pathname === '/api/rules' ? 201 : 200, result);
            }

            if (mutating) {
                logEvent({
                    level: 'debug', category: 'system', action: 'api.request',
                    message: `${req.method} ${pathname} → ${res.statusCode} (${Date.now() - started}ms)`,
                    actor: ctx.actor, source, details: { requestId },
                });
            }
        } catch (err) {
            sendError(res, err, { requestId, path: pathname, method: req.method });
        }
    }

    /* -------------------------------------------------------------- *
     * Static files
     * -------------------------------------------------------------- */

    async #static(req, res, { pathname, requestId }) {
        if (req.method !== 'GET' && req.method !== 'HEAD') {
            sendError(res, new AppError('Only GET and HEAD are supported for static content', { code: 'METHOD_NOT_ALLOWED', status: 405 }), { requestId });
            return;
        }

        const cfg = getConfig().server;
        let relative = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
        let root = path.resolve(PATHS.root, cfg.publicDir ?? 'public');

        // Documentation markdown is served read-only from docs/.
        if (relative === 'docs' || relative.startsWith('docs/')) {
            root = path.join(PATHS.root, 'docs');
            relative = relative.replace(/^docs\/?/, '') || 'README.md';
        } else if (relative === 'kb' || relative.startsWith('kb/')) {
            // The Fortinet knowledge base retains its original location at the
            // repository root, mounted under /kb/ so it coexists with the console.
            root = path.resolve(PATHS.root, cfg.kbDir ?? '.');
            relative = relative.replace(/^kb\/?/, '') || 'index.html';
            if (!isKbAsset(relative)) {
                sendError(res, new AppError('Not found', { code: 'NOT_FOUND', status: 404 }), { requestId });
                return;
            }
        }

        const target = safeResolve(root, relative);
        if (!target) {
            logEvent({
                level: 'warn', category: 'system', action: 'static.traversal_blocked',
                message: `Blocked path traversal attempt: ${pathname}`, outcome: 'denied',
            });
            sendError(res, new ForbiddenError('Path is outside the served directory'), { requestId });
            return;
        }

        let stat;
        try {
            stat = await fsp.stat(target);
        } catch {
            // SPA fallback: unknown console routes render the shell.
            if (!path.extname(relative)) {
                const shell = path.join(path.resolve(PATHS.root, cfg.publicDir ?? 'public'), 'index.html');
                if (fs.existsSync(shell)) {
                    await this.#sendFile(req, res, shell);
                    return;
                }
            }
            sendError(res, new AppError(`Not found: ${pathname}`, { code: 'NOT_FOUND', status: 404 }), { requestId });
            return;
        }

        if (stat.isDirectory()) {
            const indexFile = path.join(target, 'index.html');
            if (fs.existsSync(indexFile)) {
                await this.#sendFile(req, res, indexFile);
                return;
            }
            sendError(res, new ForbiddenError('Directory listing is not permitted'), { requestId });
            return;
        }

        await this.#sendFile(req, res, target, { stat });
    }

    async #sendFile(req, res, file, { stat = null } = {}) {
        const st = stat ?? await fsp.stat(file);
        const ext = path.extname(file).toLowerCase();
        const contentType = MIME[ext] ?? 'application/octet-stream';
        const etag = `W/"${st.size.toString(16)}-${st.mtimeMs.toString(16)}"`;

        if (req.headers['if-none-match'] === etag) {
            res.writeHead(304, { ETag: etag, ...SECURITY_HEADERS });
            res.end();
            return;
        }

        const headers = {
            'Content-Type': contentType,
            'Content-Length': st.size,
            ETag: etag,
            'Last-Modified': st.mtime.toUTCString(),
            ...SECURITY_HEADERS,
            'Content-Security-Policy': CSP,
            // Always revalidate (the ETag turns it into a cheap 304): after an
            // upgrade a cached console script must never run against a newer API.
            'Cache-Control': 'no-cache',
        };

        res.writeHead(200, headers);
        if (req.method === 'HEAD') {
            res.end();
            return;
        }
        createReadStream(file).on('error', () => { try { res.destroy(); } catch { /* noop */ } }).pipe(res);
    }

    /* -------------------------------------------------------------- *
     * Server-sent events
     * -------------------------------------------------------------- */

    #openEventStream(req, res) {
        res.writeHead(200, {
            'Content-Type': 'text/event-stream; charset=utf-8',
            'Cache-Control': 'no-store',
            Connection: 'keep-alive',
            'X-Accel-Buffering': 'no',
            ...SECURITY_HEADERS,
        });
        res.write(`retry: 5000\n\n`);
        res.write(`event: hello\ndata: ${JSON.stringify({ connectedAt: new Date().toISOString() })}\n\n`);

        this.eventClients.add(res);

        const keepAlive = setInterval(() => {
            try { res.write(': keep-alive\n\n'); } catch { /* closed */ }
        }, 25_000);
        keepAlive.unref?.();

        const cleanup = () => {
            clearInterval(keepAlive);
            this.eventClients.delete(res);
        };
        req.on('close', cleanup);
        req.on('error', cleanup);
        res.on('error', cleanup);
    }

    #broadcast(event) {
        if (this.eventClients.size === 0) return;
        // Trim payloads: the stream is for live tiles, not for bulk export.
        const slim = {
            id: event.id,
            ts: event.ts,
            level: event.level,
            category: event.category,
            action: event.action,
            message: event.message,
            outcome: event.outcome,
            source: event.source,
            target: event.target,
        };
        const frame = `event: log\ndata: ${JSON.stringify(slim)}\n\n`;
        for (const res of this.eventClients) {
            try {
                res.write(frame);
            } catch {
                this.eventClients.delete(res);
            }
        }
    }
}

/* ------------------------------------------------------------------ *
 * Helpers
 * ------------------------------------------------------------------ */

function isSecure(req) {
    if (req.socket?.encrypted) return true;
    if (getConfig().server.trustProxy && String(req.headers['x-forwarded-proto'] ?? '').toLowerCase() === 'https') return true;
    return false;
}

/**
 * Reject state-changing requests whose Origin does not match the Host we are
 * serving. This is what stops a malicious page in the operator's browser from
 * driving the console (and therefore the host firewall) via DNS rebinding.
 */
function checkOrigin(req) {
    const host = req.headers.host;
    if (!host) return 'Missing Host header';

    const origin = req.headers.origin;
    if (origin && origin !== 'null') {
        let originHost;
        try {
            originHost = new URL(origin).host;
        } catch {
            return `Malformed Origin header: ${origin}`;
        }
        if (originHost !== host) {
            return `Origin ${origin} does not match Host ${host}`;
        }
        return null;
    }

    // No Origin (e.g. curl, fwctl): accept, since CSRF still applies to
    // cookie-authenticated calls and a token cannot be guessed cross-origin.
    return null;
}

/** Restrict /kb/ to the knowledge base's own assets. */
function isKbAsset(relative) {
    const normalised = relative.replace(/\\/g, '/');
    if (normalised === 'index.html' || normalised === 'app.js' || normalised === 'style.css') return true;
    if (/^content\/[A-Za-z0-9_-]+\.js$/.test(normalised)) return true;
    return false;
}

function formatHost(host) {
    return host.includes(':') ? `[${host}]` : host;
}

/** Constant-time string compare used by the tests. */
export function safeEqual(a, b) {
    const ba = Buffer.from(String(a));
    const bb = Buffer.from(String(b));
    if (ba.length !== bb.length) return false;
    return crypto.timingSafeEqual(ba, bb);
}

export { SESSION_COOKIE, CSRF_HEADER, CSP, checkOrigin, isKbAsset };
