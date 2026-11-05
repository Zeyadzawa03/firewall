/**
 * SentryFW operator console.
 *
 * Plain browser JavaScript, no build step and no dependencies. The server's CSP
 * forbids inline scripts, so everything is wired up here. All untrusted data
 * (log messages, process names, remote addresses) is rendered through
 * textContent via h(); nothing is ever assigned to innerHTML.
 */
(() => {
    'use strict';

    /* ================================================================ *
     * DOM helpers
     * ================================================================ */

    /**
     * h('div', { class: 'x', on: { click: fn } }, 'text', child, [more])
     * Attribute values of `false`/`null`/`undefined` are omitted.
     */
    function h(tag, attrs, ...children) {
        const el = tag === 'svg' || attrs?.svg ? document.createElementNS('http://www.w3.org/2000/svg', tag) : document.createElement(tag);
        if (attrs) {
            for (const [key, value] of Object.entries(attrs)) {
                if (value === false || value === null || value === undefined || key === 'svg') continue;
                if (key === 'on') {
                    for (const [evt, fn] of Object.entries(value)) el.addEventListener(evt, fn);
                } else if (key === 'text') {
                    el.textContent = String(value);
                } else if (key === 'dataset') {
                    Object.assign(el.dataset, value);
                } else if (['value', 'checked', 'disabled', 'selected', 'hidden', 'required', 'multiple'].includes(key) && !(el instanceof SVGElement)) {
                    el[key] = value;
                } else {
                    el.setAttribute(key, value === true ? '' : String(value));
                }
            }
        }
        append(el, children);
        return el;
    }

    function append(el, children) {
        for (const child of children.flat(Infinity)) {
            if (child === null || child === undefined || child === false) continue;
            el.append(child instanceof Node ? child : document.createTextNode(String(child)));
        }
        return el;
    }

    function svg(tag, attrs = {}) {
        const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
        for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, String(v));
        return el;
    }

    const $ = (sel, root = document) => root.querySelector(sel);
    const clear = (el) => { el.replaceChildren(); return el; };
    /** Replace an element's children. Unlike Element.append, flattens arrays and skips null/false. */
    const fill = (el, ...children) => append(clear(el), children);

    /* ================================================================ *
     * Formatting
     * ================================================================ */

    const fmt = {
        num: (n) => (Number.isFinite(Number(n)) ? Number(n).toLocaleString() : '—'),
        time(iso) {
            if (!iso) return '—';
            const d = new Date(iso);
            return Number.isNaN(d.getTime()) ? String(iso) : d.toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'medium' });
        },
        clock(iso) {
            const d = new Date(iso);
            return Number.isNaN(d.getTime()) ? '' : d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        },
        rel(iso) {
            if (!iso) return 'never';
            const s = Math.round((Date.now() - Date.parse(iso)) / 1000);
            if (!Number.isFinite(s)) return String(iso);
            if (s < 5) return 'just now';
            if (s < 60) return `${s}s ago`;
            if (s < 3600) return `${Math.round(s / 60)}m ago`;
            if (s < 172800) return `${Math.round(s / 3600)}h ago`;
            return `${Math.round(s / 86400)}d ago`;
        },
        bytes(n) {
            let v = Number(n) || 0;
            const units = ['B', 'KB', 'MB', 'GB'];
            let i = 0;
            while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
            return `${i ? v.toFixed(1) : v} ${units[i]}`;
        },
        endpoint: (addr, port) => (port && port !== 'any' ? `${addr}:${port}` : String(addr ?? '')),
        duration(seconds) {
            if (seconds === null || seconds === undefined) return '—';
            if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
            if (seconds < 172800) return `${Math.round(seconds / 3600)}h`;
            return `${Math.round(seconds / 86400)}d`;
        },
    };

    const badge = (text, tone = '') => h('span', { class: `badge${tone ? ` badge-${tone}` : ''}`, text });
    const actionBadge = (a) => badge(a === 'allow' ? 'Allow' : 'Deny', a === 'allow' ? 'ok' : 'bad');
    const severityTone = { critical: 'bad', high: 'bad', medium: 'warn', low: 'info' };
    const levelTone = { critical: 'bad', error: 'bad', warn: 'warn', info: 'info', debug: '' };
    const severityBadge = (s) => badge(s, severityTone[s] ?? '');
    const levelBadge = (l) => badge(l, levelTone[l] ?? '');

    function osBadge(rule) {
        if (rule.osLastError) return h('span', { title: rule.osLastError }, badge('Error', 'bad'));
        if (rule.osApplied) return badge('Applied', 'ok');
        return badge('Pending');
    }

    /* ================================================================ *
     * API client
     * ================================================================ */

    const state = {
        user: null,
        csrf: null,
        system: null,
        cleanup: null,
        openFindings: 0,
    };

    class ApiError extends Error {
        constructor(status, error) {
            super(error?.message ?? `Request failed (${status})`);
            this.status = status;
            this.code = error?.code ?? `HTTP_${status}`;
            this.details = error?.details ?? null;
        }
    }

    async function api(method, url, body) {
        const headers = { Accept: 'application/json' };
        if (body !== undefined) headers['Content-Type'] = 'application/json';
        if (method !== 'GET' && state.csrf) headers['X-SentryFW-CSRF'] = state.csrf;

        let res;
        try {
            res = await fetch(url, {
                method,
                headers,
                credentials: 'same-origin',
                body: body === undefined ? undefined : JSON.stringify(body),
            });
        } catch {
            throw new ApiError(0, { code: 'NETWORK', message: 'Cannot reach the SentryFW server. Is `fwctl serve` still running?' });
        }

        if (res.status === 204) return null;
        const data = await res.json().catch(() => null);
        if (res.ok) return data;

        const err = new ApiError(res.status, data?.error);
        if (err.status === 401 && err.code === 'UNAUTHENTICATED' && !url.startsWith('/api/auth/')) {
            showLogin('Your session has ended. Sign in again.');
        } else if (err.code === 'PASSWORD_CHANGE_REQUIRED') {
            showPasswordChange();
        }
        throw err;
    }

    const get = (url) => api('GET', url);
    const post = (url, body = {}) => api('POST', url, body);
    const patch = (url, body) => api('PATCH', url, body);
    const del = (url, body = {}) => api('DELETE', url, body);

    function qs(params) {
        const sp = new URLSearchParams();
        for (const [k, v] of Object.entries(params)) {
            if (v === null || v === undefined || v === '' || (Array.isArray(v) && v.length === 0)) continue;
            sp.set(k, Array.isArray(v) ? v.join(',') : String(v));
        }
        const s = sp.toString();
        return s ? `?${s}` : '';
    }

    const can = (perm) => !!state.user?.permissions?.includes(perm);

    /* ================================================================ *
     * Toasts, modals, confirmation
     * ================================================================ */

    function toast(message, tone = 'info', ms = 4500) {
        const el = h('div', { class: `toast toast-${tone}`, role: tone === 'bad' ? 'alert' : 'status', text: message });
        $('#toast-root').append(el);
        setTimeout(() => el.remove(), ms);
    }

    function toastError(err) {
        if (err?.code === 'PASSWORD_CHANGE_REQUIRED' || (err?.status === 401 && err?.code === 'UNAUTHENTICATED')) return;
        const fields = Array.isArray(err?.details) ? err.details.map((d) => `${d.field}: ${d.message}`).join('; ') : '';
        toast(fields && !err.message.includes(fields) ? `${err.message} (${fields})` : (err?.message ?? String(err)), 'bad', 7000);
    }

    /**
     * Open a modal. `build(close)` returns { body, foot } nodes.
     * Resolves with whatever is passed to close().
     */
    function modal({ title, wide = false, build }) {
        return new Promise((resolve) => {
            const root = $('#modal-root');
            const previous = document.activeElement;
            let done = false;
            const close = (value) => {
                if (done) return;
                done = true;
                backdrop.remove();
                document.removeEventListener('keydown', onKey);
                previous?.focus?.();
                resolve(value);
            };
            const onKey = (e) => { if (e.key === 'Escape') close(undefined); };
            const parts = build(close);
            const dialog = h('div', { class: `modal${wide ? ' modal-wide' : ''}`, role: 'dialog', 'aria-modal': 'true', 'aria-label': title },
                h('div', { class: 'modal-head' },
                    h('h2', { text: title }),
                    h('button', { class: 'icon-btn', 'aria-label': 'Close', on: { click: () => close(undefined) } }, '✕')),
                h('div', { class: 'modal-body' }, parts.body),
                parts.foot ? h('div', { class: 'modal-foot' }, parts.foot) : null);
            const backdrop = h('div', { class: 'modal-backdrop', on: { mousedown: (e) => { if (e.target === backdrop) close(undefined); } } }, dialog);
            root.append(backdrop);
            document.addEventListener('keydown', onKey);
            (dialog.querySelector('[autofocus], input, select, textarea, .btn-primary, .btn-danger') ?? dialog).focus?.();
        });
    }

    function confirmDialog({ title, message, confirmLabel = 'Confirm', danger = true, extra = null }) {
        return modal({
            title,
            build: (close) => ({
                body: [h('p', { text: message }), extra],
                foot: [
                    h('button', { class: 'btn', type: 'button', on: { click: () => close(false) } }, 'Cancel'),
                    h('button', { class: `btn ${danger ? 'btn-danger' : 'btn-primary'}`, type: 'button', on: { click: () => close(true) } }, confirmLabel),
                ],
            }),
        }).then((v) => v === true);
    }

    /** Run an async action with a busy button and error toast. */
    async function busy(button, fn) {
        const original = button?.textContent;
        if (button) { button.disabled = true; button.textContent = 'Working…'; }
        try {
            return await fn();
        } catch (err) {
            toastError(err);
            return undefined;
        } finally {
            if (button) { button.disabled = false; button.textContent = original; }
        }
    }

    function formData(form) {
        const out = {};
        for (const el of form.elements) {
            if (!el.name) continue;
            if (el.type === 'checkbox') {
                if (el.dataset.group) {
                    out[el.dataset.group] ??= [];
                    if (el.checked) out[el.dataset.group].push(el.value);
                } else {
                    out[el.name] = el.checked;
                }
            } else {
                out[el.name] = el.value;
            }
        }
        return out;
    }

    /* ================================================================ *
     * Generic building blocks
     * ================================================================ */

    function card(title, actions, body, { flush = false } = {}) {
        return h('section', { class: 'card' },
            title || actions ? h('div', { class: 'card-head' }, title ? h('h2', { text: title }) : null, actions) : null,
            h('div', { class: `card-body${flush ? ' flush' : ''}` }, body));
    }

    function tile(label, value, sub = '', tone = '') {
        return h('div', { class: `tile${tone ? ` is-${tone}` : ''}` },
            h('div', { class: 'tile-label', text: label }),
            h('div', { class: 'tile-value', text: value }),
            sub ? h('div', { class: 'tile-sub', text: sub }) : null);
    }

    /**
     * Table with optional client-side sort.
     * columns: [{ label, render(row) -> Node|string, class, sort: 'key' }]
     */
    function dataTable(columns, rows, { empty = 'Nothing to show.', rowClass = null, sort = null, onSort = null } = {}) {
        if (!rows || rows.length === 0) return h('div', { class: 'empty', text: empty });
        const head = h('tr', null, columns.map((col) => {
            const sortable = col.sort && onSort;
            const active = sortable && sort?.key === col.sort;
            return h('th', {
                class: [col.class, sortable ? 'sortable' : ''].filter(Boolean).join(' ') || null,
                scope: 'col',
                'aria-sort': active ? (sort.order === 'asc' ? 'ascending' : 'descending') : null,
                on: sortable ? { click: () => onSort(col.sort) } : null,
            }, col.label, active ? (sort.order === 'asc' ? ' ▲' : ' ▼') : '');
        }));
        const body = rows.map((row) => h('tr', { class: rowClass ? rowClass(row) : null },
            columns.map((col) => {
                const value = col.render(row);
                return h('td', { class: col.class ?? null }, value instanceof Node || Array.isArray(value) ? value : String(value ?? ''));
            })));
        return h('div', { class: 'table-wrap' }, h('table', null, h('thead', null, head), h('tbody', null, body)));
    }

    function pager({ total, offset, limit, onPage }) {
        const from = total === 0 ? 0 : offset + 1;
        const to = Math.min(total, offset + limit);
        return h('div', { class: 'pager' },
            h('span', { text: `${fmt.num(from)}–${fmt.num(to)} of ${fmt.num(total)}` }),
            h('div', { class: 'btn-row' },
                h('button', { class: 'btn btn-sm', disabled: offset === 0, on: { click: () => onPage(Math.max(0, offset - limit)) } }, '← Newer'),
                h('button', { class: 'btn btn-sm', disabled: to >= total, on: { click: () => onPage(offset + limit) } }, 'Older →')));
    }

    function select(name, options, value, attrs = {}) {
        return h('select', { name, ...attrs },
            options.map((opt) => {
                const [v, label] = Array.isArray(opt) ? opt : [opt, opt];
                return h('option', { value: v, selected: String(v) === String(value ?? '') }, label);
            }));
    }

    function switchInput({ checked, disabled = false, label, onChange }) {
        const input = h('input', { type: 'checkbox', checked, disabled, 'aria-label': label });
        input.addEventListener('change', () => onChange(input.checked, input));
        return h('label', { class: 'switch', title: label }, input, h('span'));
    }

    function debounce(fn, ms = 250) {
        let t;
        return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
    }

    function kvList(pairs) {
        return h('dl', { class: 'kv' }, pairs.filter(([, v]) => v !== undefined).flatMap(([k, v]) => [
            h('dt', { text: k }),
            h('dd', null, v instanceof Node ? v : String(v ?? '—')),
        ]));
    }

    function downloadLink(label, href) {
        return h('a', { class: 'btn btn-sm', href, download: '' }, label);
    }

    /* ================================================================ *
     * Pages
     * ================================================================ */

    const PAGES = {
        dashboard: { title: 'Dashboard', icon: '📊', perm: 'traffic:read', section: 'Monitor', render: renderDashboard },
        traffic: { title: 'Traffic', icon: '🔀', perm: 'traffic:read', section: 'Monitor', render: renderTraffic },
        detection: { title: 'Detection', icon: '🚨', perm: 'logs:read', section: 'Monitor', render: renderDetection },
        rules: { title: 'Rules', icon: '🧱', perm: 'rules:read', section: 'Policy', render: renderRules },
        blocklist: { title: 'Blocklist', icon: '⛔', perm: 'blocklist:read', section: 'Policy', render: renderBlocklist },
        scenarios: { title: 'Quick hardening', icon: '⚡', perm: 'rules:write', section: 'Policy', render: renderScenarios },
        logs: { title: 'Event log', icon: '📜', perm: 'logs:read', section: 'Records', render: renderLogs },
        audit: { title: 'Audit trail', icon: '🔏', perm: 'audit:read', section: 'Records', render: renderAudit },
        backups: { title: 'Backups', icon: '💾', perm: 'backup:read', section: 'Records', render: renderBackups },
        settings: { title: 'Settings', icon: '⚙️', perm: 'settings:read', section: 'Administration', render: renderSettings },
        users: { title: 'Users', icon: '👤', perm: 'users:read', section: 'Administration', render: renderUsers },
    };

    /* ---------------------------------------------------------------- *
     * Dashboard
     * ---------------------------------------------------------------- */

    async function renderDashboard(page) {
        let timer = null;
        const body = h('div', { class: 'grid' }, h('div', { class: 'loading', text: 'Loading dashboard…' }));
        page.append(body);

        const load = async () => {
            let d;
            try {
                d = await get('/api/dashboard');
            } catch (err) {
                toastError(err);
                return;
            }
            state.openFindings = d.counters.openFindings;
            updateNavCounts();

            const exposed = (d.listeners ?? []).filter((l) => l.exposure === 'all-interfaces');
            fill(body,
                h('div', { class: 'tiles' },
                    tile('Rules enabled', `${fmt.num(d.rules.enabled)} / ${fmt.num(d.rules.total)}`, `${d.rules.appliedToOS} applied to OS`),
                    tile('Allowed flows', fmt.num(d.counters.allowed), 'since monitor start', 'ok'),
                    tile('Denied by policy', fmt.num(d.counters.denied), `${fmt.num(d.counters.blocklisted)} blocklisted`, d.counters.denied ? 'bad' : ''),
                    tile('Open findings', fmt.num(d.counters.openFindings), `${fmt.num(d.counters.suspicious)} total`, d.counters.openFindings ? 'warn' : ''),
                    tile('Blocked addresses', fmt.num(d.blocklist.active), `${fmt.num(d.blocklist.expired)} expired`),
                    tile('Connections', fmt.num(d.network?.established ?? 0), `${fmt.num(d.network?.total ?? 0)} sockets · ${d.network?.source ?? 'n/a'}`)),
                card('Traffic decisions per sample', h('div', { class: 'legend' },
                    h('span', null, h('i', { style: 'background:var(--series-allow)' }), 'Allowed'),
                    h('span', null, h('i', { style: 'background:var(--series-deny)' }), 'Denied')),
                trafficChart(d.series)),
                h('div', { class: 'grid grid-2' },
                    card('Rule analysis', h('a', { class: 'btn btn-sm', href: '#/rules' }, 'Open rules'),
                        d.ruleFindings.length
                            ? h('ul', { class: 'list' }, d.ruleFindings.map((f) => h('li', null,
                                severityBadge(f.severity),
                                h('div', { class: 'list-main' },
                                    h('div', { class: 'list-title', text: f.ruleName }),
                                    h('div', { class: 'list-meta', text: f.message })))))
                            : h('div', { class: 'empty', text: 'No shadowed, duplicate or risky rules.' }), { flush: true }),
                    card('Detection', h('a', { class: 'btn btn-sm', href: '#/detection' }, 'All findings'),
                        d.topFindings.length
                            ? h('ul', { class: 'list' }, d.topFindings.map((f) => h('li', null,
                                severityBadge(f.severity),
                                h('div', { class: 'list-main' },
                                    h('div', { class: 'list-title', text: f.title }),
                                    h('div', { class: 'list-meta', text: [f.remoteAddress, `${f.occurrences}×`, fmt.rel(f.lastSeenAt)].filter(Boolean).join(' · ') })),
                                f.acknowledged ? badge('Ack') : null)))
                            : h('div', { class: 'empty', text: d.monitor.running ? 'Nothing suspicious observed.' : 'The traffic monitor is stopped, so nothing is being analysed.' }), { flush: true })),
                h('div', { class: 'grid grid-2' },
                    card('Recent events', h('a', { class: 'btn btn-sm', href: '#/logs' }, 'Event log'),
                        h('ul', { class: 'list' }, d.recentEvents.slice(0, 10).map((e) => h('li', null,
                            levelBadge(e.level),
                            h('div', { class: 'list-main' },
                                h('div', { text: e.message }),
                                h('div', { class: 'list-meta', text: `${e.category} · ${fmt.rel(e.ts)}${e.actor ? ` · ${e.actor}` : ''}` }))))), { flush: true }),
                    card(`Services listening on all interfaces (${exposed.length})`, h('a', { class: 'btn btn-sm', href: '#/traffic?tab=listeners' }, 'Listeners'),
                        dataTable([
                            { label: 'Port', class: 'num', render: (l) => `${l.protocol}/${l.localPort}` },
                            { label: 'Service', render: (l) => l.wellKnown ?? '' },
                            { label: 'Process', render: (l) => l.process ?? '' },
                        ], exposed.slice(0, 12), { empty: d.monitor.running ? 'No wildcard listeners found.' : 'Start the traffic monitor to inventory listeners.' }), { flush: true })),
                card('Provider', null, kvList([
                    ['Firewall provider', `${d.provider.label} (${d.provider.id})`],
                    ['Apply to OS', d.provider.applyToOS ? badge('Enforcing', 'ok') : badge('Not enforced', 'warn')],
                    ['Provider available', d.provider.probe?.available ? 'yes' : `no — ${d.provider.probe?.reason ?? 'unknown'}`],
                    ['Monitor', d.monitor.running ? `running, every ${d.monitor.intervalSeconds}s (last sample ${fmt.rel(d.monitor.lastSampleAt)})` : 'stopped'],
                    ['Monitor error', d.monitor.lastError ?? undefined],
                ])),
            );
        };

        await load();
        timer = setInterval(load, 10_000);
        return () => clearInterval(timer);
    }

    function trafficChart(series) {
        const W = 800;
        const H = 180;
        const pad = { l: 36, r: 8, t: 10, b: 20 };
        const el = svg('svg', { class: 'chart', viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'none', role: 'img', 'aria-label': 'Allowed and denied connections per sample' });
        if (!series || series.length < 2) {
            const t = svg('text', { x: W / 2, y: H / 2, 'text-anchor': 'middle', class: 'axis-label' });
            t.textContent = 'Waiting for traffic samples…';
            el.append(t);
            return el;
        }
        const max = Math.max(1, ...series.map((s) => Math.max(s.allowed, s.denied)));
        const x = (i) => pad.l + (i / (series.length - 1)) * (W - pad.l - pad.r);
        const y = (v) => pad.t + (1 - v / max) * (H - pad.t - pad.b);

        for (const frac of [0, 0.5, 1]) {
            const yy = y(max * frac);
            el.append(svg('line', { x1: pad.l, x2: W - pad.r, y1: yy, y2: yy, class: 'grid-line' }));
            const label = svg('text', { x: pad.l - 6, y: yy + 3, 'text-anchor': 'end', class: 'axis-label' });
            label.textContent = String(Math.round(max * frac));
            el.append(label);
        }
        for (const [key, cls] of [['allowed', 'allow'], ['denied', 'deny']]) {
            const pts = series.map((s, i) => `${x(i).toFixed(1)},${y(s[key]).toFixed(1)}`);
            el.append(svg('path', { d: `M${pts[0]} L${pts.slice(1).join(' L')} L${x(series.length - 1)},${y(0)} L${x(0)},${y(0)} Z`, class: `area-${cls}` }));
            el.append(svg('path', { d: `M${pts.join(' L')}`, class: `line-${cls}` }));
        }
        const first = svg('text', { x: pad.l, y: H - 4, class: 'axis-label' });
        first.textContent = fmt.clock(series[0].at);
        const last = svg('text', { x: W - pad.r, y: H - 4, 'text-anchor': 'end', class: 'axis-label' });
        last.textContent = fmt.clock(series.at(-1).at);
        el.append(first, last);
        return el;
    }

    /* ---------------------------------------------------------------- *
     * Rules
     * ---------------------------------------------------------------- */

    const PROTOCOLS = ['any', 'tcp', 'udp', 'icmp', 'icmpv6'];
    const PROFILES = ['Domain', 'Private', 'Public'];

    async function renderRules(page) {
        const filters = { q: '', direction: '', action: '', enabled: '' };
        let sort = { key: 'priority', order: 'asc' };
        const tableHost = h('div', null, h('div', { class: 'loading', text: 'Loading rules…' }));
        const analysisHost = h('div');
        const countLabel = h('span', { class: 'muted small' });

        const reload = async () => {
            try {
                const [list, analysis] = await Promise.all([
                    get(`/api/rules${qs({ ...filters, sort: sort.key, order: sort.order, limit: 1000 })}`),
                    get('/api/rules/analysis'),
                ]);
                countLabel.textContent = `${list.total} rule(s)`;
                const findingsByRule = new Map();
                for (const f of analysis.findings) {
                    if (!findingsByRule.has(f.ruleId)) findingsByRule.set(f.ruleId, []);
                    findingsByRule.get(f.ruleId).push(f);
                }
                clear(analysisHost);
                const serious = analysis.findings.filter((f) => f.severity === 'critical' || f.severity === 'high' || f.type === 'shadowed');
                if (serious.length) {
                    analysisHost.append(card(`Rule analysis — ${analysis.findings.length} finding(s)`, null,
                        h('ul', { class: 'list' }, analysis.findings.map((f) => h('li', null,
                            severityBadge(f.severity),
                            h('div', { class: 'list-main' },
                                h('div', { class: 'list-title', text: f.ruleName }),
                                h('div', { class: 'list-meta', text: `${f.type} — ${f.message}` }))))), { flush: true }));
                }
                fill(tableHost, rulesTable(list.rules, findingsByRule));
            } catch (err) {
                toastError(err);
            }
        };

        const rulesTable = (rules, findingsByRule) => dataTable([
            { label: 'Pri', class: 'num', sort: 'priority', render: (r) => r.priority },
            {
                label: 'On',
                sort: 'enabled',
                render: (r) => switchInput({
                    checked: r.enabled,
                    disabled: !can('rules:write'),
                    label: `${r.enabled ? 'Disable' : 'Enable'} ${r.name}`,
                    onChange: async (on, input) => {
                        try {
                            const res = await post(`/api/rules/${encodeURIComponent(r.id)}/${on ? 'enable' : 'disable'}`);
                            toast(`${on ? 'Enabled' : 'Disabled'} "${r.name}"`, 'ok');
                            if (res.os && !res.os.ok) toast(`OS: ${res.os.error}`, 'warn', 8000);
                            reload();
                        } catch (err) {
                            input.checked = !on;
                            toastError(err);
                        }
                    },
                }),
            },
            { label: 'Action', sort: 'action', render: (r) => actionBadge(r.action) },
            { label: 'Dir', sort: 'direction', render: (r) => (r.direction === 'inbound' ? 'In' : 'Out') },
            { label: 'Proto', sort: 'protocol', render: (r) => r.protocol.toUpperCase() },
            { label: 'Source', render: (r) => h('span', { class: 'mono', text: fmt.endpoint(r.srcAddress, r.srcPort) }) },
            { label: 'Destination', render: (r) => h('span', { class: 'mono', text: fmt.endpoint(r.dstAddress, r.dstPort) }) },
            {
                label: 'Name',
                sort: 'name',
                render: (r) => [
                    h('strong', { text: r.name }),
                    ' ',
                    ...(findingsByRule.get(r.id) ?? []).slice(0, 1).map((f) => h('span', { title: f.message }, badge(f.type, severityTone[f.severity]))),
                    ...(r.tags ?? []).map((t) => [' ', badge(t)]),
                    r.description ? h('span', { class: 'sub', text: r.description }) : null,
                ],
            },
            { label: 'OS', render: osBadge },
            { label: 'Hits', class: 'num', sort: 'hitCount', render: (r) => fmt.num(r.hitCount) },
            {
                label: '',
                render: (r) => h('div', { class: 'row-actions' },
                    h('button', { class: 'btn btn-ghost btn-sm', title: 'Show the native OS command', on: { click: () => previewRule(r) } }, 'Command'),
                    can('rules:write') ? h('button', { class: 'btn btn-ghost btn-sm', on: { click: () => editRule(r) } }, 'Edit') : null,
                    can('rules:write') ? h('button', { class: 'btn btn-ghost btn-sm', on: { click: () => deleteRule(r) } }, 'Delete') : null),
            },
        ], rules, {
            empty: 'No rules match. Create one, or start from Quick hardening.',
            rowClass: (r) => (r.enabled ? null : 'is-disabled'),
            sort,
            onSort: (key) => {
                sort = { key, order: sort.key === key && sort.order === 'asc' ? 'desc' : 'asc' };
                reload();
            },
        });

        const editRule = async (rule) => {
            const saved = await ruleEditor(rule);
            if (saved) reload();
        };

        const deleteRule = async (rule) => {
            const ok = await confirmDialog({
                title: 'Delete rule',
                message: `Delete "${rule.name}"? ${rule.osApplied ? 'It will also be removed from the operating system firewall.' : ''}`,
                confirmLabel: 'Delete rule',
            });
            if (!ok) return;
            try {
                await del(`/api/rules/${encodeURIComponent(rule.id)}`, { confirm: true });
                toast(`Deleted "${rule.name}"`, 'ok');
                reload();
            } catch (err) { toastError(err); }
        };

        const search = h('input', { type: 'search', placeholder: 'Search name, address, port, tag…', 'aria-label': 'Search rules', on: { input: debounce((e) => { filters.q = e.target.value; reload(); }) } });
        const filterSelect = (key, options, label) => select(key, options, '', { 'aria-label': label, on: { change: (e) => { filters[key] = e.target.value; reload(); } } });

        const actions = h('div', { class: 'btn-row' },
            h('button', { class: 'btn', on: { click: () => packetTester() } }, 'Test a packet'),
            can('rules:apply') ? h('button', { class: 'btn', on: { click: (e) => syncRules(e.currentTarget, reload) } }, 'Check OS sync') : null,
            can('rules:apply') ? h('button', { class: 'btn', on: { click: (e) => applyAll(e.currentTarget, reload) } }, 'Apply all to OS') : null,
            can('backup:read') ? downloadLink('Export', '/api/rules/export/json') : null,
            can('rules:write') ? h('button', { class: 'btn btn-primary', on: { click: () => editRule(null) } }, '+ New rule') : null);

        page.append(
            h('div', { class: 'toolbar' },
                search,
                filterSelect('direction', [['', 'All directions'], ['inbound', 'Inbound'], ['outbound', 'Outbound']], 'Direction'),
                filterSelect('action', [['', 'All actions'], ['allow', 'Allow'], ['deny', 'Deny']], 'Action'),
                filterSelect('enabled', [['', 'Enabled & disabled'], ['true', 'Enabled only'], ['false', 'Disabled only']], 'State'),
                countLabel,
                h('div', { class: 'grow' }),
                actions),
            analysisHost,
            card(null, null, tableHost, { flush: true }),
            h('p', { class: 'muted small', text: 'Rules are evaluated top-down by priority (lower first); the first match decides. On Windows the OS applies any matching Block rule before Allow rules regardless of order — the packet tester warns when that changes the outcome.' }));

        await reload();
    }

    /** Create (rule = null) or edit a rule. Resolves true when saved. */
    function ruleEditor(rule) {
        const isNew = !rule;
        const r = rule ?? {
            name: '', description: '', direction: 'inbound', action: 'deny', protocol: 'tcp',
            srcAddress: 'any', dstAddress: 'any', srcPort: 'any', dstPort: 'any', iface: 'any',
            profiles: ['Any'], program: '', priority: 100, enabled: true, tags: [],
        };
        const allProfiles = (r.profiles ?? ['Any']).includes('Any');

        return modal({
            title: isNew ? 'New rule' : `Edit rule — ${r.name}`,
            wide: true,
            build: (close) => {
                const error = h('p', { class: 'form-error', role: 'alert' });
                const previewHost = h('div');
                const form = h('form', { class: 'form-grid', novalidate: true },
                    h('label', { class: 'span-2' }, 'Name', h('input', { name: 'name', value: r.name, required: true, maxlength: 96, autofocus: true })),
                    h('label', null, 'Priority', h('span', { class: 'field-hint', text: 'Lower is evaluated first' }), h('input', { name: 'priority', type: 'number', min: 1, max: 65535, value: r.priority })),
                    h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'enabled', checked: r.enabled !== false }), 'Enabled'),
                    h('label', null, 'Direction', select('direction', [['inbound', 'Inbound'], ['outbound', 'Outbound']], r.direction)),
                    h('label', null, 'Action', select('action', [['allow', 'Allow'], ['deny', 'Deny']], r.action)),
                    h('label', null, 'Protocol', select('protocol', PROTOCOLS.map((p) => [p, p.toUpperCase()]), r.protocol)),
                    h('label', null, 'Interface', h('input', { name: 'iface', value: r.iface, placeholder: 'any' })),
                    h('label', { class: 'span-2' }, 'Source address', h('span', { class: 'field-hint', text: 'any, 10.0.0.5, 10.0.0.0/8, 10.0.0.1-10.0.0.9, or a comma list' }), h('input', { name: 'srcAddress', value: r.srcAddress, class: 'mono' })),
                    h('label', null, 'Source port', h('input', { name: 'srcPort', value: r.srcPort, class: 'mono' })),
                    h('label', { class: 'span-2' }, 'Destination address', h('input', { name: 'dstAddress', value: r.dstAddress, class: 'mono' })),
                    h('label', null, 'Destination port', h('span', { class: 'field-hint', text: 'TCP/UDP only: 443, 8000-8100, 80,443' }), h('input', { name: 'dstPort', value: r.dstPort, class: 'mono' })),
                    h('fieldset', { class: 'span-all check', style: 'border:0;padding:0;margin:0;flex-wrap:wrap' },
                        h('legend', { class: 'field-hint', text: 'Windows profiles (none checked = all profiles)', style: 'padding:0;margin-bottom:4px' }),
                        PROFILES.map((p) => h('label', { class: 'check' },
                            h('input', { type: 'checkbox', name: `profile-${p}`, value: p, 'data-group': 'profiles', checked: !allProfiles && (r.profiles ?? []).includes(p) }), p))),
                    h('label', { class: 'span-all' }, 'Program', h('span', { class: 'field-hint', text: 'Optional absolute path, e.g. C:\\Program Files\\App\\app.exe (Windows application rule)' }), h('input', { name: 'program', value: r.program ?? '', class: 'mono' })),
                    h('label', { class: 'span-all' }, 'Description', h('input', { name: 'description', value: r.description ?? '', maxlength: 400 })),
                    h('label', { class: 'span-all' }, 'Tags', h('span', { class: 'field-hint', text: 'Comma-separated' }), h('input', { name: 'tags', value: (r.tags ?? []).join(', ') })));

                const payload = () => {
                    const f = formData(form);
                    return {
                        name: f.name.trim(),
                        description: f.description.trim(),
                        direction: f.direction,
                        action: f.action,
                        protocol: f.protocol,
                        srcAddress: f.srcAddress.trim() || 'any',
                        dstAddress: f.dstAddress.trim() || 'any',
                        srcPort: f.srcPort.trim() || 'any',
                        dstPort: f.dstPort.trim() || 'any',
                        iface: f.iface.trim() || 'any',
                        priority: Number(f.priority) || 100,
                        enabled: f.enabled,
                        profiles: f.profiles.length ? f.profiles : ['Any'],
                        program: f.program.trim(),
                        tags: f.tags.split(',').map((t) => t.trim()).filter(Boolean),
                    };
                };

                const save = async (button) => {
                    error.textContent = '';
                    await busy(button, async () => {
                        try {
                            const res = isNew
                                ? await post('/api/rules', payload())
                                : await patch(`/api/rules/${encodeURIComponent(r.id)}`, payload());
                            toast(`${isNew ? 'Created' : 'Saved'} "${res.rule.name}"`, 'ok');
                            if (res.os && !res.os.ok && !res.os.skipped) toast(`OS apply failed: ${res.os.error}`, 'warn', 9000);
                            close(true);
                        } catch (err) {
                            error.textContent = [err.message, ...(Array.isArray(err.details) ? err.details.map((d) => `${d.field}: ${d.message}`) : [])].join(' — ');
                        }
                    });
                };

                form.addEventListener('submit', (e) => { e.preventDefault(); save(form.querySelector('[type=submit]')); });

                return {
                    body: [form, error, previewHost],
                    foot: [
                        h('button', {
                            class: 'btn btn-ghost',
                            type: 'button',
                            on: {
                                click: async () => {
                                    try {
                                        const p = await post('/api/rules/preview', payload());
                                        fill(previewHost, nativePreview(p));
                                    } catch (err) {
                                        fill(previewHost, h('p', { class: 'form-error', text: err.message }));
                                    }
                                },
                            },
                        }, 'Preview OS command'),
                        h('div', { class: 'grow' }),
                        h('button', { class: 'btn', type: 'button', on: { click: () => close(false) } }, 'Cancel'),
                        h('button', { class: 'btn btn-primary', type: 'button', on: { click: (e) => save(e.currentTarget) } }, isNew ? 'Create rule' : 'Save changes'),
                    ],
                };
            },
        });
    }

    function nativePreview(p) {
        const native = p.native ?? {};
        return h('div', { class: 'grid', style: 'gap:10px' },
            h('div', { class: 'muted small', text: p.summary }),
            h('h3', { text: native.primary ?? native.kind ?? 'Command' }),
            h('pre', { class: 'code', text: (native.lines ?? []).join('\n') }),
            (native.alternatives ?? []).map((alt) => [
                h('h3', { text: alt.label }),
                h('pre', { class: 'code', text: (alt.lines ?? []).join('\n') }),
            ]),
            native.guiPath ? h('p', { class: 'muted small', text: `GUI: ${native.guiPath}` }) : null,
            native.note ? h('p', { class: 'muted small', text: native.note }) : null);
    }

    async function previewRule(rule) {
        const { id, osRuleName, osApplied, osLastError, osAppliedAt, hitCount, lastHitAt, createdAt, updatedAt, createdBy, updatedBy, revision, ...input } = rule;
        try {
            const p = await post('/api/rules/preview', input);
            modal({ title: `OS command — ${rule.name}`, wide: true, build: () => ({ body: nativePreview(p) }) });
        } catch (err) { toastError(err); }
    }

    function packetTester() {
        modal({
            title: 'Test a packet against the policy',
            wide: true,
            build: () => {
                const result = h('div');
                const form = h('form', { class: 'form-grid' },
                    h('label', null, 'Direction', select('direction', [['inbound', 'Inbound'], ['outbound', 'Outbound']], 'inbound')),
                    h('label', null, 'Protocol', select('protocol', ['tcp', 'udp', 'icmp'].map((p) => [p, p.toUpperCase()]), 'tcp')),
                    h('label', null, 'Source IP', h('input', { name: 'srcAddress', placeholder: '203.0.113.10', class: 'mono', autofocus: true })),
                    h('label', null, 'Source port', h('input', { name: 'srcPort', placeholder: 'any', class: 'mono' })),
                    h('label', null, 'Destination IP', h('input', { name: 'dstAddress', placeholder: 'this host', class: 'mono' })),
                    h('label', null, 'Destination port', h('input', { name: 'dstPort', placeholder: '3389', class: 'mono' })),
                    h('div', { class: 'span-all btn-row' }, h('button', { class: 'btn btn-primary', type: 'submit' }, 'Evaluate')));
                form.addEventListener('submit', async (e) => {
                    e.preventDefault();
                    const f = formData(form);
                    try {
                        const r = await post('/api/rules/test', {
                            direction: f.direction, protocol: f.protocol,
                            srcAddress: f.srcAddress.trim() || undefined, dstAddress: f.dstAddress.trim() || undefined,
                            srcPort: f.srcPort.trim() || undefined, dstPort: f.dstPort.trim() || undefined,
                        });
                        fill(result,
                            h('div', { class: 'verdict' },
                                h('div', { class: `verdict-word ${r.decision}`, text: r.decision.toUpperCase() }),
                                h('div', null,
                                    h('div', { text: r.explanation }),
                                    r.matchCount > 1 ? h('div', { class: 'muted small', text: `${r.matchCount} rules match; only the first decides.` }) : null)),
                            r.note ? h('div', { class: 'banner banner-warn', style: 'margin-top:10px' }, h('p', { text: `${r.note} Windows would ${r.wfpDecision.toUpperCase()} this packet.` })) : null);
                    } catch (err) {
                        fill(result, h('p', { class: 'form-error', text: err.message }));
                    }
                });
                return { body: [form, result] };
            },
        });
    }

    async function applyAll(button, reload) {
        const ok = await confirmDialog({
            title: 'Apply all rules to the OS',
            message: 'Write every SentryFW rule into the operating system firewall now. Existing SentryFW-managed OS rules are replaced; rules created outside SentryFW are not touched.',
            confirmLabel: 'Apply rules',
            danger: false,
        });
        if (!ok) return;
        const res = await busy(button, () => post('/api/rules/apply', { confirm: true }));
        if (!res) return;
        toast(`Applied ${res.applied}/${res.total} rule(s)`, res.failed.length ? 'warn' : 'ok');
        if (res.failed.length) {
            modal({
                title: `${res.failed.length} rule(s) could not be applied`,
                build: () => ({ body: h('ul', { class: 'list' }, res.failed.map((f) => h('li', null, h('div', { class: 'list-main' }, h('div', { class: 'list-title', text: f.name }), h('div', { class: 'list-meta', text: f.error }), f.hint ? h('div', { class: 'list-meta', text: f.hint }) : null)))) }),
            });
        }
        reload();
    }

    async function syncRules(button, reload) {
        const res = await busy(button, () => post('/api/rules/sync', {}));
        if (!res) return;
        if (!res.supported) { toast(res.reason, 'warn'); return; }
        if (!res.ok) { toast(`${res.error}${res.hint ? ` — ${res.hint}` : ''}`, 'bad', 9000); return; }
        if (res.inSync) { toast(`In sync: ${res.storeRuleCount} rule(s) match the OS firewall`, 'ok'); return; }
        modal({
            title: `Drift: ${res.drift.length} discrepancy/ies`,
            wide: true,
            build: (close) => ({
                body: dataTable([
                    { label: 'Type', render: (d) => badge(d.type, d.type === 'not-applied' ? '' : 'warn') },
                    { label: 'Rule', render: (d) => d.name ?? d.osName },
                    { label: 'Detail', render: (d) => d.detail },
                ], res.drift),
                foot: [
                    h('button', { class: 'btn', on: { click: () => close() } }, 'Close'),
                    h('button', {
                        class: 'btn btn-primary',
                        on: {
                            click: async (e) => {
                                const fixed = await busy(e.currentTarget, () => post('/api/rules/sync', { repair: true, confirm: true }));
                                if (fixed) { toast(`Repair: ${fixed.repaired?.length ?? 0} action(s) taken`, 'ok'); close(); reload(); }
                            },
                        },
                    }, 'Repair drift'),
                ],
            }),
        });
    }

    /* ---------------------------------------------------------------- *
     * Traffic
     * ---------------------------------------------------------------- */

    async function renderTraffic(page, params) {
        let tab = params.get('tab') ?? 'tracked';
        const filters = { q: '', direction: '', decision: '', scope: '', hideLoopback: true };
        const pageState = { offset: 0, limit: 100 };
        const host = h('div');
        const statusHost = h('div', { class: 'btn-row' });
        const toolbarHost = h('div', { class: 'toolbar' });
        let timer = null;

        const tabs = [['tracked', 'Tracked connections'], ['live', 'Live socket table'], ['listeners', 'Listeners'], ['interfaces', 'Interfaces']];
        const tabBar = h('div', { class: 'btn-row', role: 'tablist' });
        const drawTabs = () => {
            fill(tabBar, tabs.map(([id, label]) => h('button', {
                class: `btn btn-sm${tab === id ? ' btn-primary' : ''}`,
                role: 'tab',
                'aria-selected': String(tab === id),
                on: { click: () => { tab = id; pageState.offset = 0; history.replaceState(null, '', `#/traffic?tab=${id}`); drawTabs(); drawToolbar(); load(); } },
            }, label)));
        };

        const drawToolbar = () => {
            clear(toolbarHost);
            if (tab === 'tracked' || tab === 'live') {
                append(toolbarHost, [
                    h('input', { type: 'search', placeholder: 'Address, port, process…', value: filters.q, 'aria-label': 'Filter connections', on: { input: debounce((e) => { filters.q = e.target.value; pageState.offset = 0; load(); }) } }),
                    tab === 'tracked' ? [
                        select('direction', [['', 'All directions'], ['inbound', 'Inbound'], ['outbound', 'Outbound']], filters.direction, { on: { change: (e) => { filters.direction = e.target.value; load(); } } }),
                        select('decision', [['', 'Any decision'], ['allow', 'Allowed'], ['deny', 'Denied']], filters.decision, { on: { change: (e) => { filters.decision = e.target.value; load(); } } }),
                        select('scope', [['', 'Any remote'], ['public', 'Public'], ['private', 'Private'], ['loopback', 'Loopback']], filters.scope, { on: { change: (e) => { filters.scope = e.target.value; load(); } } }),
                        h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: filters.hideLoopback, on: { change: (e) => { filters.hideLoopback = e.target.checked; pageState.offset = 0; load(); } } }), 'Hide loopback'),
                    ] : null]);
            }
        };

        const drawStatus = (m) => {
            fill(statusHost,
                m.running ? badge(`Monitor running · every ${m.intervalSeconds}s`, 'ok') : badge('Monitor stopped', 'warn'),
                h('span', { class: 'muted small', text: m.lastSampleAt ? `last sample ${fmt.rel(m.lastSampleAt)}` : '' }),
                h('button', { class: 'btn btn-sm', on: { click: async (e) => { await busy(e.currentTarget, () => post('/api/traffic/sample')); load(); } } }, 'Sample now'),
                can('settings:write') ? h('button', {
                    class: 'btn btn-sm',
                    on: { click: async (e) => { const s = await busy(e.currentTarget, () => post(`/api/traffic/monitor/${m.running ? 'stop' : 'start'}`)); if (s) drawStatus(s); } },
                }, m.running ? 'Stop monitor' : 'Start monitor') : null);
        };

        const blockButton = (address) => (can('blocklist:write') && address && !['0.0.0.0', '::', '*', '127.0.0.1', '::1'].includes(address)
            ? h('button', { class: 'btn btn-ghost btn-sm', on: { click: () => quickBlock(address) } }, 'Block')
            : null);

        const load = async () => {
            try {
                get('/api/traffic/monitor').then(drawStatus).catch(() => {});
                if (tab === 'tracked') {
                    const d = await get(`/api/traffic/connections${qs({ ...filters, hideLoopback: filters.hideLoopback && filters.scope !== 'loopback', offset: pageState.offset, limit: pageState.limit })}`);
                    fill(host, card(null, null, [
                        dataTable([
                            { label: 'Proto', render: (c) => c.protocol.toUpperCase() },
                            { label: 'Dir', render: (c) => (c.direction === 'inbound' ? 'In' : 'Out') },
                            { label: 'Local', render: (c) => h('span', { class: 'mono', text: `${c.localAddress}:${c.localPort}` }) },
                            { label: 'Remote', render: (c) => [h('span', { class: 'mono', text: `${c.remoteAddress}:${c.remotePort}` }), h('span', { class: 'sub', text: [c.remoteScope, c.service].filter(Boolean).join(' · ') })] },
                            { label: 'State', render: (c) => c.state },
                            { label: 'Process', render: (c) => (c.process ? `${c.process}${c.pid ? ` (${c.pid})` : ''}` : '') },
                            { label: 'Policy', render: (c) => [actionBadge(c.decision), c.blocklisted ? [' ', badge('Blocklist', 'bad')] : null, h('span', { class: 'sub', text: c.matchedRuleName ?? (c.usedDefault ? 'default policy' : '') })] },
                            { label: 'Seen', render: (c) => [fmt.rel(c.lastSeenAt), h('span', { class: 'sub', text: `${c.observations}×` })] },
                            { label: '', render: (c) => blockButton(c.remoteAddress) },
                        ], d.connections, { empty: 'No connections tracked yet. The monitor samples the socket table periodically; press "Sample now" to take one immediately.' }),
                        d.total > pageState.limit ? pager({ ...pageState, total: d.total, onPage: (o) => { pageState.offset = o; load(); } }) : null,
                    ], { flush: true }));
                } else if (tab === 'live') {
                    const d = await get(`/api/traffic/connections${qs({ live: true, limit: 2000 })}`);
                    const needle = filters.q.toLowerCase();
                    const rows = d.connections.filter((c) => c.state !== 'listen' && c.state !== 'bound')
                        .filter((c) => !needle || `${c.localAddress}:${c.localPort} ${c.remoteAddress}:${c.remotePort} ${c.process ?? ''} ${c.state}`.toLowerCase().includes(needle));
                    fill(host, card(`${rows.length} socket(s) · source: ${d.source}`, null, dataTable([
                        { label: 'Proto', render: (c) => c.protocol.toUpperCase() },
                        { label: 'Local', render: (c) => h('span', { class: 'mono', text: `${c.localAddress}:${c.localPort}` }) },
                        { label: 'Remote', render: (c) => h('span', { class: 'mono', text: `${c.remoteAddress}:${c.remotePort}` }) },
                        { label: 'State', render: (c) => c.state },
                        { label: 'Process', render: (c) => c.process ?? '' },
                        { label: '', render: (c) => blockButton(c.remoteAddress) },
                    ], rows.slice(0, 500), { empty: 'The socket table is empty or could not be read.' }), { flush: true }));
                } else if (tab === 'listeners') {
                    const d = await get('/api/traffic/listeners');
                    const rows = d.listeners.slice().sort((a, b) => a.localPort - b.localPort);
                    fill(host, card(`${rows.length} listening socket(s) · source: ${d.source}`, null, dataTable([
                        { label: 'Port', class: 'num', render: (l) => `${l.protocol}/${l.localPort}` },
                        { label: 'Address', render: (l) => h('span', { class: 'mono', text: l.localAddress }) },
                        { label: 'Exposure', render: (l) => badge(l.exposure, l.exposure === 'all-interfaces' ? 'warn' : l.exposure === 'loopback-only' ? '' : 'info') },
                        { label: 'Service', render: (l) => l.wellKnown ?? '' },
                        { label: 'Process', render: (l) => (l.process ? `${l.process}${l.pid ? ` (${l.pid})` : ''}` : '') },
                    ], rows, { empty: d.reason ?? 'No listening sockets found.' }), { flush: true }));
                } else {
                    const d = await get('/api/traffic/interfaces');
                    fill(host, card(`${d.interfaces.length} interface(s) · source: ${d.source}`, null, dataTable([
                        { label: 'Name', render: (i) => [h('strong', { text: i.name }), i.description && i.description !== i.name ? h('span', { class: 'sub', text: i.description }) : null] },
                        { label: 'Status', render: (i) => badge(i.status, i.status === 'up' ? 'ok' : '') },
                        { label: 'IPv4', render: (i) => h('span', { class: 'mono', text: i.primaryIPv4 ?? '' }) },
                        { label: 'IPv6', render: (i) => h('span', { class: 'mono', text: i.primaryIPv6 ?? '' }) },
                        { label: 'MAC', render: (i) => h('span', { class: 'mono', text: i.mac ?? '' }) },
                        { label: 'Gateway', render: (i) => i.gateway ?? '' },
                    ], d.interfaces), { flush: true }));
                }
            } catch (err) {
                toastError(err);
            }
        };

        page.append(h('div', { class: 'toolbar' }, tabBar, h('div', { class: 'grow' }), statusHost), toolbarHost, host);
        drawTabs();
        drawToolbar();
        await load();
        timer = setInterval(() => { if (tab === 'tracked') load(); }, 15_000);
        return () => clearInterval(timer);
    }

    async function quickBlock(address) {
        const reason = h('input', { name: 'reason', placeholder: 'Why?', maxlength: 300, autofocus: true });
        const ttl = select('ttl', [['24', '24 hours'], ['168', '7 days'], ['0', 'Permanently']], '24');
        const ok = await confirmDialog({
            title: `Block ${address}`,
            message: `Deny all inbound and outbound traffic to and from ${address}. Two priority-1 deny rules are created.`,
            confirmLabel: 'Block address',
            extra: h('div', { class: 'form-grid' }, h('label', null, 'Reason', reason), h('label', null, 'Duration', ttl)),
        });
        if (!ok) return;
        try {
            const res = await post('/api/blocklist', { target: address, reason: reason.value, ttlHours: Number(ttl.value) });
            toast(`Blocked ${res.entry.target}`, 'ok');
            for (const w of res.entry.warnings ?? []) toast(w, 'warn', 9000);
        } catch (err) { toastError(err); }
    }

    /* ---------------------------------------------------------------- *
     * Detection
     * ---------------------------------------------------------------- */

    async function renderDetection(page) {
        const filters = { severity: '', acknowledged: 'false', q: '' };
        const tilesHost = h('div');
        const host = h('div');

        const load = async () => {
            try {
                const [summary, list] = await Promise.all([
                    get('/api/detection/summary'),
                    get(`/api/detection/findings${qs({ ...filters, limit: 500 })}`),
                ]);
                state.openFindings = summary.open;
                updateNavCounts();
                fill(tilesHost, h('div', { class: 'tiles' },
                    tile('Open', fmt.num(summary.open), `${fmt.num(summary.total)} total`, summary.open ? 'warn' : ''),
                    tile('Critical', fmt.num(summary.bySeverity.critical), '', summary.bySeverity.critical ? 'bad' : ''),
                    tile('High', fmt.num(summary.bySeverity.high), '', summary.bySeverity.high ? 'bad' : ''),
                    tile('Medium', fmt.num(summary.bySeverity.medium)),
                    tile('Low', fmt.num(summary.bySeverity.low)),
                    tile('Tracked remotes', fmt.num(summary.trackedRemotes), summary.enabled ? `last run ${fmt.rel(summary.lastRunAt)}` : 'detection disabled')));
                fill(host, card(null, null, dataTable([
                    { label: 'Severity', render: (f) => severityBadge(f.severity) },
                    { label: 'Finding', render: (f) => [h('strong', { text: f.title }), h('span', { class: 'sub', text: f.detail })] },
                    { label: 'Remote', render: (f) => h('span', { class: 'mono', text: f.remoteAddress ?? '' }) },
                    { label: 'Seen', render: (f) => [`${f.occurrences}×`, h('span', { class: 'sub', text: `${fmt.rel(f.firstSeenAt)} → ${fmt.rel(f.lastSeenAt)}` })] },
                    { label: 'Recommendation', render: (f) => h('span', { class: 'small', text: f.recommendation ?? '' }) },
                    {
                        label: '',
                        render: (f) => h('div', { class: 'row-actions' },
                            f.remoteAddress && can('blocklist:write') ? h('button', { class: 'btn btn-ghost btn-sm', on: { click: () => quickBlock(f.remoteAddress) } }, 'Block') : null,
                            f.acknowledged
                                ? h('span', { class: 'muted small', text: `ack by ${f.acknowledgedBy}` })
                                : h('button', { class: 'btn btn-sm', on: { click: async (e) => { await busy(e.currentTarget, () => post(`/api/detection/findings/${encodeURIComponent(f.id)}/acknowledge`)); load(); } } }, 'Acknowledge')),
                    },
                ], list.findings, { empty: filters.acknowledged === 'false' ? 'No open findings. Detection runs on each traffic sample.' : 'No findings match.' }), { flush: true }));
            } catch (err) { toastError(err); }
        };

        page.append(
            tilesHost,
            h('div', { class: 'toolbar' },
                h('input', { type: 'search', placeholder: 'Search findings…', 'aria-label': 'Search findings', on: { input: debounce((e) => { filters.q = e.target.value; load(); }) } }),
                select('severity', [['', 'All severities'], ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low']], '', { on: { change: (e) => { filters.severity = e.target.value; load(); } } }),
                select('acknowledged', [['false', 'Open only'], ['', 'Open & acknowledged'], ['true', 'Acknowledged only']], 'false', { on: { change: (e) => { filters.acknowledged = e.target.value; load(); } } })),
            host);
        await load();
        const timer = setInterval(load, 15_000);
        return () => clearInterval(timer);
    }

    /* ---------------------------------------------------------------- *
     * Blocklist
     * ---------------------------------------------------------------- */

    async function renderBlocklist(page) {
        const host = h('div');
        let q = '';

        const load = async () => {
            try {
                const d = await get(`/api/blocklist${qs({ q })}`);
                fill(host, card(`${d.total} entr${d.total === 1 ? 'y' : 'ies'}`, null, dataTable([
                    { label: 'Target', render: (e) => h('strong', { class: 'mono', text: e.target }) },
                    { label: 'State', render: (e) => (e.active ? badge('Blocked', 'bad') : badge('Expired')) },
                    { label: 'Expires', render: (e) => (e.expiresAt ? [fmt.time(e.expiresAt), h('span', { class: 'sub', text: e.active ? `in ${fmt.duration(e.expiresIn)}` : '' })] : 'never') },
                    { label: 'Source', render: (e) => [e.source, e.feed ? h('span', { class: 'sub', text: e.feed }) : null] },
                    { label: 'Reason', render: (e) => [e.reason ?? '', ...(e.warnings ?? []).map((w) => h('span', { class: 'sub', text: `⚠ ${w}` }))] },
                    { label: 'Added', render: (e) => [fmt.rel(e.addedAt), h('span', { class: 'sub', text: e.addedBy })] },
                    {
                        label: '',
                        render: (e) => (can('blocklist:write') ? h('button', {
                            class: 'btn btn-ghost btn-sm',
                            on: {
                                click: async () => {
                                    if (!await confirmDialog({ title: 'Unblock', message: `Remove ${e.target} from the blocklist and delete its deny rules?`, confirmLabel: 'Unblock' })) return;
                                    try {
                                        await del(`/api/blocklist/${encodeURIComponent(e.target)}`);
                                        toast(`Unblocked ${e.target}`, 'ok');
                                        load();
                                    } catch (err) { toastError(err); }
                                },
                            },
                        }, 'Unblock') : null),
                    },
                ], d.entries, { empty: 'Nothing is blocked.' }), { flush: true }));
            } catch (err) { toastError(err); }
        };

        if (can('blocklist:write')) {
            const error = h('p', { class: 'form-error', role: 'alert' });
            const form = h('form', { class: 'form-grid' },
                h('label', { class: 'span-2' }, 'IP address or CIDR', h('input', { name: 'target', placeholder: '203.0.113.9 or 198.51.100.0/24', class: 'mono', required: true })),
                h('label', { class: 'span-2' }, 'Reason', h('input', { name: 'reason', maxlength: 300 })),
                h('label', null, 'Duration', select('ttlHours', [['0', 'Permanent'], ['1', '1 hour'], ['24', '24 hours'], ['168', '7 days'], ['720', '30 days']], '24')),
                h('label', null, 'Direction', select('direction', [['both', 'Both'], ['inbound', 'Inbound only'], ['outbound', 'Outbound only']], 'both')),
                h('div', { class: 'span-all btn-row' },
                    h('button', { class: 'btn btn-primary', type: 'submit' }, 'Block'),
                    h('button', { class: 'btn', type: 'button', on: { click: () => importFeed(load) } }, 'Import list…'),
                    error));
            form.addEventListener('submit', async (e) => {
                e.preventDefault();
                error.textContent = '';
                const f = formData(form);
                try {
                    const res = await post('/api/blocklist', { target: f.target.trim(), reason: f.reason, ttlHours: Number(f.ttlHours), direction: f.direction });
                    toast(`Blocked ${res.entry.target}`, 'ok');
                    for (const w of res.entry.warnings ?? []) toast(w, 'warn', 9000);
                    form.reset();
                    load();
                } catch (err) { error.textContent = err.message; }
            });
            page.append(card('Block an address', null, form));
        }

        page.append(
            h('div', { class: 'toolbar' }, h('input', { type: 'search', placeholder: 'Search target, reason, owner…', 'aria-label': 'Search blocklist', on: { input: debounce((e) => { q = e.target.value; load(); }) } })),
            host);
        await load();
    }

    function importFeed(reload) {
        modal({
            title: 'Import addresses',
            build: (close) => {
                const text = h('textarea', { placeholder: '# One IP or CIDR per line\n203.0.113.9\n198.51.100.0/24', autofocus: true });
                const reason = h('input', { value: 'Imported list', maxlength: 300 });
                const rules = h('input', { type: 'checkbox', checked: true });
                return {
                    body: [
                        h('label', null, 'Addresses', text),
                        h('label', null, 'Reason', reason),
                        h('label', { class: 'check' }, rules, 'Create deny rules for each entry'),
                    ],
                    foot: [
                        h('button', { class: 'btn', on: { click: () => close() } }, 'Cancel'),
                        h('button', {
                            class: 'btn btn-primary',
                            on: {
                                click: async (e) => {
                                    const entries = text.value.split(/\r?\n/).map((l) => l.replace(/#.*/, '').trim()).filter(Boolean).map((target) => ({ target }));
                                    if (!entries.length) { toast('Nothing to import', 'warn'); return; }
                                    const res = await busy(e.currentTarget, () => post('/api/blocklist/import', { entries, reason: reason.value, createRules: rules.checked }));
                                    if (res) {
                                        toast(`Imported ${res.added ?? 0}, skipped ${res.skipped?.length ?? 0}${res.invalid?.length ? `, ${res.invalid.length} invalid` : ''}`, res.invalid?.length ? 'warn' : 'ok', 7000);
                                        close();
                                        reload();
                                    }
                                },
                            },
                        }, 'Import'),
                    ],
                };
            },
        });
    }

    /* ---------------------------------------------------------------- *
     * Scenarios
     * ---------------------------------------------------------------- */

    async function renderScenarios(page) {
        let data;
        try {
            data = await get('/api/scenarios');
        } catch (err) { toastError(err); return; }

        page.append(
            h('p', { class: 'muted', text: 'Each recipe creates ordinary, editable rules tagged "scenario". Review them on the Rules page before enabling OS enforcement.' }),
            h('div', { class: 'grid grid-3' }, data.scenarios.map((s) => {
                const form = h('form', { class: 'grid', style: 'gap:10px' },
                    s.fields.map((f) => h('label', null, f.label, h('input', { name: f.name, placeholder: f.placeholder ?? '', required: !!f.required, class: 'mono' }))),
                    s.id === 'restrict-outbound' ? h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'enableDenyAll' }), 'Enable the final deny-all rule now') : null,
                    h('button', { class: 'btn btn-primary', type: 'submit' }, 'Apply'));
                form.addEventListener('submit', async (e) => {
                    e.preventDefault();
                    const res = await busy(form.querySelector('button[type=submit]'), () => post(`/api/scenarios/${encodeURIComponent(s.id)}`, formData(form)));
                    if (!res) return;
                    const created = res.created ?? res.rules ?? [];
                    const failed = created.filter((c) => c.error);
                    toast(failed.length ? `${created.length - failed.length} rule(s) created, ${failed.length} failed: ${failed.map((f) => f.error).join('; ')}` : `${s.label}: done`, failed.length ? 'warn' : 'ok', 8000);
                    form.reset();
                });
                return card(s.label, null, [h('p', { class: 'muted small', text: s.description }), form]);
            })));
    }

    /* ---------------------------------------------------------------- *
     * Logs
     * ---------------------------------------------------------------- */

    const LEVELS = ['debug', 'info', 'warn', 'error', 'critical'];
    const CATEGORIES = ['system', 'auth', 'rule', 'firewall', 'traffic', 'detection', 'blocklist', 'config', 'backup', 'error'];

    async function renderLogs(page) {
        const filters = { q: '', level: ['info', 'warn', 'error', 'critical'], category: '', outcome: '' };
        const pageState = { offset: 0, limit: 100 };
        const host = h('div');
        let source = null;
        const liveDot = h('span', { class: 'live-dot' });
        const liveBtn = h('button', { class: 'btn btn-sm', on: { click: () => toggleLive() } }, liveDot, ' Live');
        let rows = [];

        const matches = (e) => (!filters.level.length || filters.level.includes(e.level))
            && (!filters.category || e.category === filters.category)
            && (!filters.outcome || e.outcome === filters.outcome)
            && (!filters.q || `${e.message} ${e.action} ${e.source ?? ''} ${e.actor ?? ''}`.toLowerCase().includes(filters.q.toLowerCase()));

        const draw = (total) => {
            fill(host, card(null, null, [
                dataTable([
                    { label: 'Time', render: (e) => h('span', { class: 'nowrap', title: e.ts, text: fmt.time(e.ts) }) },
                    { label: 'Level', render: (e) => levelBadge(e.level) },
                    { label: 'Category', render: (e) => e.category },
                    { label: 'Message', render: (e) => [e.message, e.action ? h('span', { class: 'sub mono', text: e.action }) : null] },
                    { label: 'Actor / source', render: (e) => [e.actor ?? '', e.source ? h('span', { class: 'sub mono', text: e.source }) : null] },
                    { label: 'Outcome', render: (e) => (e.outcome ? badge(e.outcome, e.outcome === 'denied' ? 'bad' : e.outcome === 'suspicious' ? 'warn' : 'ok') : '') },
                ], rows, { empty: 'No events match these filters.' }),
                source ? null : pager({ ...pageState, total, onPage: (o) => { pageState.offset = o; load(); } }),
            ], { flush: true }));
        };

        const params = () => ({ q: filters.q, level: filters.level, category: filters.category, outcome: filters.outcome });

        const load = async () => {
            try {
                const d = await get(`/api/logs${qs({ ...params(), offset: pageState.offset, limit: pageState.limit })}`);
                rows = d.events;
                draw(d.total);
            } catch (err) { toastError(err); }
        };

        const toggleLive = () => {
            if (source) {
                source.close();
                source = null;
                liveDot.classList.remove('on');
                load();
                return;
            }
            pageState.offset = 0;
            source = new EventSource('/api/events/stream');
            liveDot.classList.add('on');
            source.addEventListener('log', (msg) => {
                let e;
                try { e = JSON.parse(msg.data); } catch { return; }
                if (!matches(e)) return;
                rows = [e, ...rows].slice(0, 300);
                draw(rows.length);
            });
            source.addEventListener('error', () => {
                if (source?.readyState === EventSource.CLOSED) { liveDot.classList.remove('on'); source = null; }
            });
            draw(rows.length);
        };

        const levelChecks = h('div', { class: 'btn-row' }, LEVELS.map((l) => h('label', { class: 'check' },
            h('input', { type: 'checkbox', checked: filters.level.includes(l), on: { change: (e) => { filters.level = e.target.checked ? [...filters.level, l] : filters.level.filter((x) => x !== l); pageState.offset = 0; load(); } } }), l)));

        const exportHref = (format) => `/api/logs/export${qs({ ...params(), format })}`;
        const exportMenu = can('logs:export')
            ? h('div', { class: 'btn-row' }, ['csv', 'json', 'ndjson'].map((f) => h('a', {
                class: 'btn btn-sm',
                href: exportHref(f),
                download: '',
                on: { click: (e) => { e.currentTarget.href = exportHref(f); } },
            }, `Export ${f.toUpperCase()}`)))
            : null;

        page.append(
            h('div', { class: 'toolbar' },
                h('input', { type: 'search', placeholder: 'Search messages, actors, addresses…', 'aria-label': 'Search events', on: { input: debounce((e) => { filters.q = e.target.value; pageState.offset = 0; load(); }) } }),
                select('category', [['', 'All categories'], ...CATEGORIES.map((c) => [c, c])], '', { on: { change: (e) => { filters.category = e.target.value; pageState.offset = 0; load(); } } }),
                select('outcome', [['', 'Any outcome'], ['allowed', 'Allowed'], ['denied', 'Denied'], ['suspicious', 'Suspicious']], '', { on: { change: (e) => { filters.outcome = e.target.value; pageState.offset = 0; load(); } } }),
                levelChecks,
                h('div', { class: 'grow' }),
                liveBtn,
                exportMenu),
            host);
        await load();
        return () => source?.close();
    }

    /* ---------------------------------------------------------------- *
     * Audit
     * ---------------------------------------------------------------- */

    async function renderAudit(page) {
        const filters = { q: '' };
        const pageState = { offset: 0, limit: 100 };
        const chainHost = h('div');
        const host = h('div');

        const load = async () => {
            try {
                const [d, chain] = await Promise.all([
                    get(`/api/audit${qs({ ...filters, ...pageState })}`),
                    get('/api/audit/verify'),
                ]);
                fill(chainHost, chain.valid
                    ? h('div', { class: 'banner banner-info' }, h('p', { text: `Hash chain intact — ${fmt.num(chain.checked)} entries verified. Any edit or deletion in logs/audit.log would break the chain.` }))
                    : h('div', { class: 'banner banner-bad' }, h('p', { text: `Hash chain BROKEN at entry #${chain.brokenAt}: ${chain.reason}. The audit log was modified outside SentryFW.` })));
                fill(host, card(null, null, [
                    dataTable([
                        { label: '#', class: 'num', render: (e) => e.seq },
                        { label: 'Time', render: (e) => h('span', { class: 'nowrap', text: fmt.time(e.ts) }) },
                        { label: 'Actor', render: (e) => [e.actor, e.source ? h('span', { class: 'sub mono', text: e.source }) : null] },
                        { label: 'Action', render: (e) => h('span', { class: 'mono', text: e.action }) },
                        { label: 'Target', render: (e) => [e.target, e.reason ? h('span', { class: 'sub', text: `Reason: ${e.reason}` }) : null] },
                        { label: 'Outcome', render: (e) => badge(e.outcome, e.outcome === 'success' ? 'ok' : 'warn') },
                        { label: '', render: (e) => (e.before || e.after ? h('button', { class: 'btn btn-ghost btn-sm', on: { click: () => auditDetail(e) } }, 'Changes') : null) },
                    ], d.entries, { empty: 'No audit entries yet.' }),
                    pager({ ...pageState, total: d.total, onPage: (o) => { pageState.offset = o; load(); } }),
                ], { flush: true }));
            } catch (err) { toastError(err); }
        };

        page.append(
            chainHost,
            h('div', { class: 'toolbar' },
                h('input', { type: 'search', placeholder: 'Search actor, action, target…', 'aria-label': 'Search audit trail', on: { input: debounce((e) => { filters.q = e.target.value; pageState.offset = 0; load(); }) } }),
                h('div', { class: 'grow' }),
                downloadLink('Export CSV', '/api/audit/export?format=csv'),
                downloadLink('Export JSON', '/api/audit/export?format=json')),
            host);
        await load();
    }

    function auditDetail(entry) {
        modal({
            title: `${entry.action} — ${entry.target}`,
            wide: true,
            build: () => ({
                body: [
                    kvList([['Sequence', entry.seq], ['Time', fmt.time(entry.ts)], ['Actor', entry.actor], ['Source', entry.source], ['Hash', h('span', { class: 'mono small', text: entry.hash })]]),
                    entry.before ? [h('h3', { text: 'Before' }), h('pre', { class: 'code', text: JSON.stringify(entry.before, null, 2) })] : null,
                    entry.after ? [h('h3', { text: 'After' }), h('pre', { class: 'code', text: JSON.stringify(entry.after, null, 2) })] : null,
                ],
            }),
        });
    }

    /* ---------------------------------------------------------------- *
     * Backups
     * ---------------------------------------------------------------- */

    async function renderBackups(page) {
        const host = h('div');

        const load = async () => {
            try {
                const d = await get('/api/backups');
                fill(host, card(`${d.backups.length} backup(s)`, null, dataTable([
                    { label: 'File', render: (b) => [h('span', { class: 'mono', text: b.filename }), b.note ? h('span', { class: 'sub', text: b.note }) : null] },
                    { label: 'Created', render: (b) => fmt.time(b.createdAt ?? b.modifiedAt) },
                    { label: 'Contents', render: (b) => (b.counts ? `${b.counts.rules} rules · ${b.counts.blocklist} blocked` : '') },
                    { label: 'Size', class: 'num', render: (b) => fmt.bytes(b.bytes) },
                    { label: 'Valid', render: (b) => (b.valid ? badge('OK', 'ok') : badge('Invalid', 'bad')) },
                    {
                        label: '',
                        render: (b) => h('div', { class: 'row-actions' },
                            h('a', { class: 'btn btn-ghost btn-sm', href: `/api/backups/${encodeURIComponent(b.filename)}`, download: b.filename }, 'Download'),
                            can('backup:write') && b.valid ? h('button', { class: 'btn btn-ghost btn-sm', on: { click: () => restoreFlow({ filename: b.filename }, load) } }, 'Restore') : null,
                            can('backup:write') ? h('button', {
                                class: 'btn btn-ghost btn-sm',
                                on: {
                                    click: async () => {
                                        if (!await confirmDialog({ title: 'Delete backup', message: `Permanently delete ${b.filename}?`, confirmLabel: 'Delete' })) return;
                                        try { await del(`/api/backups/${encodeURIComponent(b.filename)}`, { confirm: true }); toast('Backup deleted', 'ok'); load(); } catch (err) { toastError(err); }
                                    },
                                },
                            }, 'Delete') : null),
                    },
                ], d.backups, { empty: 'No backups yet.' }), { flush: true }));
            } catch (err) { toastError(err); }
        };

        if (can('backup:write')) {
            const note = h('input', { name: 'note', placeholder: 'Note (optional), e.g. "before change #1234"', maxlength: 300 });
            const fileInput = h('input', { type: 'file', accept: '.json,application/json', hidden: true });
            fileInput.addEventListener('change', async () => {
                const file = fileInput.files?.[0];
                fileInput.value = '';
                if (!file) return;
                try {
                    const doc = JSON.parse(await file.text());
                    restoreFlow({ backup: doc }, load);
                } catch {
                    toast(`${file.name} is not valid JSON`, 'bad');
                }
            });
            page.append(card('Create or restore', null, h('div', { class: 'toolbar' },
                note,
                h('button', {
                    class: 'btn btn-primary',
                    on: {
                        click: async (e) => {
                            const res = await busy(e.currentTarget, () => post('/api/backups', { note: note.value }));
                            if (res) { toast(`Backup written: ${res.filename}`, 'ok'); note.value = ''; load(); }
                        },
                    },
                }, 'Create backup'),
                h('button', { class: 'btn', on: { click: () => fileInput.click() } }, 'Restore from file…'),
                downloadLink('Download current config', '/api/backups/export'),
                fileInput)));
        }
        page.append(host, h('p', { class: 'muted small', text: 'Backups contain rules, blocklist entries and setting overrides. Accounts and password hashes are never included. Every restore first writes an automatic rollback snapshot.' }));
        await load();
    }

    async function restoreFlow(source, reload) {
        let info;
        try {
            const doc = source.backup ?? await get(`/api/backups/${encodeURIComponent(source.filename)}`);
            info = await post('/api/backups/validate', { backup: doc });
            source = { backup: doc };
        } catch (err) { toastError(err); return; }

        const withBlocklist = h('input', { type: 'checkbox', checked: true });
        const withSettings = h('input', { type: 'checkbox' });
        const ok = await confirmDialog({
            title: 'Restore backup',
            message: `Replace the current rule set with ${info.counts.rules} rule(s) from a backup created ${fmt.time(info.createdAt)}. A rollback snapshot is written first.`,
            confirmLabel: 'Restore',
            extra: h('div', { class: 'grid', style: 'gap:8px' },
                info.warnings.map((w) => h('div', { class: 'banner banner-warn' }, h('p', { text: w }))),
                h('label', { class: 'check' }, withBlocklist, `Restore blocklist (${info.counts.blocklist} entries)`),
                h('label', { class: 'check' }, withSettings, `Restore settings (${info.counts.settings} values)`)),
        });
        if (!ok) return;
        try {
            const res = await post('/api/backups/restore', { ...source, blocklist: withBlocklist.checked, settings: withSettings.checked, confirm: true });
            toast(`Restored ${res.rules?.imported ?? 0} rule(s). Rollback snapshot: ${res.rollback}`, 'ok', 9000);
            reload();
        } catch (err) { toastError(err); }
    }

    /* ---------------------------------------------------------------- *
     * Settings
     * ---------------------------------------------------------------- */

    const SETTING_LABELS = {
        'firewall.provider': 'Firewall provider',
        'firewall.applyToOS': 'Apply rules to the operating system',
        'firewall.rulePrefix': 'OS rule name prefix',
        'firewall.defaultPolicy.inbound': 'Default inbound policy',
        'firewall.defaultPolicy.outbound': 'Default outbound policy',
        'monitoring.enabled': 'Traffic monitoring',
        'monitoring.intervalSeconds': 'Sampling interval (seconds)',
        'detection.enabled': 'Threat detection',
        'detection.portScan.enabled': 'Port-scan detection',
        'detection.portScan.distinctPorts': 'Port scan: distinct ports',
        'detection.portScan.windowSeconds': 'Port scan: window (seconds)',
        'detection.connectionFlood.enabled': 'Connection-flood detection',
        'detection.connectionFlood.connections': 'Flood: connections',
        'detection.connectionFlood.windowSeconds': 'Flood: window (seconds)',
        'detection.deniedBurst.enabled': 'Denied-burst detection',
        'detection.deniedBurst.denies': 'Denied burst: denies',
        'detection.beaconing.enabled': 'Beaconing detection',
        'detection.autoBlockOnScan': 'Automatically block high-severity scanners',
        'logging.level': 'Log level',
        'logging.logAllowed': 'Log allowed connections',
        'logging.logDenied': 'Log denied connections',
        'blocklist.enabled': 'Evaluate the blocklist',
        'security.requireConfirmForDestructive': 'Require confirmation for destructive API calls',
    };

    async function renderSettings(page) {
        let data;
        let providers = [];
        try {
            [data, providers] = await Promise.all([
                get('/api/settings'),
                get('/api/providers').then((p) => p.providers).catch(() => []),
            ]);
        } catch (err) { toastError(err); return; }

        const editable = data.config.editableSettings;
        const writable = can('settings:write');
        const inputs = new Map();
        const groups = {};
        for (const key of Object.keys(editable)) {
            const group = key.split('.')[0];
            (groups[group] ??= []).push(key);
        }

        const control = (key, spec) => {
            let input;
            if (spec.type === 'bool') {
                input = h('input', { type: 'checkbox', checked: !!spec.current, disabled: !writable });
                inputs.set(key, () => input.checked);
                return h('label', { class: 'switch' }, input, h('span'));
            }
            if (spec.type === 'enum') {
                input = select(key, spec.values, spec.current, { disabled: !writable });
            } else if (spec.type === 'int') {
                input = h('input', { type: 'number', min: spec.min, max: spec.max, value: spec.current, disabled: !writable });
            } else {
                input = h('input', { value: spec.current ?? '', maxlength: spec.maxLength ?? 64, disabled: !writable });
            }
            inputs.set(key, () => (spec.type === 'int' ? Number(input.value) : input.value));
            return input;
        };

        const groupTitles = { firewall: 'Firewall', monitoring: 'Monitoring', detection: 'Detection', logging: 'Logging', blocklist: 'Blocklist', security: 'Security' };
        const form = h('div', { class: 'grid grid-2' }, Object.entries(groups).map(([group, keys]) => card(groupTitles[group] ?? group, null,
            h('div', { class: 'grid', style: 'gap:12px' }, keys.map((key) => {
                const spec = editable[key];
                return h('div', { class: 'setting-row' },
                    h('div', { class: 'setting-label' },
                        h('div', { text: SETTING_LABELS[key] ?? key }),
                        h('div', { class: 'faint small mono setting-key', text: `${key}${spec.restartRequired ? ' · restart required' : ''}` })),
                    h('div', { class: spec.type === 'bool' ? null : 'setting-control' }, control(key, spec)));
            })))));

        const save = async (button) => {
            const changes = {};
            for (const [key, read] of inputs) {
                const value = read();
                if (String(value) !== String(editable[key].current)) changes[key] = value;
            }
            if (Object.keys(changes).length === 0) { toast('No changes to save', 'info'); return; }
            if (changes['firewall.applyToOS'] === true) {
                const ok = await confirmDialog({
                    title: 'Enable OS enforcement',
                    message: 'From now on, rule changes are written into the operating system firewall. Existing rules are not pushed until you press "Apply all to OS" on the Rules page. Make sure a rule allows your management access before enabling a default-deny policy.',
                    confirmLabel: 'Enable enforcement',
                    danger: false,
                });
                if (!ok) return;
            }
            const res = await busy(button, () => patch('/api/settings', changes));
            if (!res) return;
            toast(`Saved ${Object.keys(res.applied).length} setting(s)${res.restartRequired ? ' — restart the server to apply provider changes' : ''}`, res.restartRequired ? 'warn' : 'ok', 8000);
            await refreshSystem();
            navigate();
        };

        page.append(
            writable ? h('div', { class: 'toolbar' }, h('div', { class: 'grow' }), h('button', { class: 'btn btn-primary', on: { click: (e) => save(e.currentTarget) } }, 'Save settings')) : h('div', { class: 'banner banner-info' }, h('p', { text: 'Read-only: only administrators can change settings.' })),
            form,
            card('Firewall providers', null, dataTable([
                { label: 'Provider', render: (p) => [h('strong', { text: p.label }), ' ', p.active ? badge('Active', 'accent') : null, h('span', { class: 'sub mono', text: p.id })] },
                { label: 'Available', render: (p) => (p.probe?.available ? badge('Yes', 'ok') : [badge('No'), h('span', { class: 'sub', text: p.probe?.reason ?? '' })]) },
                { label: 'Elevated', render: (p) => (p.capabilities?.requiresElevation ? (p.probe?.elevated ? badge('Yes', 'ok') : badge('No', 'warn')) : 'not needed') },
                { label: 'Notes', render: (p) => h('span', { class: 'small', text: (p.capabilities?.notes ?? []).join(' ') }) },
            ], providers), { flush: true }),
            accountCard());
    }

    function accountCard() {
        const error = h('p', { class: 'form-error', role: 'alert' });
        const form = h('form', { class: 'form-grid' },
            h('label', null, 'Current password', h('input', { name: 'currentPassword', type: 'password', autocomplete: 'current-password', required: true })),
            h('label', null, 'New password', h('input', { name: 'newPassword', type: 'password', autocomplete: 'new-password', required: true, minlength: 10 })),
            h('div', { class: 'span-all btn-row' }, h('button', { class: 'btn', type: 'submit' }, 'Change password'), error));
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            error.textContent = '';
            try {
                await post('/api/account/password', formData(form));
                form.reset();
                toast('Password changed', 'ok');
            } catch (err) { error.textContent = err.message; }
        });
        return card(`Your account — ${state.user.username} (${state.user.role})`, null, form);
    }

    /* ---------------------------------------------------------------- *
     * Users
     * ---------------------------------------------------------------- */

    async function renderUsers(page) {
        const host = h('div');
        const sessionsHost = h('div');

        const load = async () => {
            try {
                const [d, s] = await Promise.all([get('/api/users'), get('/api/sessions')]);
                fill(host, card(`${d.users.length} account(s)`, can('users:write') ? h('button', { class: 'btn btn-primary btn-sm', on: { click: () => createUserDialog(d.roles, load) } }, '+ New user') : null, dataTable([
                    { label: 'User', render: (u) => [h('strong', { text: u.username }), u.username === state.user.username ? [' ', badge('You', 'accent')] : null] },
                    {
                        label: 'Role',
                        render: (u) => (can('users:write') ? select('role', d.roles, u.role, {
                            'aria-label': `Role for ${u.username}`,
                            on: { change: async (e) => { try { await patch(`/api/users/${encodeURIComponent(u.username)}`, { role: e.target.value }); toast(`${u.username} is now ${e.target.value}`, 'ok'); } catch (err) { e.target.value = u.role; toastError(err); } } },
                        }) : u.role),
                    },
                    { label: 'Status', render: (u) => (u.disabled ? badge('Disabled', 'bad') : u.mustChangePassword ? badge('Must change password', 'warn') : badge('Active', 'ok')) },
                    { label: 'Last sign-in', render: (u) => [fmt.rel(u.lastLoginAt), u.lastLoginFrom ? h('span', { class: 'sub mono', text: u.lastLoginFrom }) : null] },
                    {
                        label: '',
                        render: (u) => (can('users:write') && u.username !== state.user.username ? h('div', { class: 'row-actions' },
                            h('button', { class: 'btn btn-ghost btn-sm', on: { click: () => resetPasswordDialog(u, load) } }, 'Reset password'),
                            h('button', { class: 'btn btn-ghost btn-sm', on: { click: async () => { try { await patch(`/api/users/${encodeURIComponent(u.username)}`, { disabled: !u.disabled }); load(); } catch (err) { toastError(err); } } } }, u.disabled ? 'Enable' : 'Disable'),
                            h('button', {
                                class: 'btn btn-ghost btn-sm',
                                on: {
                                    click: async () => {
                                        if (!await confirmDialog({ title: 'Delete user', message: `Delete ${u.username}? Their sessions end immediately.`, confirmLabel: 'Delete user' })) return;
                                        try { await del(`/api/users/${encodeURIComponent(u.username)}`, { confirm: true }); toast(`Deleted ${u.username}`, 'ok'); load(); } catch (err) { toastError(err); }
                                    },
                                },
                            }, 'Delete')) : null),
                    },
                ], d.users), { flush: true }));
                fill(sessionsHost, card(`Active sessions (${s.sessions.length})`, null, dataTable([
                    { label: 'User', render: (x) => x.username },
                    { label: 'Role', render: (x) => x.role },
                    { label: 'From', render: (x) => h('span', { class: 'mono', text: x.source ?? '' }) },
                    { label: 'Signed in', render: (x) => fmt.rel(x.createdAt) },
                    { label: 'Last activity', render: (x) => fmt.rel(x.lastSeenAt) },
                    { label: 'Client', render: (x) => h('span', { class: 'small faint', text: (x.userAgent ?? '').slice(0, 80) }) },
                ], s.sessions), { flush: true }));
            } catch (err) { toastError(err); }
        };

        page.append(
            h('p', { class: 'muted small', text: 'Roles: admin — everything; operator — rules, blocklist and monitoring; auditor — read-only, including the audit trail.' }),
            host,
            sessionsHost);
        await load();
    }

    function createUserDialog(roles, reload) {
        modal({
            title: 'New user',
            build: (close) => {
                const error = h('p', { class: 'form-error', role: 'alert' });
                const form = h('form', { class: 'grid', style: 'gap:12px' },
                    h('label', null, 'Username', h('input', { name: 'username', required: true, autofocus: true, autocomplete: 'off' })),
                    h('label', null, 'Role', select('role', roles, 'operator')),
                    h('label', null, 'Initial password', h('span', { class: 'field-hint', text: 'The user will be asked to change it at first sign-in.' }), h('input', { name: 'password', type: 'password', autocomplete: 'new-password', required: true, minlength: 10 })));
                const submit = async (button) => {
                    error.textContent = '';
                    const f = formData(form);
                    await busy(button, async () => {
                        try {
                            await post('/api/users', f);
                            await patch(`/api/users/${encodeURIComponent(f.username.toLowerCase())}`, { password: f.password, mustChangePassword: true });
                            toast(`Created ${f.username}`, 'ok');
                            close();
                            reload();
                        } catch (err) { error.textContent = err.message; }
                    });
                };
                form.addEventListener('submit', (e) => { e.preventDefault(); submit(null); });
                return {
                    body: [form, error],
                    foot: [
                        h('button', { class: 'btn', on: { click: () => close() } }, 'Cancel'),
                        h('button', { class: 'btn btn-primary', on: { click: (e) => submit(e.currentTarget) } }, 'Create user'),
                    ],
                };
            },
        });
    }

    function resetPasswordDialog(user, reload) {
        modal({
            title: `Reset password — ${user.username}`,
            build: (close) => {
                const error = h('p', { class: 'form-error', role: 'alert' });
                const pwd = h('input', { type: 'password', autocomplete: 'new-password', minlength: 10, autofocus: true });
                return {
                    body: [h('p', { class: 'muted', text: 'Their sessions end immediately and they must choose a new password at next sign-in.' }), h('label', null, 'Temporary password', pwd), error],
                    foot: [
                        h('button', { class: 'btn', on: { click: () => close() } }, 'Cancel'),
                        h('button', {
                            class: 'btn btn-primary',
                            on: {
                                click: async () => {
                                    try {
                                        await patch(`/api/users/${encodeURIComponent(user.username)}`, { password: pwd.value, mustChangePassword: true });
                                        toast(`Password reset for ${user.username}`, 'ok');
                                        close();
                                        reload();
                                    } catch (err) { error.textContent = err.message; }
                                },
                            },
                        }, 'Reset password'),
                    ],
                };
            },
        });
    }

    /* ================================================================ *
     * Shell: auth screens, navigation, routing
     * ================================================================ */

    function showOnly(id) {
        for (const view of ['view-login', 'view-password', 'view-app']) $(`#${view}`).hidden = view !== id;
    }

    function showLogin(message = '') {
        teardownPage();
        state.user = null;
        state.csrf = null;
        showOnly('view-login');
        $('#login-error').textContent = message;
        $('#login-form [name=username]').focus();
    }

    function showPasswordChange() {
        teardownPage();
        showOnly('view-password');
        $('#password-form [name=currentPassword]').focus();
    }

    async function refreshSystem() {
        try {
            state.system = await get('/api/system');
        } catch {
            state.system = null;
        }
        renderChrome();
    }

    function renderChrome() {
        const user = state.user;
        fill($('#user-chip'), h('span', null, 'Signed in as ', h('strong', { text: user.username }), ` · ${user.role}`));

        const sys = state.system;
        const status = clear($('#topbar-status'));
        const banners = clear($('#banner-area'));
        if (sys) {
            status.append(
                badge(sys.provider.label, 'info'),
                sys.config.firewall.applyToOS ? badge('Enforcing', 'ok') : badge('Not enforced', 'warn'));
            if (!sys.config.firewall.applyToOS) {
                banners.append(h('div', { class: 'banner banner-warn' },
                    h('p', null, h('strong', { text: 'Rules are not being enforced. ' }), 'SentryFW stores and evaluates your rules, but "Apply rules to the operating system" is off, so the host firewall is unchanged.'),
                    can('settings:write') ? h('a', { class: 'btn btn-sm', href: '#/settings' }, 'Settings') : null));
            } else if (sys.provider.capabilities?.requiresElevation && sys.elevated === false) {
                banners.append(h('div', { class: 'banner banner-bad' }, h('p', null, h('strong', { text: 'Not elevated. ' }), sys.elevationHint ?? 'Rule changes cannot reach the OS firewall.')));
            }
            if (sys.audit?.chain && !sys.audit.chain.valid) {
                banners.append(h('div', { class: 'banner banner-bad' }, h('p', { text: `Audit hash chain is broken at entry #${sys.audit.chain.brokenAt}.` })));
            }
            if (sys.config.server.requireAuth === false) {
                banners.append(h('div', { class: 'banner banner-bad' }, h('p', { text: 'Authentication is disabled (server.requireAuth = false). Every visitor is treated as an administrator.' })));
            }
        }
        renderNav();
    }

    function renderNav() {
        const nav = clear($('#nav'));
        let section = null;
        for (const [id, p] of Object.entries(PAGES)) {
            if (!can(p.perm)) continue;
            if (p.section !== section) {
                section = p.section;
                nav.append(h('div', { class: 'nav-section', text: section }));
            }
            nav.append(h('a', { class: 'nav-link', href: `#/${id}`, dataset: { page: id } },
                h('span', { class: 'nav-icon', 'aria-hidden': 'true', text: p.icon }),
                h('span', { text: p.title }),
                id === 'detection' && state.openFindings ? h('span', { class: 'nav-count', text: state.openFindings > 99 ? '99+' : String(state.openFindings) }) : null));
        }
        markActiveNav();
    }

    function updateNavCounts() {
        const link = $('#nav [data-page=detection]');
        if (!link) return;
        link.querySelector('.nav-count')?.remove();
        if (state.openFindings) link.append(h('span', { class: 'nav-count', text: state.openFindings > 99 ? '99+' : String(state.openFindings) }));
    }

    function markActiveNav() {
        const current = currentRoute().id;
        for (const link of document.querySelectorAll('#nav .nav-link')) {
            link.classList.toggle('active', link.dataset.page === current);
            if (link.dataset.page === current) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current');
        }
    }

    function currentRoute() {
        const raw = location.hash.replace(/^#\/?/, '');
        const [id, query = ''] = raw.split('?');
        return { id: id || 'dashboard', params: new URLSearchParams(query) };
    }

    function teardownPage() {
        try { state.cleanup?.(); } catch { /* ignore */ }
        state.cleanup = null;
    }

    let navToken = 0;
    async function navigate() {
        if (!state.user) return;
        teardownPage();
        const token = ++navToken;
        let { id, params } = currentRoute();
        if (!PAGES[id] || !can(PAGES[id].perm)) {
            id = Object.keys(PAGES).find((p) => can(PAGES[p].perm)) ?? 'dashboard';
            params = new URLSearchParams();
        }
        const pageDef = PAGES[id];
        $('#page-title').textContent = pageDef.title;
        document.title = `${pageDef.title} · SentryFW`;
        markActiveNav();
        $('#sidebar').classList.remove('open');

        const page = clear($('#page'));
        const cleanup = await pageDef.render(page, params);
        if (token !== navToken) { cleanup?.(); return; }
        state.cleanup = cleanup ?? null;
    }

    async function enterApp(session) {
        state.user = session.user;
        state.csrf = session.csrf ?? null;
        if (state.user.mustChangePassword) {
            showPasswordChange();
            return;
        }
        showOnly('view-app');
        await refreshSystem();
        await navigate();
    }

    async function boot() {
        applyTheme(loadTheme());
        wireStaticHandlers();
        let session;
        try {
            session = await get('/api/auth/session');
        } catch {
            showLogin('Cannot reach the SentryFW server.');
            return;
        }
        if (session.authenticated) {
            await enterApp(session);
        } else if (session.requireAuth === false) {
            // Lab mode: the server treats every request as an administrator.
            const account = await get('/api/account');
            await enterApp({ user: account.user, csrf: null });
        } else {
            showLogin();
        }
    }

    function wireStaticHandlers() {
        $('#login-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const form = e.currentTarget;
            const button = form.querySelector('button[type=submit]');
            $('#login-error').textContent = '';
            button.disabled = true;
            try {
                const res = await post('/api/auth/login', { username: form.username.value, password: form.password.value });
                form.password.value = '';
                await enterApp({ user: { ...res.user, mustChangePassword: res.mustChangePassword }, csrf: res.csrf });
            } catch (err) {
                $('#login-error').textContent = err.message;
            } finally {
                button.disabled = false;
            }
        });

        $('#password-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const form = e.currentTarget;
            const error = $('#password-error');
            error.textContent = '';
            if (form.newPassword.value !== form.confirmPassword.value) {
                error.textContent = 'The new passwords do not match.';
                return;
            }
            try {
                const user = await post('/api/account/password', { currentPassword: form.currentPassword.value, newPassword: form.newPassword.value });
                form.reset();
                toast('Password updated', 'ok');
                await enterApp({ user, csrf: state.csrf });
            } catch (err) {
                error.textContent = [err.message, ...(Array.isArray(err.details) ? err.details.map((d) => d.message) : [])].join(' — ');
            }
        });

        for (const btn of document.querySelectorAll('[data-action=logout]')) {
            btn.addEventListener('click', async () => {
                try { await post('/api/auth/logout'); } catch { /* ending anyway */ }
                showLogin('Signed out.');
            });
        }

        $('#menu-btn').addEventListener('click', () => $('#sidebar').classList.toggle('open'));
        $('#theme-btn').addEventListener('click', () => {
            const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
            applyTheme(next);
            try { localStorage.setItem('sentryfw-theme', next); } catch { /* storage unavailable */ }
        });
        window.addEventListener('hashchange', navigate);
    }

    function loadTheme() {
        try {
            const saved = localStorage.getItem('sentryfw-theme');
            if (saved) return saved;
        } catch { /* storage unavailable */ }
        return window.matchMedia?.('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
    }

    function applyTheme(theme) {
        document.documentElement.dataset.theme = theme;
    }

    boot();
})();
