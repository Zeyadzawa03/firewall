/**
 * Traffic monitor.
 *
 * Periodically samples the socket table, evaluates each observed connection
 * against the rule set, records allow/deny counters and rule hit counts, and
 * feeds the detection engine. It is the component that turns a static rule list
 * into observable security telemetry.
 *
 * Important: on a host firewall the kernel enforces policy, not this process.
 * The evaluation performed here answers "what does the configured policy say
 * about this connection?" — which is exactly what makes the Traffic page useful
 * (it shows connections that policy would deny but that exist anyway, i.e. rules
 * that are not actually applied to the OS).
 */

import { EventEmitter } from 'node:events';

import { getConfig } from '../core/config.js';
import { logEvent } from '../core/logger.js';
import { networkSnapshot, connectionStats, summariseConnections, WELL_KNOWN_PORTS } from '../network/inspector.js';
import { evaluate } from '../firewall/rule-model.js';
import * as ruleStore from '../firewall/rule-store.js';
import { detection } from './detection.js';
import { isBlocked } from './blocklist.js';

export class TrafficMonitor extends EventEmitter {
    constructor() {
        super();
        this.timer = null;
        this.running = false;
        this.sampling = false;
        /** @type {Promise<object>|null} the sampling cycle currently running */
        this.inflight = null;

        /** @type {Map<string, object>} connection key -> tracked connection */
        this.tracked = new Map();
        /** @type {Array<object>} rolling per-sample aggregates */
        this.samples = [];
        this.counters = {
            allowed: 0,
            denied: 0,
            blocklisted: 0,
            observed: 0,
            newConnections: 0,
            closedConnections: 0,
            samples: 0,
            errors: 0,
        };
        this.lastSnapshot = null;
        this.lastError = null;
        this.startedAt = null;
    }

    get intervalMs() {
        return Math.max(2, getConfig().monitoring.intervalSeconds ?? 10) * 1000;
    }

    start() {
        if (this.running) return this;
        if (getConfig().monitoring.enabled === false) {
            logEvent({ level: 'info', category: 'system', action: 'monitor.disabled', message: 'Traffic monitoring is disabled in configuration' });
            return this;
        }
        this.running = true;
        this.startedAt = new Date().toISOString();
        logEvent({
            level: 'info', category: 'system', action: 'monitor.start',
            message: `Traffic monitor started (sampling every ${this.intervalMs / 1000}s)`,
        });

        // Immediate first sample so the dashboard is populated at once.
        this.sample().catch(() => { /* recorded in counters */ });
        this.#schedule();
        return this;
    }

    #schedule() {
        if (!this.running) return;
        this.timer = setTimeout(async () => {
            try {
                await this.sample();
            } catch (err) {
                this.counters.errors += 1;
                this.lastError = err.message;
            } finally {
                this.#schedule();
            }
        }, this.intervalMs);
        this.timer.unref?.();
    }

    stop() {
        this.running = false;
        if (this.timer) {
            clearTimeout(this.timer);
            this.timer = null;
        }
        logEvent({ level: 'info', category: 'system', action: 'monitor.stop', message: 'Traffic monitor stopped' });
        return this;
    }

    /**
     * One sampling cycle. Safe to call manually (the GUI refresh button does):
     * concurrent callers share the in-flight cycle instead of starting another.
     */
    sample() {
        if (!this.inflight) {
            this.inflight = this.#sampleOnce().finally(() => { this.inflight = null; });
        }
        return this.inflight;
    }

    async #sampleOnce() {
        this.sampling = true;
        const startedAt = Date.now();

        try {
            const cfg = getConfig();
            const snapshot = await networkSnapshot({ limit: cfg.monitoring.maxTrackedConnections ?? 4000 });
            const rules = ruleStore.allRules();
            const defaultPolicy = cfg.firewall.defaultPolicy;

            let allowed = 0;
            let denied = 0;
            let blocklisted = 0;
            let newCount = 0;
            const seen = new Set();
            const decisions = [];

            for (const conn of snapshot.connections) {
                // A bound/listening socket is not a traffic flow; counting those
                // would inflate every metric on the dashboard.
                if (conn.state === 'bound' || conn.state === 'listen') continue;

                const key = conn.key;
                seen.add(key);

                // Loopback is host-internal IPC. Windows Firewall, iptables and
                // nftables setups all exempt it, so judging it against the
                // inbound default-deny policy only produced thousands of false
                // "denied" flows and findings. Track it, but do not score it.
                if (conn.remoteScope === 'loopback') {
                    const existing = this.tracked.get(key);
                    if (existing) {
                        existing.lastSeenAt = conn.observedAt;
                        existing.observations += 1;
                        existing.state = conn.state;
                    } else {
                        this.tracked.set(key, {
                            ...conn,
                            firstSeenAt: conn.observedAt,
                            lastSeenAt: conn.observedAt,
                            observations: 1,
                            decision: 'allow',
                            matchedRuleId: null,
                            matchedRuleName: 'loopback (not filtered)',
                            usedDefault: false,
                            loopback: true,
                            blocklisted: false,
                            service: WELL_KNOWN_PORTS[conn.direction === 'inbound' ? conn.localPort : conn.remotePort] ?? null,
                        });
                    }
                    continue;
                }

                const verdict = evaluate(rules, {
                    direction: conn.direction,
                    protocol: conn.protocol,
                    localAddress: conn.localAddress,
                    localPort: conn.localPort,
                    remoteAddress: conn.remoteAddress,
                    remotePort: conn.remotePort,
                    iface: conn.iface,
                }, defaultPolicy);

                const blockEntry = conn.remoteAddress ? isBlocked(conn.remoteAddress) : null;
                const decision = blockEntry ? 'deny' : verdict.decision;

                if (decision === 'deny') {
                    denied += 1;
                    if (blockEntry) blocklisted += 1;
                } else {
                    allowed += 1;
                }

                if (verdict.matchedRuleId) ruleStore.recordHit(verdict.matchedRuleId, 1);

                const existing = this.tracked.get(key);
                if (existing) {
                    existing.lastSeenAt = conn.observedAt;
                    existing.observations += 1;
                    existing.state = conn.state;
                    existing.decision = decision;
                    existing.matchedRuleId = verdict.matchedRuleId;
                } else {
                    newCount += 1;
                    this.tracked.set(key, {
                        ...conn,
                        firstSeenAt: conn.observedAt,
                        lastSeenAt: conn.observedAt,
                        observations: 1,
                        decision,
                        matchedRuleId: verdict.matchedRuleId,
                        matchedRuleName: verdict.matchedRule?.name ?? null,
                        usedDefault: verdict.usedDefault,
                        blocklisted: !!blockEntry,
                        service: WELL_KNOWN_PORTS[conn.direction === 'inbound' ? conn.localPort : conn.remotePort] ?? null,
                    });

                    this.#logConnection(conn, decision, verdict, blockEntry);
                }

                decisions.push({ key, decision, ruleId: verdict.matchedRuleId });

                // A connection that policy says should be denied but which is
                // established anyway means the rule is not enforced by the OS.
                if (decision === 'deny' && conn.state === 'established' && !cfg.firewall.applyToOS) {
                    const tracked = this.tracked.get(key);
                    if (tracked && !tracked.unenforcedWarned) {
                        tracked.unenforcedWarned = true;
                        logEvent({
                            level: 'warn', category: 'firewall', action: 'policy.unenforced',
                            message: `Policy denies ${conn.remoteAddress}:${conn.remotePort} → :${conn.localPort} but the connection is established. Rules are not being applied to the operating system (firewall.applyToOS is off).`,
                            source: conn.remoteAddress, target: String(conn.localPort), outcome: 'denied',
                            details: { rule: verdict.matchedRule?.name ?? 'default policy', state: conn.state },
                        });
                    }
                }
            }

            // Retire connections that disappeared from the socket table.
            let closed = 0;
            for (const [key, tracked] of this.tracked) {
                if (seen.has(key)) continue;
                const age = Date.now() - Date.parse(tracked.lastSeenAt);
                if (age > this.intervalMs * 3) {
                    this.tracked.delete(key);
                    closed += 1;
                }
            }

            // Bound memory.
            const cap = cfg.monitoring.maxTrackedConnections ?? 4000;
            if (this.tracked.size > cap) {
                const ordered = [...this.tracked.entries()].sort(
                    (a, b) => Date.parse(a[1].lastSeenAt) - Date.parse(b[1].lastSeenAt),
                );
                for (const [key] of ordered.slice(0, this.tracked.size - cap)) this.tracked.delete(key);
            }

            this.counters.observed += snapshot.connections.length;
            this.counters.allowed += allowed;
            this.counters.denied += denied;
            this.counters.blocklisted += blocklisted;
            this.counters.newConnections += newCount;
            this.counters.closedConnections += closed;
            this.counters.samples += 1;

            const sampleRecord = {
                at: new Date().toISOString(),
                durationMs: Date.now() - startedAt,
                connections: snapshot.connections.length,
                tracked: this.tracked.size,
                allowed,
                denied,
                blocklisted,
                new: newCount,
                closed,
                listeners: snapshot.listeners.length,
                interfaces: snapshot.interfaces.length,
            };
            this.samples.push(sampleRecord);
            const retain = cfg.monitoring.retainSamples ?? 180;
            if (this.samples.length > retain) this.samples.splice(0, this.samples.length - retain);

            // Detection.
            if (cfg.detection?.enabled !== false) {
                const findings = detection.ingestConnections(snapshot.connections);
                const listenerFindings = detection.ingestListeners(snapshot.listeners);
                for (const f of [...findings, ...listenerFindings]) this.emit('finding', f);

                if (cfg.detection.autoBlockOnScan) {
                    await this.#autoBlock(findings);
                }
            }

            this.lastSnapshot = { ...snapshot, sample: sampleRecord };
            this.lastError = snapshot.errors.length > 0 ? snapshot.errors.join('; ') : null;
            if (snapshot.errors.length > 0) this.counters.errors += 1;

            this.emit('sample', sampleRecord);
            return this.lastSnapshot;
        } finally {
            this.sampling = false;
        }
    }

    #logConnection(conn, decision, verdict, blockEntry) {
        const cfg = getConfig().logging;
        if (decision === 'allowed' || decision === 'allow') {
            if (cfg.logAllowed === false) return;
        } else if (cfg.logDenied === false) {
            return;
        }

        const service = WELL_KNOWN_PORTS[conn.direction === 'inbound' ? conn.localPort : conn.remotePort];
        logEvent({
            level: decision === 'deny' ? 'warn' : 'debug',
            category: 'traffic',
            action: decision === 'deny' ? 'traffic.denied' : 'traffic.allowed',
            message: `${decision === 'deny' ? 'DENY' : 'ALLOW'} ${conn.direction} ${conn.protocol.toUpperCase()} `
                + `${conn.remoteAddress}:${conn.remotePort} → ${conn.localAddress}:${conn.localPort}`
                + `${service ? ` (${service})` : ''}${conn.process ? ` [${conn.process}]` : ''}`
                + `${blockEntry ? ' — blocklisted' : verdict.matchedRule ? ` — rule "${verdict.matchedRule.name}"` : ' — default policy'}`,
            source: conn.remoteAddress,
            target: `${conn.localAddress}:${conn.localPort}`,
            outcome: decision === 'deny' ? 'denied' : 'allowed',
            details: {
                protocol: conn.protocol,
                state: conn.state,
                process: conn.process,
                pid: conn.pid,
                rule: verdict.matchedRule?.name ?? null,
                ruleId: verdict.matchedRuleId,
                usedDefault: verdict.usedDefault,
                blocklist: blockEntry ? { target: blockEntry.target, reason: blockEntry.reason } : null,
            },
        });

        if (decision === 'deny') {
            detection.ingestDenial({
                remoteAddress: conn.remoteAddress,
                localPort: conn.localPort,
                protocol: conn.protocol,
                ruleName: verdict.matchedRule?.name ?? 'default policy',
            });
        }
    }

    async #autoBlock(findings) {
        const { block } = await import('./blocklist.js');
        for (const f of findings) {
            if (f.type !== 'port-scan' || !f.remoteAddress) continue;
            if (f.severity !== 'high' && f.severity !== 'critical') continue;
            try {
                await block({
                    target: f.remoteAddress,
                    reason: `Automatic block: ${f.title}`,
                    ttlHours: 24,
                    source: 'automatic',
                    direction: 'inbound',
                }, { actor: 'detection-engine' });
            } catch { /* already blocked, or the block failed and was logged */ }
        }
    }

    /** Filter / sort / paginate tracked connections for the GUI. */
    query({
        text = '', direction = null, protocol = null, state = null,
        decision = null, scope = null, process: proc = null, hideLoopback = false,
        sort = 'lastSeenAt', order = 'desc', limit = 200, offset = 0,
    } = {}) {
        const needle = String(text || '').trim().toLowerCase();
        let rows = [...this.tracked.values()].filter((c) => {
            if (direction && c.direction !== direction) return false;
            if (protocol && c.protocol !== protocol) return false;
            if (state && c.state !== state) return false;
            if (decision && c.decision !== decision) return false;
            if (scope && c.remoteScope !== scope) return false;
            if (hideLoopback && c.remoteScope === 'loopback') return false;
            if (proc && c.process !== proc) return false;
            if (needle) {
                const hay = `${c.localAddress}:${c.localPort} ${c.remoteAddress}:${c.remotePort} ${c.protocol} ${c.state} ${c.process ?? ''} ${c.service ?? ''} ${c.matchedRuleName ?? ''}`.toLowerCase();
                if (!hay.includes(needle)) return false;
            }
            return true;
        });

        const dir = order === 'asc' ? 1 : -1;
        const allowed = ['lastSeenAt', 'firstSeenAt', 'localPort', 'remotePort', 'observations', 'protocol', 'state', 'remoteAddress', 'decision'];
        const key = allowed.includes(sort) ? sort : 'lastSeenAt';
        rows.sort((a, b) => {
            if (key === 'localPort' || key === 'remotePort' || key === 'observations') {
                return ((a[key] ?? 0) - (b[key] ?? 0)) * dir;
            }
            const av = String(a[key] ?? '');
            const bv = String(b[key] ?? '');
            return av < bv ? -dir : av > bv ? dir : 0;
        });

        const total = rows.length;
        return {
            total,
            offset,
            limit,
            connections: rows.slice(Math.max(0, offset), Math.max(0, offset) + Math.min(2000, Math.max(1, limit))),
        };
    }

    /** Rolling series for the dashboard charts. */
    series(points = 60) {
        return this.samples.slice(-Math.max(1, Math.min(500, points)));
    }

    status() {
        return {
            running: this.running,
            startedAt: this.startedAt,
            intervalSeconds: this.intervalMs / 1000,
            tracked: this.tracked.size,
            samples: this.samples.length,
            counters: { ...this.counters },
            lastSampleAt: this.samples.at(-1)?.at ?? null,
            lastSampleDurationMs: this.samples.at(-1)?.durationMs ?? null,
            lastError: this.lastError,
            source: this.lastSnapshot?.connectionSource ?? null,
        };
    }

    /**
     * Connection statistics. Reuses the latest monitor sample when it is fresh:
     * on Windows each enumeration spawns PowerShell and takes seconds, so the
     * dashboard's 10s refresh must not trigger one of its own every time.
     */
    async networkStats() {
        if (this.inflight && !this.lastSnapshot) await this.inflight.catch(() => {});
        const snap = this.lastSnapshot;
        if (snap && Date.now() - Date.parse(snap.collectedAt) < this.intervalMs * 2) {
            return summariseConnections(snap.connections, { total: snap.connectionTotal, source: snap.connectionSource });
        }
        return connectionStats();
    }

    /** Combined payload for the dashboard, in one call. */
    async dashboard() {
        const netStats = await this.networkStats().catch(() => null);
        return {
            monitor: this.status(),
            network: netStats,
            rules: ruleStore.ruleStats(),
            detection: detection.summary(),
            series: this.series(60),
            interfaces: this.lastSnapshot?.interfaces ?? [],
            listeners: this.lastSnapshot?.listeners ?? [],
        };
    }

    reset() {
        this.tracked.clear();
        this.samples.length = 0;
        for (const k of Object.keys(this.counters)) this.counters[k] = 0;
        this.lastSnapshot = null;
        this.lastError = null;
    }
}

/** Process-wide monitor. */
export const monitor = new TrafficMonitor();
