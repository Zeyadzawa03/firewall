/**
 * Detection engine — heuristics over observed connections and firewall events.
 *
 * Deliberately explainable rather than clever: each detector states what it
 * counted, over what window, and against which threshold, so an analyst can
 * confirm or dismiss a finding without reading the source. Thresholds live in
 * config under `detection.*` and are editable from the GUI.
 *
 * Detectors:
 *   port-scan          one remote address touching many distinct local ports
 *   connection-flood   one remote address opening an unusual number of sockets
 *   sensitive-access   a public address reaching a sensitive service port
 *   denied-burst       repeated policy denials from the same source
 *   beaconing          near-constant interval between connections (C2 pattern)
 *   new-listener       a port started listening that was not listening before
 *   outbound-anomaly   local process talking to a public address on an odd port
 */

import { getConfig } from '../core/config.js';
import { logEvent } from '../core/logger.js';
import { randomId } from '../core/ids.js';
import { isPrivateIP } from '../core/validate.js';
import { WELL_KNOWN_PORTS, classifyAddress } from '../network/inspector.js';

export const SEVERITIES = Object.freeze(['low', 'medium', 'high', 'critical']);

const SEVERITY_RANK = Object.freeze({ low: 1, medium: 2, high: 3, critical: 4 });

/** Sliding-window activity per remote address. */
class RemoteTracker {
    constructor() {
        /** @type {Map<string, {ports:Map<number,number>, events:number[], denies:number[], first:number, last:number, processes:Set<string>}>} */
        this.map = new Map();
    }

    touch(remote, { port = null, at = Date.now(), denied = false, process: proc = null } = {}) {
        let rec = this.map.get(remote);
        if (!rec) {
            rec = { ports: new Map(), events: [], denies: [], first: at, last: at, processes: new Set() };
            this.map.set(remote, rec);
        }
        rec.last = at;
        rec.events.push(at);
        if (port !== null) rec.ports.set(port, at);
        if (denied) rec.denies.push(at);
        if (proc) rec.processes.add(proc);
        return rec;
    }

    prune(windowMs, now = Date.now()) {
        const cutoff = now - windowMs;
        for (const [remote, rec] of this.map) {
            rec.events = rec.events.filter((t) => t >= cutoff);
            rec.denies = rec.denies.filter((t) => t >= cutoff);
            for (const [port, t] of rec.ports) {
                if (t < cutoff) rec.ports.delete(port);
            }
            if (rec.events.length === 0 && rec.ports.size === 0) this.map.delete(remote);
        }
        // Hard cap so a spoofed-source flood cannot grow memory without bound.
        if (this.map.size > 20_000) {
            const entries = [...this.map.entries()].sort((a, b) => b[1].last - a[1].last);
            this.map = new Map(entries.slice(0, 10_000));
        }
    }

    get size() {
        return this.map.size;
    }
}

export class DetectionEngine {
    constructor() {
        this.tracker = new RemoteTracker();
        /** @type {Map<string, object>} findingKey -> finding (deduped) */
        this.findings = new Map();
        /** @type {Set<string>} `${protocol}:${address}:${port}` seen listening */
        this.knownListeners = new Set();
        this.listenersInitialised = false;
        /** @type {Map<string, number[]>} remote -> connection timestamps for beaconing */
        this.intervals = new Map();
        this.stats = { evaluations: 0, findings: 0, lastRunAt: null, suppressed: 0 };
    }

    get enabled() {
        return getConfig().detection?.enabled !== false;
    }

    /**
     * Feed a batch of observed connections.
     * @returns {Array<object>} newly raised findings
     */
    ingestConnections(connections, { now = Date.now() } = {}) {
        if (!this.enabled) return [];
        const cfg = getConfig().detection;
        this.stats.evaluations += 1;
        this.stats.lastRunAt = new Date(now).toISOString();

        const maxWindowMs = Math.max(
            cfg.portScan?.windowSeconds ?? 60,
            cfg.connectionFlood?.windowSeconds ?? 60,
            cfg.deniedBurst?.windowSeconds ?? 120,
        ) * 1000;

        for (const conn of connections) {
            const remote = conn.remoteAddress;
            if (!remote || remote === '0.0.0.0' || remote === '::' || remote === '*') continue;
            if (conn.remoteScope === 'loopback') continue;

            const at = conn.observedAt ? Date.parse(conn.observedAt) || now : now;
            const servicePort = conn.direction === 'inbound' ? conn.localPort : conn.remotePort;
            this.tracker.touch(remote, { port: servicePort, at, process: conn.process || null });

            if (conn.direction === 'outbound' && conn.remoteScope === 'public') {
                const arr = this.intervals.get(remote) ?? [];
                if (arr.length === 0 || at - arr.at(-1) > 1000) arr.push(at);
                this.intervals.set(remote, arr.slice(-30));
            }
        }

        this.tracker.prune(maxWindowMs, now);

        const raised = [];
        raised.push(...this.#detectPortScans(now));
        raised.push(...this.#detectFloods(now));
        raised.push(...this.#detectSensitiveAccess(connections, now));
        raised.push(...this.#detectBeaconing(now));
        raised.push(...this.#detectOutboundAnomalies(connections, now));
        return raised.filter(Boolean);
    }

    /** Feed a policy denial (from the evaluation engine or an OS log). */
    ingestDenial({ remoteAddress, localPort, protocol = 'tcp', ruleName = null, now = Date.now() } = {}) {
        if (!this.enabled || !remoteAddress) return null;
        // Host-internal traffic is never filtered by the OS firewall; never a finding.
        if (classifyAddress(remoteAddress) === 'loopback') return null;
        this.tracker.touch(remoteAddress, { port: localPort ?? null, at: now, denied: true });

        const cfg = getConfig().detection.deniedBurst ?? {};
        if (cfg.enabled === false) return null;
        const rec = this.tracker.map.get(remoteAddress);
        const windowMs = (cfg.windowSeconds ?? 120) * 1000;
        const denies = rec.denies.filter((t) => t >= now - windowMs).length;
        if (denies < (cfg.denies ?? 10)) return null;

        return this.#raise({
            type: 'denied-burst',
            severity: denies >= (cfg.denies ?? 10) * 3 ? 'high' : 'medium',
            remoteAddress,
            title: `Repeated policy denials from ${remoteAddress}`,
            detail: `${denies} connection attempt(s) denied in the last ${cfg.windowSeconds ?? 120}s (threshold ${cfg.denies ?? 10}).`,
            evidence: { denies, windowSeconds: cfg.windowSeconds ?? 120, protocol, lastRule: ruleName },
            recommendation: `Confirm the source is not a misconfigured internal host, then block it: fwctl block ${remoteAddress} --reason "repeated denials"`,
            now,
        });
    }

    /** Feed the current listener set; raises a finding for newly opened ports. */
    ingestListeners(listeners, { now = Date.now() } = {}) {
        if (!this.enabled) return [];
        const current = new Set(
            listeners.map((l) => `${l.protocol}:${l.localAddress}:${l.localPort}`),
        );

        // First sample establishes the baseline instead of alerting on everything.
        if (!this.listenersInitialised) {
            this.knownListeners = current;
            this.listenersInitialised = true;
            return [];
        }

        const raised = [];
        for (const l of listeners) {
            const key = `${l.protocol}:${l.localAddress}:${l.localPort}`;
            if (this.knownListeners.has(key)) continue;
            const exposed = l.localAddress === '0.0.0.0' || l.localAddress === '::';
            const service = WELL_KNOWN_PORTS[l.localPort];
            raised.push(this.#raise({
                type: 'new-listener',
                severity: exposed ? 'medium' : 'low',
                remoteAddress: null,
                title: `New listening port ${l.localPort}/${l.protocol}${service ? ` (${service})` : ''}`,
                detail: `${l.process || 'unknown process'} (pid ${l.pid || '?'}) started listening on ${l.localAddress}:${l.localPort}. Exposure: ${l.exposure ?? (exposed ? 'all-interfaces' : 'specific')}.`,
                evidence: { port: l.localPort, protocol: l.protocol, address: l.localAddress, process: l.process, pid: l.pid, exposure: l.exposure },
                recommendation: exposed
                    ? 'Confirm the service is meant to be reachable from other hosts; add an inbound allow rule scoped to the expected sources, or block the port.'
                    : 'Informational: the service is bound to a specific address.',
                now,
            }));
        }
        this.knownListeners = current;
        return raised.filter(Boolean);
    }

    #detectPortScans(now) {
        const cfg = getConfig().detection.portScan ?? {};
        if (cfg.enabled === false) return [];
        const threshold = cfg.distinctPorts ?? 12;
        const windowMs = (cfg.windowSeconds ?? 60) * 1000;
        const out = [];

        for (const [remote, rec] of this.tracker.map) {
            const recentPorts = [...rec.ports.entries()].filter(([, t]) => t >= now - windowMs).map(([p]) => p);
            if (recentPorts.length < threshold) continue;
            const severity = recentPorts.length >= threshold * 4 ? 'critical'
                : recentPorts.length >= threshold * 2 ? 'high' : 'medium';
            out.push(this.#raise({
                type: 'port-scan',
                severity,
                remoteAddress: remote,
                title: `Possible port scan from ${remote}`,
                detail: `${recentPorts.length} distinct ports contacted within ${cfg.windowSeconds ?? 60}s (threshold ${threshold}).`,
                evidence: {
                    distinctPorts: recentPorts.length,
                    threshold,
                    windowSeconds: cfg.windowSeconds ?? 60,
                    samplePorts: recentPorts.slice(0, 25).sort((a, b) => a - b),
                    private: isPrivateIP(remote),
                },
                recommendation: isPrivateIP(remote)
                    ? 'Internal source: verify whether this is an authorised vulnerability scanner before blocking.'
                    : `External source: block it — fwctl block ${remote} --reason "port scan"`,
                now,
            }));
        }
        return out;
    }

    #detectFloods(now) {
        const cfg = getConfig().detection.connectionFlood ?? {};
        if (cfg.enabled === false) return [];
        const threshold = cfg.connections ?? 60;
        const windowMs = (cfg.windowSeconds ?? 60) * 1000;
        const out = [];

        for (const [remote, rec] of this.tracker.map) {
            const recent = rec.events.filter((t) => t >= now - windowMs).length;
            if (recent < threshold) continue;
            out.push(this.#raise({
                type: 'connection-flood',
                severity: recent >= threshold * 5 ? 'high' : 'medium',
                remoteAddress: remote,
                title: `High connection volume from ${remote}`,
                detail: `${recent} connection observations within ${cfg.windowSeconds ?? 60}s (threshold ${threshold}).`,
                evidence: { observations: recent, threshold, windowSeconds: cfg.windowSeconds ?? 60, private: isPrivateIP(remote) },
                recommendation: 'Check whether this is legitimate bulk traffic (backup, replication, CDN) before acting. Consider a rate-limited allow rule rather than a block.',
                now,
            }));
        }
        return out;
    }

    #detectSensitiveAccess(connections, now) {
        const cfg = getConfig().detection;
        const sensitive = new Set((cfg.sensitivePorts ?? []).map(Number));
        if (sensitive.size === 0) return [];
        const out = [];

        for (const conn of connections) {
            if (conn.direction !== 'inbound') continue;
            if (conn.remoteScope !== 'public') continue;
            if (!sensitive.has(Number(conn.localPort))) continue;
            if (conn.state !== 'established' && conn.state !== 'synreceived') continue;

            const service = WELL_KNOWN_PORTS[conn.localPort] ?? `port ${conn.localPort}`;
            out.push(this.#raise({
                type: 'sensitive-access',
                severity: 'high',
                remoteAddress: conn.remoteAddress,
                title: `Public address connected to ${service}`,
                detail: `${conn.remoteAddress}:${conn.remotePort} has an ${conn.state} connection to local ${conn.localAddress}:${conn.localPort} (${service}) via ${conn.process || 'unknown process'}.`,
                evidence: {
                    localPort: conn.localPort,
                    service,
                    protocol: conn.protocol,
                    process: conn.process,
                    pid: conn.pid,
                    state: conn.state,
                },
                recommendation: `Restrict this service to known sources. Example: fwctl rules add --name "Allow ${service} from office" --direction inbound --action allow --protocol ${conn.protocol} --dport ${conn.localPort} --src <office-cidr>, then a lower-priority deny for the same port.`,
                now,
            }));
        }
        return out;
    }

    #detectBeaconing(now) {
        const cfg = getConfig().detection.beaconing ?? {};
        if (cfg.enabled === false) return [];
        const minSamples = cfg.minSamples ?? 5;
        const tolerance = (cfg.jitterToleranceSeconds ?? 3) * 1000;
        const out = [];

        for (const [remote, times] of this.intervals) {
            if (times.length < minSamples) continue;
            const gaps = [];
            for (let i = 1; i < times.length; i++) gaps.push(times[i] - times[i - 1]);
            if (gaps.length < minSamples - 1) continue;
            const mean = gaps.reduce((a, b) => a + b, 0) / gaps.length;
            if (mean < 5000) continue; // too fast to distinguish from normal chatter
            const variance = gaps.reduce((acc, g) => acc + (g - mean) ** 2, 0) / gaps.length;
            const stddev = Math.sqrt(variance);
            if (stddev > tolerance) continue;

            out.push(this.#raise({
                type: 'beaconing',
                severity: 'medium',
                remoteAddress: remote,
                title: `Regular-interval outbound traffic to ${remote}`,
                detail: `${gaps.length + 1} outbound connections at a near-constant interval of ${Math.round(mean / 1000)}s (jitter ±${Math.round(stddev / 1000)}s). Regular beaconing is characteristic of command-and-control channels, but also of polling clients and update checks.`,
                evidence: { samples: times.length, meanIntervalSeconds: Math.round(mean / 1000), jitterSeconds: Math.round(stddev / 1000) },
                recommendation: 'Identify the owning process and destination reputation before acting. Legitimate agents (telemetry, monitoring, update checks) look identical at this level.',
                now,
            }));
        }
        return out;
    }

    #detectOutboundAnomalies(connections, now) {
        const out = [];
        const suspiciousPorts = new Set([4444, 1080, 6667, 6697, 9001, 9050, 31337]);
        for (const conn of connections) {
            if (conn.direction !== 'outbound' || conn.remoteScope !== 'public') continue;
            if (!suspiciousPorts.has(Number(conn.remotePort))) continue;
            out.push(this.#raise({
                type: 'outbound-anomaly',
                severity: 'medium',
                remoteAddress: conn.remoteAddress,
                title: `Outbound connection to uncommon port ${conn.remotePort}`,
                detail: `${conn.process || 'unknown process'} (pid ${conn.pid || '?'}) connected to ${conn.remoteAddress}:${conn.remotePort}. This port is commonly associated with proxies, IRC or offensive tooling.`,
                evidence: { remotePort: conn.remotePort, process: conn.process, pid: conn.pid, protocol: conn.protocol },
                recommendation: 'Verify the process. If unexpected, block the destination and investigate the host.',
                now,
            }));
        }
        return out;
    }

    /** Deduplicate, escalate and log. Returns the finding only when it is new or escalated. */
    #raise({ type, severity, remoteAddress, title, detail, evidence, recommendation, now }) {
        const key = `${type}|${remoteAddress ?? '-'}|${evidence?.port ?? evidence?.localPort ?? evidence?.remotePort ?? ''}`;
        const existing = this.findings.get(key);

        if (existing) {
            existing.occurrences += 1;
            existing.lastSeenAt = new Date(now).toISOString();
            existing.evidence = evidence;
            existing.detail = detail;
            const escalated = SEVERITY_RANK[severity] > SEVERITY_RANK[existing.severity];
            if (escalated) existing.severity = severity;
            if (!escalated) {
                this.stats.suppressed += 1;
                return null;
            }
        }

        const finding = existing ?? {
            id: randomId('det'),
            type,
            severity,
            remoteAddress: remoteAddress ?? null,
            title,
            detail,
            evidence,
            recommendation,
            firstSeenAt: new Date(now).toISOString(),
            lastSeenAt: new Date(now).toISOString(),
            occurrences: 1,
            acknowledged: false,
            acknowledgedBy: null,
            acknowledgedAt: null,
        };
        if (!existing) this.findings.set(key, finding);

        // Bound memory: keep the newest 1000 findings.
        if (this.findings.size > 1000) {
            const oldest = [...this.findings.entries()].sort(
                (a, b) => Date.parse(a[1].lastSeenAt) - Date.parse(b[1].lastSeenAt),
            )[0];
            if (oldest) this.findings.delete(oldest[0]);
        }

        this.stats.findings += 1;
        logEvent({
            level: severity === 'critical' ? 'critical' : severity === 'high' ? 'error' : 'warn',
            category: 'detection',
            action: `detection.${type}`,
            message: `${title} — ${detail}`,
            source: remoteAddress ?? null,
            target: evidence?.port ? String(evidence.port) : null,
            outcome: 'suspicious',
            details: { severity, evidence, recommendation, findingId: finding.id },
        });

        return finding;
    }

    /** Filter / sort findings for the GUI. */
    query({ severity = null, type = null, acknowledged = null, text = '', limit = 100, offset = 0 } = {}) {
        const needle = String(text || '').trim().toLowerCase();
        let rows = [...this.findings.values()].filter((f) => {
            if (severity && f.severity !== severity) return false;
            if (type && f.type !== type) return false;
            if (acknowledged !== null && acknowledged !== undefined && f.acknowledged !== acknowledged) return false;
            if (needle) {
                const hay = `${f.title} ${f.detail} ${f.remoteAddress ?? ''} ${f.type}`.toLowerCase();
                if (!hay.includes(needle)) return false;
            }
            return true;
        });
        rows.sort((a, b) => {
            const rank = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
            if (rank !== 0) return rank;
            return Date.parse(b.lastSeenAt) - Date.parse(a.lastSeenAt);
        });
        const total = rows.length;
        return {
            total,
            offset,
            limit,
            findings: rows.slice(Math.max(0, offset), Math.max(0, offset) + Math.min(500, Math.max(1, limit))),
        };
    }

    acknowledge(id, actor = 'system') {
        for (const finding of this.findings.values()) {
            if (finding.id !== id) continue;
            finding.acknowledged = true;
            finding.acknowledgedBy = actor;
            finding.acknowledgedAt = new Date().toISOString();
            logEvent({
                level: 'info', category: 'detection', action: 'detection.acknowledge',
                message: `Finding acknowledged: ${finding.title}`, actor, target: id,
            });
            return finding;
        }
        return null;
    }

    summary() {
        const bySeverity = { low: 0, medium: 0, high: 0, critical: 0 };
        const byType = {};
        let open = 0;
        for (const f of this.findings.values()) {
            bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
            byType[f.type] = (byType[f.type] ?? 0) + 1;
            if (!f.acknowledged) open += 1;
        }
        return {
            enabled: this.enabled,
            total: this.findings.size,
            open,
            bySeverity,
            byType,
            trackedRemotes: this.tracker.size,
            knownListeners: this.knownListeners.size,
            ...this.stats,
        };
    }

    reset() {
        this.tracker = new RemoteTracker();
        this.findings.clear();
        this.knownListeners.clear();
        this.listenersInitialised = false;
        this.intervals.clear();
        this.stats = { evaluations: 0, findings: 0, lastRunAt: null, suppressed: 0 };
    }
}

/** Process-wide engine. */
export const detection = new DetectionEngine();
