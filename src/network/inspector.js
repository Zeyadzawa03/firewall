/**
 * Network inspection — interfaces, active connections, listening ports.
 *
 * Windows: driven by scripts/windows-network.ps1 (NetTCPIP / NetAdapter).
 * Linux:   `ss -tunap` plus `ip -j addr` / `ip -j link`.
 * Elsewhere: falls back to Node's os.networkInterfaces() for interfaces and
 *            reports connections as unavailable rather than inventing data.
 *
 * Everything here is read-only and works without elevation, although process
 * ownership for other users' sockets is only visible to a privileged process.
 */

import os from 'node:os';

import { run, runPowerShellScript } from '../core/safe-exec.js';
import { PATHS } from '../core/paths.js';
import { logEvent } from '../core/logger.js';
import { isPrivateIP, isIPv4, isIPv6 } from '../core/validate.js';

const CACHE_TTL_MS = 3000;
const cache = new Map();

function cached(key, ttl, producer) {
    const hit = cache.get(key);
    if (hit && hit.expires > Date.now()) return hit.value;
    const value = producer().then(
        (v) => { cache.set(key, { value: Promise.resolve(v), expires: Date.now() + ttl }); return v; },
        (err) => { cache.delete(key); throw err; },
    );
    cache.set(key, { value, expires: Date.now() + ttl });
    return value;
}

export function invalidateNetworkCache() {
    cache.clear();
}

/* ------------------------------------------------------------------ *
 * Interfaces
 * ------------------------------------------------------------------ */

export function listInterfaces() {
    return cached('interfaces', 10_000, async () => {
        if (process.platform === 'win32') {
            try {
                const data = await runPowerShellScript(PATHS.psNetwork, { op: 'interfaces' }, { timeout: 30_000 });
                return { source: 'netadapter', interfaces: (data.interfaces ?? []).map(decorateInterface) };
            } catch (err) {
                logEvent({ level: 'warn', category: 'system', action: 'net.interfaces_fallback', message: `Falling back to os.networkInterfaces(): ${err.message}` });
            }
        } else if (process.platform === 'linux') {
            try {
                const linux = await linuxInterfaces();
                if (linux.length > 0) return { source: 'ip', interfaces: linux.map(decorateInterface) };
            } catch (err) {
                logEvent({ level: 'warn', category: 'system', action: 'net.interfaces_fallback', message: `Falling back to os.networkInterfaces(): ${err.message}` });
            }
        }
        return { source: 'nodejs', interfaces: nodeInterfaces().map(decorateInterface) };
    });
}

function nodeInterfaces() {
    const out = [];
    for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
        const list = addrs ?? [];
        out.push({
            name,
            description: name,
            index: list[0]?.scopeid ?? 0,
            status: 'up',
            mac: list.find((a) => a.mac && a.mac !== '00:00:00:00:00:00')?.mac ?? '',
            linkSpeed: '',
            mtu: 0,
            type: list.some((a) => a.internal) ? 'loopback' : 'unknown',
            virtual: false,
            gateway: '',
            addresses: list.map((a) => ({
                address: a.address,
                family: a.family === 'IPv6' || a.family === 6 ? 'ipv6' : 'ipv4',
                prefix: prefixFromNetmask(a.netmask, a.family),
                state: 'preferred',
                origin: a.internal ? 'wellknown' : 'unknown',
            })),
            rxBytes: 0, txBytes: 0, rxPackets: 0, txPackets: 0, rxDiscarded: 0, txDiscarded: 0,
        });
    }
    return out;
}

function prefixFromNetmask(netmask, family) {
    if (!netmask) return 0;
    if (family === 'IPv6' || family === 6) {
        return netmask.split(':').filter(Boolean).reduce((acc, g) => acc + countBits(parseInt(g, 16) || 0), 0);
    }
    return netmask.split('.').reduce((acc, o) => acc + countBits(Number(o)), 0);
}

function countBits(n) {
    let c = 0;
    let v = n;
    while (v) { c += v & 1; v >>>= 1; }
    return c;
}

async function linuxInterfaces() {
    const [addrRes, linkRes, routeRes] = await Promise.all([
        run('ip', ['-j', 'addr', 'show'], { timeout: 8000 }).catch(() => null),
        run('ip', ['-j', '-s', 'link', 'show'], { timeout: 8000 }).catch(() => null),
        run('ip', ['-j', 'route', 'show', 'default'], { timeout: 8000 }).catch(() => null),
    ]);
    if (!addrRes || addrRes.code !== 0) return [];

    const addrDocs = safeJson(addrRes.stdout, []);
    const linkDocs = safeJson(linkRes?.stdout, []);
    const routeDocs = safeJson(routeRes?.stdout, []);
    const statsByName = new Map(linkDocs.map((l) => [l.ifname, l.stats64 ?? l.stats ?? null]));
    const gatewayByName = new Map(routeDocs.filter((r) => r.dev).map((r) => [r.dev, r.gateway ?? '']));

    return addrDocs.map((iface) => {
        const stats = statsByName.get(iface.ifname);
        return {
            name: iface.ifname,
            description: iface.ifalias ?? iface.ifname,
            index: iface.ifindex ?? 0,
            status: String(iface.operstate ?? '').toLowerCase() === 'up' ? 'up' : 'down',
            mac: iface.address ?? '',
            linkSpeed: '',
            mtu: iface.mtu ?? 0,
            type: iface.link_type ?? 'unknown',
            virtual: !!iface.linkinfo,
            gateway: gatewayByName.get(iface.ifname) ?? '',
            addresses: (iface.addr_info ?? []).map((a) => ({
                address: a.local,
                family: a.family === 'inet6' ? 'ipv6' : 'ipv4',
                prefix: a.prefixlen ?? 0,
                state: a.scope ?? 'global',
                origin: a.dynamic ? 'dhcp' : 'manual',
            })),
            rxBytes: stats?.rx?.bytes ?? 0,
            txBytes: stats?.tx?.bytes ?? 0,
            rxPackets: stats?.rx?.packets ?? 0,
            txPackets: stats?.tx?.packets ?? 0,
            rxDiscarded: stats?.rx?.dropped ?? 0,
            txDiscarded: stats?.tx?.dropped ?? 0,
        };
    });
}

function decorateInterface(iface) {
    const v4 = (iface.addresses ?? []).filter((a) => a.family === 'ipv4');
    const v6 = (iface.addresses ?? []).filter((a) => a.family === 'ipv6');
    return {
        ...iface,
        primaryIPv4: v4[0]?.address ?? null,
        primaryIPv6: v6[0]?.address ?? null,
        addressCount: (iface.addresses ?? []).length,
        loopback: (iface.addresses ?? []).some((a) => a.address === '127.0.0.1' || a.address === '::1'),
    };
}

/* ------------------------------------------------------------------ *
 * Connections
 * ------------------------------------------------------------------ */

/**
 * Active connections, normalised to one shape across platforms:
 * { protocol, localAddress, localPort, remoteAddress, remotePort, state,
 *   pid, process, iface, createdAt, direction, remoteScope }
 */
export function listConnections({ limit = 4000, resolveProcess = true } = {}) {
    return cached(`connections:${limit}:${resolveProcess}`, CACHE_TTL_MS, async () => {
        if (process.platform === 'win32') {
            const data = await runPowerShellScript(
                PATHS.psNetwork,
                { op: 'connections', limit, resolveProcess },
                { timeout: 45_000 },
            );
            return {
                source: 'nettcpip',
                total: data.total ?? (data.connections ?? []).length,
                truncated: !!data.truncated,
                connections: (data.connections ?? []).map(decorateConnection),
            };
        }
        if (process.platform === 'linux') {
            const conns = await linuxConnections(limit);
            return { source: 'ss', total: conns.length, truncated: false, connections: conns.map(decorateConnection) };
        }
        return { source: 'unavailable', total: 0, truncated: false, connections: [], reason: `Connection enumeration is not implemented for ${process.platform}` };
    });
}

export function listListeners({ limit = 2000, resolveProcess = true } = {}) {
    return cached(`listeners:${limit}`, CACHE_TTL_MS, async () => {
        if (process.platform === 'win32') {
            const data = await runPowerShellScript(
                PATHS.psNetwork,
                { op: 'listeners', limit, resolveProcess },
                { timeout: 45_000 },
            );
            return { source: 'nettcpip', listeners: (data.listeners ?? []).map(decorateListener) };
        }
        if (process.platform === 'linux') {
            const conns = await linuxConnections(limit, true);
            return { source: 'ss', listeners: conns.map(decorateListener) };
        }
        return { source: 'unavailable', listeners: [], reason: `Listener enumeration is not implemented for ${process.platform}` };
    });
}

/**
 * Parse `ss -tunap`. Sample line:
 *   tcp   ESTAB  0  0  10.0.0.5:22   10.0.0.9:51544  users:(("sshd",pid=821,fd=4))
 */
export function parseSs(text) {
    const out = [];
    const lines = String(text ?? '').split('\n');
    for (const raw of lines) {
        const line = raw.trim();
        if (!line || /^Netid/i.test(line) || /^State/i.test(line)) continue;
        const cols = line.split(/\s+/);
        if (cols.length < 5) continue;

        const [netid, state, , , local, peer] = cols;
        const protocol = netid.toLowerCase() === 'udp' ? 'udp' : 'tcp';
        const localEp = splitEndpoint(local);
        const peerEp = splitEndpoint(peer ?? '');
        if (!localEp) continue;

        const usersMatch = /users:\(\("([^"]+)",pid=(\d+)/.exec(line);
        out.push({
            protocol,
            localAddress: localEp.address,
            localPort: localEp.port,
            remoteAddress: peerEp?.address ?? '',
            remotePort: peerEp?.port ?? 0,
            state: normaliseState(state),
            pid: usersMatch ? Number(usersMatch[2]) : 0,
            process: usersMatch ? usersMatch[1] : '',
            iface: '',
            createdAt: '',
        });
    }
    return out;
}

function splitEndpoint(token) {
    if (!token || token === '*') return null;
    const idx = token.lastIndexOf(':');
    if (idx === -1) return null;
    let address = token.slice(0, idx);
    const portText = token.slice(idx + 1);
    if (address.startsWith('[') && address.endsWith(']')) address = address.slice(1, -1);
    if (address === '*') address = '0.0.0.0';
    const pct = address.indexOf('%');
    if (pct >= 0) address = address.slice(0, pct);
    const port = portText === '*' ? 0 : Number(portText);
    return { address, port: Number.isFinite(port) ? port : 0 };
}

function normaliseState(state) {
    const s = String(state ?? '').toLowerCase();
    const map = {
        estab: 'established', established: 'established',
        listen: 'listen', 'time-wait': 'timewait', timewait: 'timewait',
        'close-wait': 'closewait', 'syn-sent': 'synsent', 'syn-recv': 'synreceived',
        'fin-wait-1': 'finwait1', 'fin-wait-2': 'finwait2',
        unconn: 'bound', closed: 'closed', 'last-ack': 'lastack', closing: 'closing',
    };
    return map[s] ?? s;
}

async function linuxConnections(limit, onlyListening = false) {
    const args = onlyListening ? ['-tunapl'] : ['-tunap'];
    const res = await run('ss', args, { timeout: 15_000 });
    if (res.code !== 0) return [];
    return parseSs(res.stdout).slice(0, limit);
}

/**
 * Direction heuristic: a socket in LISTEN state, or one whose local port is the
 * well-known/service side of the pair, is treated as inbound; anything else is
 * an outbound connection this host initiated. This is the same inference the
 * Windows and Linux consoles show, and it is explicitly labelled as inferred in
 * the GUI because a socket table cannot prove who sent SYN first.
 */
export function inferDirection(conn) {
    const state = String(conn.state ?? '').toLowerCase();
    if (state === 'listen' || state === 'bound') return 'inbound';
    const lp = Number(conn.localPort) || 0;
    const rp = Number(conn.remotePort) || 0;
    if (rp === 0) return 'inbound';
    if (lp < 1024 && rp >= 1024) return 'inbound';
    if (rp < 1024 && lp >= 1024) return 'outbound';
    if (lp >= 49152 && rp < 49152) return 'outbound';
    if (rp >= 49152 && lp < 49152) return 'inbound';
    return lp < rp ? 'inbound' : 'outbound';
}

function decorateConnection(conn) {
    const remote = conn.remoteAddress ?? '';
    const direction = inferDirection(conn);
    return {
        ...conn,
        direction,
        remoteScope: classifyAddress(remote),
        localScope: classifyAddress(conn.localAddress ?? ''),
        family: isIPv6(remote) || isIPv6(conn.localAddress ?? '') ? 'ipv6' : 'ipv4',
        key: `${conn.protocol}|${conn.localAddress}:${conn.localPort}|${remote}:${conn.remotePort}`,
        observedAt: new Date().toISOString(),
    };
}

function decorateListener(l) {
    return {
        ...l,
        scope: classifyAddress(l.localAddress ?? ''),
        wildcard: l.localAddress === '0.0.0.0' || l.localAddress === '::' || l.localAddress === '*',
        exposure: (l.localAddress === '0.0.0.0' || l.localAddress === '::')
            ? 'all-interfaces'
            : (l.localAddress === '127.0.0.1' || l.localAddress === '::1' ? 'loopback-only' : 'specific-interface'),
        wellKnown: WELL_KNOWN_PORTS[l.localPort] ?? null,
    };
}

export function classifyAddress(address) {
    if (!address) return 'unknown';
    if (address === '0.0.0.0' || address === '::' || address === '*') return 'wildcard';
    if (address === '127.0.0.1' || address === '::1') return 'loopback';
    if (!isIPv4(address) && !isIPv6(address)) return 'unknown';
    return isPrivateIP(address) ? 'private' : 'public';
}

export const WELL_KNOWN_PORTS = Object.freeze({
    20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
    67: 'dhcp', 68: 'dhcp', 69: 'tftp', 80: 'http', 88: 'kerberos', 110: 'pop3',
    111: 'rpcbind', 123: 'ntp', 135: 'msrpc', 137: 'netbios-ns', 138: 'netbios-dgm',
    139: 'netbios-ssn', 143: 'imap', 161: 'snmp', 389: 'ldap', 443: 'https',
    445: 'smb', 465: 'smtps', 500: 'isakmp', 514: 'syslog', 587: 'submission',
    631: 'ipp', 636: 'ldaps', 993: 'imaps', 995: 'pop3s', 1080: 'socks',
    1194: 'openvpn', 1433: 'mssql', 1521: 'oracle', 1723: 'pptp', 2049: 'nfs',
    3128: 'squid', 3306: 'mysql', 3389: 'rdp', 4444: 'metasploit-default',
    5060: 'sip', 5432: 'postgresql', 5900: 'vnc', 5985: 'winrm-http',
    5986: 'winrm-https', 6379: 'redis', 8080: 'http-alt', 8443: 'https-alt',
    9200: 'elasticsearch', 11211: 'memcached', 27017: 'mongodb', 33060: 'mysqlx',
});

/* ------------------------------------------------------------------ *
 * Aggregates
 * ------------------------------------------------------------------ */

export async function connectionStats() {
    const { connections, total, source, reason } = await listConnections({ limit: 8000 });
    return summariseConnections(connections, { total, source, reason });
}

/** Aggregate an already-collected connection list (pure; used with monitor snapshots). */
export function summariseConnections(connections, { total = connections.length, source = null, reason = null } = {}) {
    const byState = {};
    const byProtocol = {};
    const byDirection = { inbound: 0, outbound: 0 };
    const byScope = { public: 0, private: 0, loopback: 0, wildcard: 0, unknown: 0 };
    const remoteCounts = new Map();
    const portCounts = new Map();
    const processCounts = new Map();

    for (const c of connections) {
        byState[c.state] = (byState[c.state] ?? 0) + 1;
        byProtocol[c.protocol] = (byProtocol[c.protocol] ?? 0) + 1;
        byDirection[c.direction] = (byDirection[c.direction] ?? 0) + 1;
        byScope[c.remoteScope] = (byScope[c.remoteScope] ?? 0) + 1;
        if (c.remoteAddress && c.remoteScope !== 'wildcard' && c.remoteScope !== 'unknown') {
            remoteCounts.set(c.remoteAddress, (remoteCounts.get(c.remoteAddress) ?? 0) + 1);
        }
        const servicePort = c.direction === 'inbound' ? c.localPort : c.remotePort;
        if (servicePort) portCounts.set(servicePort, (portCounts.get(servicePort) ?? 0) + 1);
        if (c.process) processCounts.set(c.process, (processCounts.get(c.process) ?? 0) + 1);
    }

    const top = (map, n = 10, labelFn = (k) => String(k)) => [...map.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, n)
        .map(([key, count]) => ({ key: labelFn(key), count }));

    return {
        source,
        reason: reason ?? null,
        total,
        sampled: connections.length,
        established: byState.established ?? 0,
        listening: byState.listen ?? 0,
        byState,
        byProtocol,
        byDirection,
        byScope,
        topRemotes: top(remoteCounts),
        topPorts: top(portCounts, 10, (p) => (WELL_KNOWN_PORTS[p] ? `${p} (${WELL_KNOWN_PORTS[p]})` : String(p))),
        topProcesses: top(processCounts),
        collectedAt: new Date().toISOString(),
    };
}

/** Everything the dashboard needs in one round trip. */
export async function networkSnapshot({ limit = 4000 } = {}) {
    const [ifaces, conns, listeners] = await Promise.all([
        listInterfaces().catch((err) => ({ source: 'error', interfaces: [], error: err.message })),
        listConnections({ limit }).catch((err) => ({ source: 'error', connections: [], total: 0, error: err.message })),
        listListeners().catch((err) => ({ source: 'error', listeners: [], error: err.message })),
    ]);
    return {
        interfaces: ifaces.interfaces ?? [],
        interfaceSource: ifaces.source,
        connections: conns.connections ?? [],
        connectionTotal: conns.total ?? 0,
        connectionTruncated: !!conns.truncated,
        connectionSource: conns.source,
        listeners: listeners.listeners ?? [],
        listenerSource: listeners.source,
        errors: [ifaces.error, conns.error, listeners.error].filter(Boolean),
        collectedAt: new Date().toISOString(),
    };
}

function safeJson(text, fallback) {
    try {
        return JSON.parse(text ?? '');
    } catch {
        return fallback;
    }
}
