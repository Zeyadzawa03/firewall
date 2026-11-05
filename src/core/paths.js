/**
 * Filesystem paths and atomic JSON persistence.
 *
 * All mutable state lives under `data/`, which is created on demand and is not
 * part of the shipped tree. Writes are atomic (tmp file + rename) so a crash
 * mid-write cannot leave a truncated rule store behind.
 */

import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';

const here = path.dirname(fileURLToPath(import.meta.url));

/** Repository root (…/src/core -> …). */
export const ROOT = path.resolve(here, '..', '..');

/**
 * Mutable state and logs can be relocated with FWCTL_DATA_DIR / FWCTL_LOG_DIR,
 * e.g. to /var/lib/sentryfw under a service manager, or to a temp directory so
 * the integration tests never touch a real installation's rules.
 */
const DATA = process.env.FWCTL_DATA_DIR ? path.resolve(process.env.FWCTL_DATA_DIR) : path.join(ROOT, 'data');
const LOGS = process.env.FWCTL_LOG_DIR ? path.resolve(process.env.FWCTL_LOG_DIR) : path.join(ROOT, 'logs');

export const PATHS = Object.freeze({
    root: ROOT,
    config: path.join(ROOT, 'config'),
    defaultConfig: path.join(ROOT, 'config', 'default.json'),
    data: DATA,
    runtimeConfig: path.join(DATA, 'config.json'),
    rules: path.join(DATA, 'rules.json'),
    users: path.join(DATA, 'users.json'),
    blocklist: path.join(DATA, 'blocklist.json'),
    backups: path.join(DATA, 'backups'),
    serverLock: path.join(DATA, 'server.lock'),
    logs: LOGS,
    eventLog: path.join(LOGS, 'events.log'),
    auditLog: path.join(LOGS, 'audit.log'),
    public: path.join(ROOT, 'public'),
    scripts: path.join(ROOT, 'scripts'),
    psWindows: path.join(ROOT, 'scripts', 'windows-firewall.ps1'),
    psNetwork: path.join(ROOT, 'scripts', 'windows-network.ps1'),
});

export function ensureDirSync(dir) {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    return dir;
}

export function ensureRuntimeDirs() {
    ensureDirSync(PATHS.data);
    ensureDirSync(PATHS.backups);
    ensureDirSync(PATHS.logs);
}

/** Read + parse JSON, returning `fallback` when the file is absent. */
export async function readJson(file, fallback = null) {
    try {
        const text = await fsp.readFile(file, 'utf8');
        return JSON.parse(stripBom(text));
    } catch (err) {
        if (err.code === 'ENOENT') return fallback;
        if (err instanceof SyntaxError) {
            const backup = `${file}.corrupt-${Date.now()}`;
            try { await fsp.rename(file, backup); } catch { /* best effort */ }
            const e = new Error(`${path.basename(file)} contained invalid JSON; moved to ${path.basename(backup)}`);
            e.code = 'CORRUPT_STATE';
            throw e;
        }
        throw err;
    }
}

export function readJsonSync(file, fallback = null) {
    try {
        return JSON.parse(stripBom(fs.readFileSync(file, 'utf8')));
    } catch (err) {
        if (err.code === 'ENOENT') return fallback;
        throw err;
    }
}

/** Atomic write: unique temp file in the same directory, fsync, then rename. */
export async function writeJsonAtomic(file, value, { mode = 0o600 } = {}) {
    ensureDirSync(path.dirname(file));
    const tmp = `${file}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
    const text = `${JSON.stringify(value, null, 2)}\n`;
    let handle;
    try {
        handle = await fsp.open(tmp, 'w', mode);
        await handle.writeFile(text, 'utf8');
        await handle.sync();
    } finally {
        await handle?.close();
    }
    await fsp.rename(tmp, file);
    return file;
}

export async function appendLine(file, line) {
    ensureDirSync(path.dirname(file));
    await fsp.appendFile(file, `${line}\n`, { encoding: 'utf8', mode: 0o600 });
}

export function appendLineSync(file, line) {
    ensureDirSync(path.dirname(file));
    fs.appendFileSync(file, `${line}\n`, { encoding: 'utf8', mode: 0o600 });
}

export async function fileSize(file) {
    try {
        const st = await fsp.stat(file);
        return st.size;
    } catch {
        return 0;
    }
}

export function fileSizeSync(file) {
    try {
        return fs.statSync(file).size;
    } catch {
        return 0;
    }
}

function stripBom(s) {
    return s.charCodeAt(0) === 0xfeff ? s.slice(1) : s;
}

/**
 * Resolve a user-supplied relative path inside a base directory, refusing any
 * result that escapes it. Used by the static file server.
 */
export function safeResolve(baseDir, relative) {
    const base = path.resolve(baseDir);
    const target = path.resolve(base, `.${path.sep}${relative}`);
    const rel = path.relative(base, target);
    if (rel.startsWith('..') || path.isAbsolute(rel)) return null;
    return target;
}
