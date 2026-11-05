/**
 * Safe process execution.
 *
 * Rules enforced here, because every OS firewall change funnels through this file:
 *
 *   1. `shell: false` always. There is no code path that hands a string to cmd.exe
 *      or /bin/sh, so shell metacharacters in user data cannot be interpreted.
 *   2. Arguments are always an array. Nothing is concatenated into a command line
 *      by this application.
 *   3. The executable must be a bare name or absolute path with no metacharacters.
 *   4. Every call has a timeout and a bounded output buffer.
 *   5. PowerShell work is done by shipped .ps1 scripts that receive a JSON
 *      document on stdin — parameters never travel through a command line at all.
 *      Combined with -NoProfile / -NonInteractive there is no interpolation point.
 */

import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { AppError, ProviderError, ValidationError } from './errors.js';

const DEFAULT_TIMEOUT_MS = 20_000;
const DEFAULT_MAX_BUFFER = 8 * 1024 * 1024;

/** Executables this application is ever allowed to launch. */
const ALLOWED_EXECUTABLES = new Set([
    'powershell.exe',
    'pwsh',
    'pwsh.exe',
    'netsh.exe',
    'iptables',
    'ip6tables',
    'iptables-save',
    'nft',
    'ufw',
    'firewall-cmd',
    'ss',
    'ip',
    'sysctl',
    'id',
]);

const EXEC_NAME_RE = /^[A-Za-z0-9._-]+$/;

function assertSafeExecutable(file) {
    if (typeof file !== 'string' || file.length === 0) {
        throw new ValidationError('Executable must be a non-empty string');
    }
    // eslint-disable-next-line no-control-regex
    if (/[`$;&|<>"'\r\n\0*?]/.test(file)) {
        throw new ValidationError('Executable path contains forbidden characters');
    }
    const base = path.basename(file);
    if (!EXEC_NAME_RE.test(base)) {
        throw new ValidationError(`Executable name is not permitted: ${base}`);
    }
    if (!ALLOWED_EXECUTABLES.has(base)) {
        throw new ValidationError(`Executable is not on the allow-list: ${base}`);
    }
    return base;
}

function assertSafeArgs(args) {
    if (!Array.isArray(args)) throw new ValidationError('Command arguments must be an array');
    for (const [i, a] of args.entries()) {
        if (typeof a !== 'string') {
            throw new ValidationError(`Command argument ${i} must be a string (got ${typeof a})`);
        }
        // eslint-disable-next-line no-control-regex
        if (/[\r\n\0]/.test(a)) {
            throw new ValidationError(`Command argument ${i} contains a newline or NUL byte`);
        }
        if (a.length > 4096) {
            throw new ValidationError(`Command argument ${i} is too long`);
        }
    }
    return args;
}

/**
 * Execute a command without a shell.
 * Resolves with { code, signal, stdout, stderr, durationMs, timedOut }.
 * Never rejects on a non-zero exit code — callers decide what that means.
 */
export function run(file, args = [], options = {}) {
    const {
        timeout = DEFAULT_TIMEOUT_MS,
        maxBuffer = DEFAULT_MAX_BUFFER,
        stdin = null,
        cwd = undefined,
        env = undefined,
        encoding = 'utf8',
    } = options;

    assertSafeExecutable(file);
    assertSafeArgs(args);

    return new Promise((resolve, reject) => {
        const started = Date.now();
        let child;
        try {
            child = spawn(file, args, {
                shell: false,
                windowsHide: true,
                cwd,
                // Minimal, explicit environment. Inherit only what a console tool needs.
                env: env ?? minimalEnv(),
                stdio: ['pipe', 'pipe', 'pipe'],
            });
        } catch (err) {
            reject(new ProviderError(`Failed to spawn ${file}: ${err.message}`, { provider: file }));
            return;
        }

        let stdout = '';
        let stderr = '';
        let stdoutBytes = 0;
        let stderrBytes = 0;
        let timedOut = false;
        let settled = false;

        const timer = timeout > 0
            ? setTimeout(() => {
                timedOut = true;
                try { child.kill('SIGTERM'); } catch { /* already gone */ }
                setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* already gone */ } }, 2000).unref?.();
            }, timeout)
            : null;
        timer?.unref?.();

        child.stdout.setEncoding(encoding);
        child.stderr.setEncoding(encoding);

        child.stdout.on('data', (chunk) => {
            stdoutBytes += Buffer.byteLength(chunk);
            if (stdoutBytes <= maxBuffer) stdout += chunk;
            else if (!timedOut) { try { child.kill('SIGKILL'); } catch { /* noop */ } }
        });
        child.stderr.on('data', (chunk) => {
            stderrBytes += Buffer.byteLength(chunk);
            if (stderrBytes <= maxBuffer) stderr += chunk;
        });

        child.on('error', (err) => {
            if (settled) return;
            settled = true;
            if (timer) clearTimeout(timer);
            const code = err.code === 'ENOENT' ? 'COMMAND_NOT_FOUND' : 'PROVIDER_ERROR';
            reject(new AppError(`${file}: ${err.message}`, { code, status: 502, cause: err }));
        });

        child.on('close', (code, signal) => {
            if (settled) return;
            settled = true;
            if (timer) clearTimeout(timer);
            resolve({
                code: code === null ? -1 : code,
                signal: signal ?? null,
                stdout,
                stderr,
                durationMs: Date.now() - started,
                timedOut,
                truncated: stdoutBytes > maxBuffer,
            });
        });

        if (stdin !== null && stdin !== undefined) {
            child.stdin.on('error', () => { /* closed early; surfaced via exit code */ });
            child.stdin.end(stdin, 'utf8');
        } else {
            child.stdin.end();
        }
    });
}

/** Like run(), but throws ProviderError on a non-zero exit. */
export async function runChecked(file, args = [], options = {}) {
    const res = await run(file, args, options);
    if (res.timedOut) {
        throw new ProviderError(`${path.basename(file)} timed out after ${options.timeout ?? DEFAULT_TIMEOUT_MS}ms`, {
            provider: path.basename(file),
            exitCode: res.code,
        });
    }
    if (res.code !== 0) {
        throw new ProviderError(
            `${path.basename(file)} exited with code ${res.code}`,
            { provider: path.basename(file), exitCode: res.code, stderr: truncate(res.stderr || res.stdout, 2000) },
        );
    }
    return res;
}

/** Environment passed to children: nothing application-specific, no secrets. */
function minimalEnv() {
    const keep = process.platform === 'win32'
        ? ['SystemRoot', 'windir', 'PATH', 'Path', 'PATHEXT', 'TEMP', 'TMP', 'ComSpec', 'SystemDrive', 'USERPROFILE', 'PSModulePath', 'LOCALAPPDATA', 'APPDATA', 'PROGRAMFILES', 'ProgramFiles', 'PROGRAMDATA', 'COMPUTERNAME']
        : ['PATH', 'HOME', 'LANG', 'LC_ALL', 'TZ', 'TMPDIR'];
    const env = Object.create(null);
    for (const k of keep) {
        if (process.env[k] !== undefined) env[k] = process.env[k];
    }
    // Force invariant output so parsers are locale-independent.
    if (process.platform !== 'win32') env.LC_ALL = 'C';
    return env;
}

export function truncate(text, max = 500) {
    if (typeof text !== 'string') return '';
    const t = text.trim();
    return t.length <= max ? t : `${t.slice(0, max)}… (${t.length - max} more chars)`;
}

/* ------------------------------------------------------------------ *
 * PowerShell bridge (Windows)
 * ------------------------------------------------------------------ */

let powershellPath = null;

/** Locate PowerShell once. Prefers Windows PowerShell 5.1 (ships NetSecurity). */
export function resolvePowerShell() {
    if (powershellPath !== null) return powershellPath;
    if (process.platform !== 'win32') {
        powershellPath = '';
        return powershellPath;
    }
    const root = process.env.SystemRoot || 'C:\\Windows';
    const candidates = [
        path.join(root, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
        path.join(root, 'SysWOW64', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
    ];
    powershellPath = candidates.find((c) => existsSync(c)) || 'powershell.exe';
    return powershellPath;
}

/**
 * Run a shipped PowerShell script with a JSON payload on stdin and parse the
 * JSON document it prints. Parameters are never placed on a command line.
 */
export async function runPowerShellScript(scriptPath, payload = {}, options = {}) {
    if (process.platform !== 'win32') {
        throw new AppError('PowerShell bridge is only available on Windows', { code: 'UNSUPPORTED', status: 501 });
    }
    if (!existsSync(scriptPath)) {
        throw new AppError(`PowerShell helper script is missing: ${scriptPath}`, { code: 'INTERNAL_ERROR', status: 500 });
    }

    const exe = resolvePowerShell();
    const args = [
        '-NoProfile',
        '-NonInteractive',
        '-NoLogo',
        '-ExecutionPolicy', 'Bypass',
        '-InputFormat', 'Text',
        '-OutputFormat', 'Text',
        '-File', scriptPath,
    ];

    const res = await run(exe, args, {
        ...options,
        stdin: `${JSON.stringify(payload)}\n`,
        timeout: options.timeout ?? 30_000,
    });

    if (res.timedOut) {
        throw new ProviderError('PowerShell helper timed out', { provider: 'powershell', exitCode: res.code });
    }

    const text = res.stdout.trim();
    if (!text) {
        throw new ProviderError('PowerShell helper produced no output', {
            provider: 'powershell',
            exitCode: res.code,
            stderr: truncate(res.stderr, 2000),
        });
    }

    let parsed;
    try {
        parsed = JSON.parse(stripBom(text));
    } catch {
        throw new ProviderError('PowerShell helper returned malformed JSON', {
            provider: 'powershell',
            exitCode: res.code,
            stderr: truncate(res.stderr || text, 2000),
        });
    }

    if (parsed && parsed.ok === false) {
        const err = new ProviderError(parsed.message || 'PowerShell helper reported failure', {
            provider: 'powershell',
            exitCode: res.code,
            stderr: truncate(parsed.detail || res.stderr, 2000),
        });
        if (parsed.code) err.details = { ...err.details, providerCode: parsed.code };
        throw err;
    }

    return parsed?.data ?? parsed;
}

function stripBom(s) {
    return s.charCodeAt(0) === 0xfeff ? s.slice(1) : s;
}

/* ------------------------------------------------------------------ *
 * Privilege detection
 * ------------------------------------------------------------------ */

let cachedPrivilege = null;

/**
 * Is the current process able to change firewall state?
 * Windows: member of the Administrators role with an elevated token.
 * POSIX:   effective uid 0.
 */
export async function isElevated({ refresh = false } = {}) {
    if (!refresh && cachedPrivilege !== null) return cachedPrivilege;

    if (process.platform === 'win32') {
        try {
            const exe = resolvePowerShell();
            const res = await run(exe, [
                '-NoProfile', '-NonInteractive', '-NoLogo', '-ExecutionPolicy', 'Bypass',
                '-Command',
                // Static command text; no interpolation of any kind.
                '[Console]::Out.Write(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator).ToString())',
            ], { timeout: 15_000 });
            cachedPrivilege = res.stdout.trim().toLowerCase() === 'true';
        } catch {
            cachedPrivilege = false;
        }
    } else {
        cachedPrivilege = typeof process.getuid === 'function' ? process.getuid() === 0 : false;
    }
    return cachedPrivilege;
}

export function elevationHint() {
    if (process.platform === 'win32') {
        return 'Start the console from an elevated terminal: right-click Windows Terminal / PowerShell → "Run as administrator", then run `npm run serve`. Read-only views (interfaces, connections, rule inspection) work without elevation.';
    }
    return 'Run the service under a user with CAP_NET_ADMIN, or start it with sudo. Read-only views work unprivileged.';
}

export function platformInfo() {
    return {
        platform: process.platform,
        release: os.release(),
        arch: process.arch,
        hostname: os.hostname(),
        node: process.versions.node,
        uptimeSeconds: Math.round(os.uptime()),
        cpus: os.cpus().length,
        totalMemBytes: os.totalmem(),
        freeMemBytes: os.freemem(),
        loadavg: os.loadavg(),
    };
}

/** Test seam: reset the privilege cache. */
export function __resetPrivilegeCache() {
    cachedPrivilege = null;
}
