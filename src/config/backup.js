/**
 * Backup / restore of the SentryFW configuration.
 *
 * A backup is a single JSON document containing rules, blocklist entries and the
 * settings override tree. Credentials are never included — restoring a backup on
 * another host does not transplant accounts or password hashes.
 *
 * Restores are transactional from the operator's point of view: the current state
 * is snapshotted to a rollback file first, so a bad import can be undone.
 */

import fsp from 'node:fs/promises';
import path from 'node:path';

import { PATHS, ensureRuntimeDirs, writeJsonAtomic, readJson } from '../core/paths.js';
import { getConfig, getOverrides, updateSettings, MUTABLE_SETTINGS } from '../core/config.js';
import { timestampSlug } from '../core/ids.js';
import { logEvent } from '../core/logger.js';
import { audit } from '../core/audit.js';
import { ValidationError, NotFoundError } from '../core/errors.js';
import * as manager from '../firewall/manager.js';
import * as blocklist from '../monitoring/blocklist.js';

export const BACKUP_KIND = 'sentryfw-backup';
export const BACKUP_VERSION = 2;

/** Build an in-memory backup document. */
export function buildBackup({ includeBlocklist = true, includeSettings = true, note = '' } = {}) {
    const doc = {
        kind: BACKUP_KIND,
        version: BACKUP_VERSION,
        createdAt: new Date().toISOString(),
        host: process.env.COMPUTERNAME || process.env.HOSTNAME || 'unknown',
        platform: process.platform,
        note: String(note ?? '').slice(0, 300),
        provider: getConfig().firewall.provider,
        rules: manager.exportRules().rules,
    };
    if (includeBlocklist) doc.blocklist = blocklist.exportBlocklist().entries;
    if (includeSettings) doc.settings = getOverrides();
    doc.counts = {
        rules: doc.rules.length,
        blocklist: doc.blocklist?.length ?? 0,
        settings: Object.keys(doc.settings ?? {}).length,
    };
    return doc;
}

/** Write a backup file under data/backups and return its metadata. */
export async function createBackup({ note = '', includeBlocklist = true, includeSettings = true } = {}, ctx = {}) {
    ensureRuntimeDirs();
    const doc = buildBackup({ includeBlocklist, includeSettings, note });
    const filename = `backup-${timestampSlug()}.json`;
    const file = path.join(PATHS.backups, filename);
    await writeJsonAtomic(file, doc);

    await audit({
        actor: ctx.actor ?? 'system',
        action: 'backup.create',
        target: filename,
        after: doc.counts,
        reason: note || null,
        source: ctx.source ?? null,
    });

    logEvent({
        level: 'info', category: 'backup', action: 'backup.create',
        message: `Configuration backup written: ${filename} (${doc.counts.rules} rule(s), ${doc.counts.blocklist} blocklist entry/ies)`,
        actor: ctx.actor ?? 'system', source: ctx.source ?? null, target: filename,
    });

    return { filename, file, ...doc.counts, createdAt: doc.createdAt };
}

export async function listBackups() {
    ensureRuntimeDirs();
    let names;
    try {
        names = await fsp.readdir(PATHS.backups);
    } catch {
        return [];
    }
    const out = [];
    for (const name of names.filter((n) => n.endsWith('.json')).sort().reverse()) {
        const file = path.join(PATHS.backups, name);
        try {
            const [stat, doc] = await Promise.all([fsp.stat(file), readJson(file, null)]);
            out.push({
                filename: name,
                bytes: stat.size,
                modifiedAt: stat.mtime.toISOString(),
                createdAt: doc?.createdAt ?? null,
                note: doc?.note ?? '',
                counts: doc?.counts ?? null,
                platform: doc?.platform ?? null,
                valid: doc?.kind === BACKUP_KIND,
            });
        } catch {
            out.push({ filename: name, valid: false, error: 'unreadable' });
        }
    }
    return out;
}

/** Validate a backup document without applying it. */
export function validateBackup(doc) {
    if (!doc || typeof doc !== 'object') throw new ValidationError('Backup must be a JSON object');
    if (doc.kind !== BACKUP_KIND) {
        throw new ValidationError(`Not a SentryFW backup (expected kind "${BACKUP_KIND}", got "${doc.kind ?? 'none'}")`);
    }
    if (!Number.isFinite(doc.version) || doc.version > BACKUP_VERSION) {
        throw new ValidationError(`Unsupported backup version: ${doc.version}. This build understands up to version ${BACKUP_VERSION}.`);
    }
    if (!Array.isArray(doc.rules)) throw new ValidationError('Backup is missing a "rules" array');

    const unknownSettings = Object.keys(flatten(doc.settings ?? {})).filter((k) => !MUTABLE_SETTINGS[k]);

    return {
        valid: true,
        version: doc.version,
        createdAt: doc.createdAt ?? null,
        counts: {
            rules: doc.rules.length,
            blocklist: Array.isArray(doc.blocklist) ? doc.blocklist.length : 0,
            settings: Object.keys(flatten(doc.settings ?? {})).length,
        },
        warnings: [
            ...(doc.platform && doc.platform !== process.platform
                ? [`Backup was taken on ${doc.platform} but this host is ${process.platform}. Interface names and program paths may not exist here.`]
                : []),
            ...(unknownSettings.length > 0
                ? [`These settings will be skipped because they are not editable: ${unknownSettings.join(', ')}`]
                : []),
        ],
    };
}

function flatten(obj, prefix = '', out = {}) {
    for (const [k, v] of Object.entries(obj ?? {})) {
        const key = prefix ? `${prefix}.${k}` : k;
        if (v !== null && typeof v === 'object' && !Array.isArray(v)) flatten(v, key, out);
        else out[key] = v;
    }
    return out;
}

/**
 * Restore a backup document.
 * @param {object} doc
 * @param {{rules?:boolean, blocklist?:boolean, settings?:boolean, applyToOS?:boolean}} what
 */
export async function restoreBackup(doc, what = {}, ctx = {}) {
    const info = validateBackup(doc);
    const {
        rules: doRules = true,
        blocklist: doBlocklist = true,
        settings: doSettings = false,
    } = what;

    // Snapshot for rollback before touching anything.
    const rollback = await createBackup({ note: 'Automatic pre-restore snapshot' }, { ...ctx, actor: 'system' });

    const result = { rollback: rollback.filename, rules: null, blocklist: null, settings: null, warnings: info.warnings };

    if (doRules) {
        result.rules = await manager.importRules({ rules: doc.rules }, ctx);
    }

    if (doBlocklist && Array.isArray(doc.blocklist)) {
        // Rules for blocklist entries were part of the rule import, so entries
        // are re-registered without creating duplicates.
        const imported = await blocklist.importFeed({
            entries: doc.blocklist.map((e) => ({ target: e.target, reason: e.reason, confidence: e.confidence })),
            feed: 'backup-restore',
            reason: 'Restored from backup',
            createRules: false,
        }, ctx);
        result.blocklist = imported;
    }

    if (doSettings && doc.settings) {
        const flat = flatten(doc.settings);
        const applicable = Object.fromEntries(Object.entries(flat).filter(([k]) => MUTABLE_SETTINGS[k]));
        if (Object.keys(applicable).length > 0) {
            result.settings = await updateSettings(applicable);
        }
    }

    await audit({
        actor: ctx.actor ?? 'system',
        action: 'backup.restore',
        target: doc.createdAt ?? 'uploaded backup',
        after: { rules: result.rules?.imported ?? 0, blocklist: result.blocklist?.added ?? 0, settingsApplied: Object.keys(result.settings?.applied ?? {}).length },
        reason: ctx.reason ?? null,
        source: ctx.source ?? null,
    });

    logEvent({
        level: 'warn', category: 'backup', action: 'backup.restore',
        message: `Configuration restored from backup (${result.rules?.imported ?? 0} rule(s)). Rollback snapshot: ${rollback.filename}`,
        actor: ctx.actor ?? 'system', source: ctx.source ?? null,
        details: result,
    });

    return result;
}

export async function readBackupFile(filename) {
    const safe = String(filename ?? '').replace(/[^A-Za-z0-9._-]/g, '');
    if (!safe || !safe.endsWith('.json')) throw new ValidationError('Invalid backup filename');
    const file = path.join(PATHS.backups, safe);
    const doc = await readJson(file, null);
    if (!doc) throw new NotFoundError('Backup', safe);
    return doc;
}

export async function deleteBackup(filename, ctx = {}) {
    const safe = String(filename ?? '').replace(/[^A-Za-z0-9._-]/g, '');
    if (!safe || !safe.endsWith('.json')) throw new ValidationError('Invalid backup filename');
    const file = path.join(PATHS.backups, safe);
    try {
        await fsp.unlink(file);
    } catch (err) {
        if (err.code === 'ENOENT') throw new NotFoundError('Backup', safe);
        throw err;
    }
    await audit({ actor: ctx.actor ?? 'system', action: 'backup.delete', target: safe, source: ctx.source ?? null });
    logEvent({
        level: 'warn', category: 'backup', action: 'backup.delete',
        message: `Backup deleted: ${safe}`, actor: ctx.actor ?? 'system', source: ctx.source ?? null,
    });
    return { filename: safe, deleted: true };
}
