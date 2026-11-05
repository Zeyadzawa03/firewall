/** Identifier helpers: short, URL-safe, collision-resistant. */

import crypto from 'node:crypto';

const ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789';

/** `prefix_<10 chars>` — enough entropy for local state, readable in logs. */
export function randomId(prefix = 'id', length = 10) {
    const bytes = crypto.randomBytes(length);
    let out = '';
    for (let i = 0; i < length; i++) out += ALPHABET[bytes[i] % ALPHABET.length];
    return `${prefix}_${out}`;
}

/** 256-bit opaque token for session cookies / CSRF. */
export function randomToken(bytes = 32) {
    return crypto.randomBytes(bytes).toString('base64url');
}

/** Stable hash used to correlate a managed rule with its OS counterpart. */
export function shortHash(input, length = 8) {
    return crypto.createHash('sha256').update(String(input)).digest('hex').slice(0, length);
}

export function timestampSlug(d = new Date()) {
    return d.toISOString().replace(/[:.]/g, '-').replace('Z', 'Z');
}
