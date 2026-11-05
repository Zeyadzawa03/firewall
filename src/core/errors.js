/**
 * Typed application errors.
 *
 * Every error carries an HTTP status and a stable machine-readable `code`
 * so the API layer never has to guess, and so the GUI can react to specific
 * failures (e.g. `PRIVILEGE_REQUIRED` -> show the elevation instructions).
 */

export class AppError extends Error {
    constructor(message, { code = 'INTERNAL_ERROR', status = 500, details = null, cause = null } = {}) {
        super(message);
        this.name = new.target.name;
        this.code = code;
        this.status = status;
        this.details = details;
        if (cause) this.cause = cause;
        Error.captureStackTrace?.(this, new.target);
    }

    toJSON() {
        return {
            error: {
                code: this.code,
                message: this.message,
                ...(this.details ? { details: this.details } : {}),
            },
        };
    }
}

/** Input failed validation. `details` is a list of {field, message} entries. */
export class ValidationError extends AppError {
    constructor(message, details = null) {
        super(message, { code: 'VALIDATION_ERROR', status: 400, details });
    }

    /** Build from a single field failure. */
    static field(field, message) {
        return new ValidationError(`Invalid ${field}: ${message}`, [{ field, message }]);
    }
}

export class NotFoundError extends AppError {
    constructor(what = 'Resource', id = null) {
        super(id ? `${what} not found: ${id}` : `${what} not found`, {
            code: 'NOT_FOUND',
            status: 404,
        });
    }
}

export class ConflictError extends AppError {
    constructor(message, details = null) {
        super(message, { code: 'CONFLICT', status: 409, details });
    }
}

export class AuthError extends AppError {
    constructor(message = 'Authentication required', code = 'UNAUTHENTICATED') {
        super(message, { code, status: 401 });
    }
}

export class ForbiddenError extends AppError {
    constructor(message = 'Insufficient permissions', details = null) {
        super(message, { code: 'FORBIDDEN', status: 403, details });
    }
}

export class RateLimitError extends AppError {
    constructor(retryAfterSeconds = 60) {
        super('Too many requests', { code: 'RATE_LIMITED', status: 429 });
        this.retryAfterSeconds = retryAfterSeconds;
    }
}

/** The action needs root/Administrator and the process does not have it. */
export class PrivilegeError extends AppError {
    constructor(message, hint = null) {
        super(message, {
            code: 'PRIVILEGE_REQUIRED',
            status: 403,
            details: hint ? { hint } : null,
        });
    }
}

/** An underlying OS command failed. Keeps stderr for diagnostics. */
export class ProviderError extends AppError {
    constructor(message, { provider = 'unknown', stderr = null, exitCode = null } = {}) {
        super(message, {
            code: 'PROVIDER_ERROR',
            status: 502,
            details: { provider, ...(exitCode !== null ? { exitCode } : {}), ...(stderr ? { stderr } : {}) },
        });
    }
}

/** The requested capability is not implemented by the active provider/platform. */
export class UnsupportedError extends AppError {
    constructor(message, details = null) {
        super(message, { code: 'UNSUPPORTED', status: 501, details });
    }
}

/** Normalise anything thrown into an AppError. */
export function toAppError(err) {
    if (err instanceof AppError) return err;
    if (err instanceof Error) {
        return new AppError(err.message, { code: 'INTERNAL_ERROR', status: 500, cause: err });
    }
    return new AppError(String(err), { code: 'INTERNAL_ERROR', status: 500 });
}
