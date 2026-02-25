'use strict';

/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║               GHOSTY Auth — validator.js                    ║
 * ║          Input validation and sanitisation helpers          ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * Design principles:
 *   - Every function is pure (no I/O, no side effects)
 *   - Functions return { valid: boolean, error?: string }
 *   - Sanitisers return a cleaned value or throw on unrecoverable input
 *   - Nothing here touches the database
 *
 * Exports:
 *
 *  ── Field validators ────────────────────────────────────────────
 *   validateUsername(value)          → ValidationResult
 *   validateEmail(value)             → ValidationResult
 *   validatePassword(value)          → ValidationResult  (+strength report)
 *   validateLicenseKey(value)        → ValidationResult
 *   validateHWID(value)              → ValidationResult
 *   validateUUID(value)              → ValidationResult
 *   validateAppName(value)           → ValidationResult
 *   validateNote(value)              → ValidationResult
 *   validateDays(value)              → ValidationResult
 *   validateQuantity(value, max)     → ValidationResult
 *   validateTimestamp(value)         → ValidationResult
 *   validateHexSignature(value)      → ValidationResult
 *   validateRole(value)              → ValidationResult
 *   validateIPAddress(value)         → ValidationResult
 *   validatePaginationParams(q)      → { page, limit, errors }
 *
 *  ── Batch validator ─────────────────────────────────────────────
 *   validateFields(schema, data)     → { valid, errors[] }
 *
 *  ── Sanitisers ──────────────────────────────────────────────────
 *   sanitiseString(value, maxLen)    → string
 *   sanitiseEmail(value)             → string (lowercase, trimmed)
 *   sanitiseKey(value)               → string (uppercase, trimmed)
 *   sanitiseHWID(value)              → string (lowercase, trimmed)
 *   sanitiseNote(value, maxLen)      → string (control chars stripped)
 *   sanitiseInt(value, min, max)     → number | null
 *   sanitisePage(value)              → number (≥1)
 *   sanitiseLimit(value, max)        → number (clamped)
 *
 *  ── Predicates ──────────────────────────────────────────────────
 *   isNonEmptyString(value)          → boolean
 *   isSafePositiveInt(value)         → boolean
 *   isValidDate(value)               → boolean
 */

// ─── Constants ────────────────────────────────────────────────────────────────

const USERNAME_MIN   = 3;
const USERNAME_MAX   = 32;
const PASSWORD_MIN   = 8;
const PASSWORD_MAX   = 128;
const APP_NAME_MIN   = 1;
const APP_NAME_MAX   = 64;
const NOTE_MAX       = 255;
const EMAIL_MAX      = 254;
const DAYS_MIN       = 1;
const DAYS_MAX       = 36500;   // 100 years
const QTY_MIN        = 1;
const QTY_DEFAULT_MAX = 100;

// Request timestamp tolerance: ±30 seconds (matches server setting)
const TIMESTAMP_TOLERANCE_MS = parseInt(
  process.env.REQUEST_TIMESTAMP_TOLERANCE_MS || '30000',
  10
);

// ─── Regex Patterns ───────────────────────────────────────────────────────────

const PATTERNS = Object.freeze({
  username:       /^[a-zA-Z0-9_]{3,32}$/,
  email:          /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/,
  // Lowercase-tolerant password: min 8 chars, 1 upper, 1 lower, 1 digit
  password:       /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,128}$/,
  licenseKey:     /^[A-Z0-9]{3,8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/,
  hwid:           /^[0-9a-f]{64}$/,
  uuid:           /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
  hexSignature:   /^[0-9a-f]{64}$/,
  ipv4:           /^(\d{1,3}\.){3}\d{1,3}$/,
  ipv6:           /^[0-9a-f:]{2,39}$/i,
  // Control characters except tab and newline
  controlChars:   /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g,
});

const VALID_ROLES = Object.freeze(['seller', 'admin']);

// ─── ValidationResult factory ─────────────────────────────────────────────────

/** @typedef {{ valid: boolean, error?: string }} ValidationResult */

function pass()          { return { valid: true }; }
function err(message)    { return { valid: false, error: message }; }

// ─────────────────────────────────────────────────────────────────────────────
//  Field Validators
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Validates a seller username.
 * Rules: 3–32 chars, letters/numbers/underscores only, no leading/trailing underscore.
 *
 * @param {*} value
 * @returns {ValidationResult}
 */
function validateUsername(value) {
  if (!isNonEmptyString(value)) {
    return err('Username is required.');
  }
  const v = value.trim();
  if (v.length < USERNAME_MIN) {
    return err(`Username must be at least ${USERNAME_MIN} characters.`);
  }
  if (v.length > USERNAME_MAX) {
    return err(`Username must not exceed ${USERNAME_MAX} characters.`);
  }
  if (!PATTERNS.username.test(v)) {
    return err('Username may only contain letters, numbers, and underscores.');
  }
  if (v.startsWith('_') || v.endsWith('_')) {
    return err('Username must not start or end with an underscore.');
  }
  return pass();
}

/**
 * Validates an email address.
 *
 * @param {*} value
 * @returns {ValidationResult}
 */
function validateEmail(value) {
  if (!isNonEmptyString(value)) {
    return err('Email address is required.');
  }
  const v = value.trim().toLowerCase();
  if (v.length > EMAIL_MAX) {
    return err(`Email must not exceed ${EMAIL_MAX} characters.`);
  }
  if (!PATTERNS.email.test(v)) {
    return err('A valid email address is required.');
  }
  return pass();
}

/**
 * Validates a password against strength requirements.
 * Returns a detailed strength report in addition to pass/fail.
 *
 * @param {*}       value
 * @param {object}  [options]
 * @param {number}  [options.minLen]  — override minimum length
 * @returns {ValidationResult & { strength?: object }}
 */
function validatePassword(value, options = {}) {
  const minLen = options.minLen ?? PASSWORD_MIN;

  if (!isNonEmptyString(value)) {
    return err('Password is required.');
  }
  if (value.length < minLen) {
    return err(`Password must be at least ${minLen} characters.`);
  }
  if (value.length > PASSWORD_MAX) {
    return err(`Password must not exceed ${PASSWORD_MAX} characters.`);
  }

  const hasLower   = /[a-z]/.test(value);
  const hasUpper   = /[A-Z]/.test(value);
  const hasDigit   = /\d/.test(value);
  const hasSpecial = /[!@#$%^&*()_+\-=\[\]{}|;':",.<>?/`~\\]/.test(value);

  const strength = {
    has_lowercase:    hasLower,
    has_uppercase:    hasUpper,
    has_digit:        hasDigit,
    has_special_char: hasSpecial,
    length:           value.length,
    score: [hasLower, hasUpper, hasDigit, hasSpecial, value.length >= 12].filter(Boolean).length,
  };

  if (!hasLower) return { ...err('Password must include at least one lowercase letter.'), strength };
  if (!hasUpper) return { ...err('Password must include at least one uppercase letter.'), strength };
  if (!hasDigit) return { ...err('Password must include at least one number.'), strength };

  return { valid: true, strength };
}

/**
 * Validates a license key string format.
 * Does NOT check whether the key exists in the database.
 *
 * @param {*} value
 * @returns {ValidationResult}
 */
function validateLicenseKey(value) {
  if (!isNonEmptyString(value)) {
    return err('License key is required.');
  }
  const v = value.trim().toUpperCase();
  if (!PATTERNS.licenseKey.test(v)) {
    return err('License key must match format: PREFIX-XXXX-XXXX-XXXX (e.g. GHOST-AB12-CD34-EF56).');
  }
  return pass();
}

/**
 * Validates a HWID string.
 * Must be exactly 64 lowercase hex characters (SHA-256 output).
 *
 * @param {*} value
 * @returns {ValidationResult}
 */
function validateHWID(value) {
  if (!isNonEmptyString(value)) {
    return err('HWID is required.');
  }
  if (value.length !== 64) {
    return err('HWID must be exactly 64 characters.');
  }
  if (!PATTERNS.hwid.test(value.toLowerCase())) {
    return err('HWID must be a 64-character hexadecimal string (SHA-256 hash).');
  }
  return pass();
}

/**
 * Validates a UUID v4 string.
 *
 * @param {*} value
 * @param {string} [fieldName='ID']
 * @returns {ValidationResult}
 */
function validateUUID(value, fieldName = 'ID') {
  if (!isNonEmptyString(value)) {
    return err(`${fieldName} is required.`);
  }
  if (!PATTERNS.uuid.test(value.trim())) {
    return err(`${fieldName} must be a valid UUID.`);
  }
  return pass();
}

/**
 * Validates an application name.
 *
 * @param {*} value
 * @returns {ValidationResult}
 */
function validateAppName(value) {
  if (!isNonEmptyString(value)) {
    return err('Application name is required.');
  }
  const v = value.trim();
  if (v.length < APP_NAME_MIN) {
    return err('Application name cannot be empty.');
  }
  if (v.length > APP_NAME_MAX) {
    return err(`Application name must not exceed ${APP_NAME_MAX} characters.`);
  }
  return pass();
}

/**
 * Validates a seller/admin note.
 *
 * @param {*}      value
 * @param {number} [maxLen=255]
 * @returns {ValidationResult}
 */
function validateNote(value, maxLen = NOTE_MAX) {
  if (value === null || value === undefined || value === '') return pass();
  if (typeof value !== 'string') {
    return err('Note must be a string.');
  }
  if (value.length > maxLen) {
    return err(`Note must not exceed ${maxLen} characters.`);
  }
  return pass();
}

/**
 * Validates a number-of-days value.
 *
 * @param {*}      value
 * @param {number} [min=DAYS_MIN]
 * @param {number} [max=DAYS_MAX]
 * @returns {ValidationResult}
 */
function validateDays(value, min = DAYS_MIN, max = DAYS_MAX) {
  if (value === null || value === undefined) return pass();   // null = no expiry
  const n = parseInt(value, 10);
  if (isNaN(n)) {
    return err('Days must be a number.');
  }
  if (n < min) {
    return err(`Days must be at least ${min}.`);
  }
  if (n > max) {
    return err(`Days must not exceed ${max}.`);
  }
  return pass();
}

/**
 * Validates a key generation quantity.
 *
 * @param {*}      value
 * @param {number} [max=QTY_DEFAULT_MAX]
 * @returns {ValidationResult}
 */
function validateQuantity(value, max = QTY_DEFAULT_MAX) {
  const n = parseInt(value, 10);
  if (isNaN(n)) {
    return err('Quantity must be a number.');
  }
  if (n < QTY_MIN) {
    return err(`Quantity must be at least ${QTY_MIN}.`);
  }
  if (n > max) {
    return err(`Quantity must not exceed ${max}.`);
  }
  return pass();
}

/**
 * Validates a request timestamp for freshness (anti-replay).
 *
 * @param {*} value
 * @returns {ValidationResult}
 */
function validateTimestamp(value) {
  const ts = Number(value);
  if (!Number.isFinite(ts) || ts <= 0) {
    return err('Timestamp must be a positive Unix millisecond value.');
  }
  const diff = Math.abs(Date.now() - ts);
  if (diff > TIMESTAMP_TOLERANCE_MS) {
    return err(
      `Timestamp is outside the ±${TIMESTAMP_TOLERANCE_MS / 1000}s tolerance window. ` +
      `Server time: ${Date.now()}, received: ${ts}, diff: ${diff}ms.`
    );
  }
  return pass();
}

/**
 * Validates an HMAC-SHA256 hex signature (64-char lowercase hex).
 *
 * @param {*} value
 * @returns {ValidationResult}
 */
function validateHexSignature(value) {
  if (!isNonEmptyString(value)) {
    return err('Request signature is required.');
  }
  if (value.length !== 64) {
    return err('Request signature must be 64 characters (HMAC-SHA256 hex).');
  }
  if (!PATTERNS.hexSignature.test(value)) {
    return err('Request signature must be a lowercase hexadecimal string.');
  }
  return pass();
}

/**
 * Validates a user role string.
 *
 * @param {*} value
 * @returns {ValidationResult}
 */
function validateRole(value) {
  if (!isNonEmptyString(value)) {
    return err('Role is required.');
  }
  if (!VALID_ROLES.includes(value.toLowerCase().trim())) {
    return err(`Role must be one of: ${VALID_ROLES.join(', ')}.`);
  }
  return pass();
}

/**
 * Validates an IP address (IPv4 or IPv6).
 *
 * @param {*} value
 * @returns {ValidationResult}
 */
function validateIPAddress(value) {
  if (!isNonEmptyString(value)) {
    return err('IP address is required.');
  }
  const isIPv4 = PATTERNS.ipv4.test(value);
  const isIPv6 = PATTERNS.ipv6.test(value);
  if (!isIPv4 && !isIPv6) {
    return err('Must be a valid IPv4 or IPv6 address.');
  }
  return pass();
}

/**
 * Validates and normalises pagination query params.
 *
 * @param {object} query       — req.query
 * @param {number} [maxLimit]
 * @returns {{ page: number, limit: number, errors: string[] }}
 */
function validatePaginationParams(query, maxLimit = 100) {
  const errors = [];

  const page  = sanitiseInt(query.page,  1, 10000) ?? 1;
  const limit = sanitiseInt(query.limit, 1, maxLimit) ?? 50;

  if (query.page  !== undefined && page  === null) errors.push('page must be a positive integer.');
  if (query.limit !== undefined && limit === null) errors.push('limit must be between 1 and ' + maxLimit + '.');

  return { page, limit, errors };
}

// ─────────────────────────────────────────────────────────────────────────────
//  Batch Validator
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Validates multiple fields against a schema in one call.
 *
 * Schema format:
 * {
 *   fieldName: {
 *     required:  boolean,
 *     validator: (value) => ValidationResult,
 *   }
 * }
 *
 * Example:
 *   validateFields({
 *     license_key: { required: true, validator: validateLicenseKey },
 *     hwid:        { required: true, validator: validateHWID },
 *     app_id:      { required: true, validator: (v) => validateUUID(v, 'app_id') },
 *   }, req.body);
 *
 * @param {object} schema
 * @param {object} data
 * @returns {{ valid: boolean, errors: Array<{ field: string, message: string }> }}
 */
function validateFields(schema, data) {
  const errors = [];

  for (const [field, rules] of Object.entries(schema)) {
    const value = data?.[field];

    // Required check
    if (rules.required && (value === undefined || value === null || value === '')) {
      errors.push({ field, message: `${field} is required.` });
      continue;
    }

    // Skip optional missing fields
    if (!rules.required && (value === undefined || value === null || value === '')) {
      continue;
    }

    // Run validator
    if (rules.validator) {
      const result = rules.validator(value);
      if (!result.valid) {
        errors.push({ field, message: result.error });
      }
    }
  }

  return {
    valid:  errors.length === 0,
    errors,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
//  Sanitisers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Trims and limits a string. Returns '' for non-strings.
 *
 * @param {*}      value
 * @param {number} maxLen
 * @returns {string}
 */
function sanitiseString(value, maxLen = 255) {
  if (typeof value !== 'string') return '';
  return value.trim().slice(0, maxLen);
}

/**
 * Normalises an email: lowercase, trimmed.
 *
 * @param {*} value
 * @returns {string}
 */
function sanitiseEmail(value) {
  if (typeof value !== 'string') return '';
  return value.trim().toLowerCase().slice(0, EMAIL_MAX);
}

/**
 * Normalises a license key: uppercase, trimmed.
 *
 * @param {*} value
 * @returns {string}
 */
function sanitiseKey(value) {
  if (typeof value !== 'string') return '';
  return value.trim().toUpperCase().slice(0, 64);
}

/**
 * Normalises a HWID: lowercase, trimmed.
 *
 * @param {*} value
 * @returns {string}
 */
function sanitiseHWID(value) {
  if (typeof value !== 'string') return '';
  return value.trim().toLowerCase().slice(0, 64);
}

/**
 * Sanitises a free-text note.
 * Strips control characters (except tab/newline), trims, limits length.
 *
 * @param {*}      value
 * @param {number} [maxLen=255]
 * @returns {string}
 */
function sanitiseNote(value, maxLen = NOTE_MAX) {
  if (typeof value !== 'string') return '';
  return value
    .replace(PATTERNS.controlChars, '')
    .trim()
    .slice(0, maxLen);
}

/**
 * Parses an integer within a [min, max] range.
 * Returns null if out of range or not a number.
 *
 * @param {*}      value
 * @param {number} min
 * @param {number} max
 * @returns {number|null}
 */
function sanitiseInt(value, min, max) {
  const n = parseInt(value, 10);
  if (isNaN(n) || n < min || n > max) return null;
  return n;
}

/**
 * Parses a page number. Clamps to ≥1.
 *
 * @param {*} value
 * @returns {number}
 */
function sanitisePage(value) {
  return Math.max(1, sanitiseInt(value, 1, 100000) ?? 1);
}

/**
 * Parses a page limit. Clamps between 1 and max.
 *
 * @param {*}      value
 * @param {number} [max=100]
 * @returns {number}
 */
function sanitiseLimit(value, max = 100) {
  return Math.min(max, Math.max(1, sanitiseInt(value, 1, max) ?? 50));
}

// ─────────────────────────────────────────────────────────────────────────────
//  Predicates
// ─────────────────────────────────────────────────────────────────────────────

/** Returns true if value is a non-empty string. */
function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

/** Returns true if value is a positive integer. */
function isSafePositiveInt(value) {
  return Number.isInteger(value) && value > 0 && value <= Number.MAX_SAFE_INTEGER;
}

/** Returns true if value is a valid Date object or parseable date string. */
function isValidDate(value) {
  if (!value) return false;
  const d = new Date(value);
  return d instanceof Date && !isNaN(d.getTime());
}

// ─── Exports ──────────────────────────────────────────────────────────────────

module.exports = {
  // Field validators
  validateUsername,
  validateEmail,
  validatePassword,
  validateLicenseKey,
  validateHWID,
  validateUUID,
  validateAppName,
  validateNote,
  validateDays,
  validateQuantity,
  validateTimestamp,
  validateHexSignature,
  validateRole,
  validateIPAddress,
  validatePaginationParams,

  // Batch
  validateFields,

  // Sanitisers
  sanitiseString,
  sanitiseEmail,
  sanitiseKey,
  sanitiseHWID,
  sanitiseNote,
  sanitiseInt,
  sanitisePage,
  sanitiseLimit,

  // Predicates
  isNonEmptyString,
  isSafePositiveInt,
  isValidDate,

  // Exposed for testing
  PATTERNS,
  VALID_ROLES,
};
