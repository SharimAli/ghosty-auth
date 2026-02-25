'use strict';

/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║               GHOSTY Auth — keyService.js                   ║
 * ║         License key generation and validation logic         ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * Exports:
 *   generateLicenseKey(prefix?)      → 'GHOST-AB12-CD34-EF56'
 *   generateBatch(qty, prefix?)      → string[]
 *   isValidKeyFormat(key)            → boolean
 *   normaliseKey(key)                → uppercase trimmed string
 *   parseKeySegments(key)            → string[] | null
 *   computeKeyChecksum(key)          → string  (last segment checksum variant)
 *   validateKeyChecksum(key)         → boolean
 *   estimateKeyEntropy()             → number  (bits)
 *   sanitiseNote(note)               → string
 *   computeExpiryDate(days)          → Date | null
 *   isKeyExpired(expiresAt)          → boolean
 *   getKeyStatus(license)            → 'active' | 'expired' | 'banned'
 */

const crypto = require('crypto');

// ─── Constants ────────────────────────────────────────────────────────────────

// Default key prefix — change this to your product name
const DEFAULT_PREFIX = 'GHOST';

// Character set for key segments — unambiguous characters only.
// No 0/O, 1/I/L to prevent user confusion when reading/typing keys.
const CHARSET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

// Segment structure: PREFIX-XXXX-XXXX-XXXX
// Each X is drawn from CHARSET
const SEGMENT_LENGTH = 4;
const SEGMENT_COUNT  = 3;   // Three 4-char segments after the prefix
const CHARSET_LEN    = CHARSET.length;

// Key format regex — accepts any alphanumeric prefix of 3–8 chars
const KEY_FORMAT_REGEX = /^[A-Z0-9]{3,8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/;

// Max batch size per call — prevents accidental memory exhaustion
const MAX_BATCH_SIZE = 1000;

// ─── Key Generation ───────────────────────────────────────────────────────────

/**
 * Generates a single cryptographically secure license key.
 *
 * Format:  PREFIX-XXXX-XXXX-XXXX
 * Entropy: CHARSET(32) ^ 12 = 32^12 ≈ 2^60  (~1.15 quintillion combinations)
 *
 * Each character is drawn from CHARSET using rejection sampling on
 * crypto.randomBytes output — guarantees uniform distribution with
 * no modulo bias.
 *
 * @param {string} [prefix=DEFAULT_PREFIX]
 * @returns {string}  e.g. 'GHOST-AB12-CD34-EF56'
 */
function generateLicenseKey(prefix = DEFAULT_PREFIX) {
  _validatePrefix(prefix);

  const segments = [];

  for (let s = 0; s < SEGMENT_COUNT; s++) {
    segments.push(_randomSegment(SEGMENT_LENGTH));
  }

  return `${prefix.toUpperCase()}-${segments.join('-')}`;
}

/**
 * Generates multiple unique license keys in one call.
 * Deduplicates internally — guaranteed unique within the batch.
 *
 * @param {number} qty               — number of keys to generate
 * @param {string} [prefix]          — key prefix
 * @returns {string[]}               — array of unique key strings
 */
function generateBatch(qty, prefix = DEFAULT_PREFIX) {
  if (!Number.isInteger(qty) || qty < 1 || qty > MAX_BATCH_SIZE) {
    throw new RangeError(`[keyService] qty must be between 1 and ${MAX_BATCH_SIZE}. Got: ${qty}`);
  }

  const keys = new Set();

  // Generate with a safety ceiling to handle (extremely unlikely) collisions
  const maxAttempts = qty * 3;
  let   attempts    = 0;

  while (keys.size < qty && attempts < maxAttempts) {
    keys.add(generateLicenseKey(prefix));
    attempts++;
  }

  if (keys.size < qty) {
    throw new Error(`[keyService] Failed to generate ${qty} unique keys after ${maxAttempts} attempts.`);
  }

  return [...keys];
}

// ─── Secure Random Character Sampling ────────────────────────────────────────

/**
 * Generates a random segment of `length` characters from CHARSET.
 * Uses rejection sampling to guarantee uniform distribution.
 *
 * @param {number} length
 * @returns {string}
 */
function _randomSegment(length) {
  let result = '';

  // Determine the largest multiple of CHARSET_LEN that fits in a byte (0–255).
  // Reject values above this threshold to eliminate modulo bias.
  const cap = Math.floor(256 / CHARSET_LEN) * CHARSET_LEN;

  while (result.length < length) {
    // Request extra bytes to minimise iterations due to rejections
    const needed = length - result.length;
    const bytes  = crypto.randomBytes(needed * 2);

    for (let i = 0; i < bytes.length && result.length < length; i++) {
      const byte = bytes[i];
      if (byte < cap) {
        result += CHARSET[byte % CHARSET_LEN];
      }
      // Reject bytes >= cap (modulo bias prevention)
    }
  }

  return result;
}

// ─── Key Format Validation ────────────────────────────────────────────────────

/**
 * Returns true if `key` matches the expected key format.
 * Does NOT check if the key exists in the database.
 *
 * @param {string} key
 * @returns {boolean}
 */
function isValidKeyFormat(key) {
  if (typeof key !== 'string') return false;
  return KEY_FORMAT_REGEX.test(key.trim().toUpperCase());
}

/**
 * Normalises a key string: trims whitespace, uppercases, collapses spaces.
 *
 * @param {string} key
 * @returns {string}
 */
function normaliseKey(key) {
  if (typeof key !== 'string') return '';
  return key.trim().toUpperCase().replace(/\s+/g, '');
}

/**
 * Splits a key string into its segments.
 * Returns null if the format is invalid.
 *
 * @param {string} key
 * @returns {string[] | null}  e.g. ['GHOST', 'AB12', 'CD34', 'EF56']
 */
function parseKeySegments(key) {
  const normalised = normaliseKey(key);
  if (!isValidKeyFormat(normalised)) return null;
  return normalised.split('-');
}

// ─── Checksum ─────────────────────────────────────────────────────────────────

/**
 * Computes a 4-character checksum segment for a key's first 3 segments.
 * This is a lightweight integrity check — not a replacement for DB validation.
 *
 * Algorithm:
 *   1. Concatenate prefix + first two data segments
 *   2. SHA-256 hash the result
 *   3. Take 4 chars from the hash, map to CHARSET
 *
 * @param {string} key  — key with or without the last segment
 * @returns {string}    — 4-char checksum segment
 */
function computeKeyChecksum(key) {
  const parts = normaliseKey(key).split('-');
  if (parts.length < 3) {
    throw new Error('[keyService] computeKeyChecksum: key must have at least 3 segments.');
  }

  const base   = parts.slice(0, 3).join('-');
  const hash   = crypto.createHash('sha256').update(base, 'utf8').digest();
  let checksum = '';

  for (let i = 0; i < SEGMENT_LENGTH; i++) {
    checksum += CHARSET[hash[i] % CHARSET_LEN];
  }

  return checksum;
}

/**
 * Validates the checksum segment of a complete key.
 *
 * @param {string} key  — full key including last segment
 * @returns {boolean}
 */
function validateKeyChecksum(key) {
  const parts = parseKeySegments(key);
  if (!parts || parts.length !== 4) return false;

  const expectedChecksum = computeKeyChecksum(parts.slice(0, 3).join('-'));
  return parts[3] === expectedChecksum;
}

// ─── Entropy Estimation ───────────────────────────────────────────────────────

/**
 * Returns the theoretical entropy of a generated key in bits.
 * Useful for security documentation and auditing.
 *
 * Formula: log2(CHARSET_LEN ^ (SEGMENT_LENGTH * SEGMENT_COUNT))
 *
 * @returns {number}
 */
function estimateKeyEntropy() {
  const totalChars = SEGMENT_LENGTH * SEGMENT_COUNT;
  return Math.floor(Math.log2(Math.pow(CHARSET_LEN, totalChars)));
}

// ─── Lifecycle Helpers ────────────────────────────────────────────────────────

/**
 * Computes an expiry Date from a number of days from now.
 * Returns null if days is falsy (meaning: no expiry).
 *
 * @param {number|null|undefined} days
 * @returns {Date|null}
 */
function computeExpiryDate(days) {
  if (!days) return null;
  const d = parseInt(days, 10);
  if (isNaN(d) || d < 1) return null;
  return new Date(Date.now() + d * 24 * 60 * 60 * 1000);
}

/**
 * Returns true if the provided date is in the past.
 *
 * @param {Date|string|null} expiresAt
 * @returns {boolean}
 */
function isKeyExpired(expiresAt) {
  if (!expiresAt) return false;
  return new Date(expiresAt) < new Date();
}

/**
 * Returns a computed status string for a license record.
 * Mirrors the License model's getStatus() instance method — usable
 * without a Sequelize instance (e.g. in raw query results).
 *
 * @param {{ is_banned: boolean, expires_at: Date|string|null }} license
 * @returns {'active' | 'expired' | 'banned'}
 */
function getKeyStatus(license) {
  if (!license) throw new Error('[keyService] getKeyStatus: license is required.');
  if (license.is_banned) return 'banned';
  if (isKeyExpired(license.expires_at)) return 'expired';
  return 'active';
}

// ─── Input Sanitisation ───────────────────────────────────────────────────────

/**
 * Sanitises a seller-supplied note string.
 * Strips control characters, limits length.
 *
 * @param {string|null|undefined} note
 * @param {number} [maxLen=255]
 * @returns {string}
 */
function sanitiseNote(note, maxLen = 255) {
  if (!note || typeof note !== 'string') return '';
  // Strip control characters (0x00–0x1F except tab/newline)
  return note
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
    .trim()
    .slice(0, maxLen);
}

// ─── Prefix Validation ────────────────────────────────────────────────────────

function _validatePrefix(prefix) {
  if (typeof prefix !== 'string' || prefix.length < 2 || prefix.length > 8) {
    throw new RangeError('[keyService] Prefix must be a string between 2 and 8 characters.');
  }
  if (!/^[A-Z0-9]+$/i.test(prefix)) {
    throw new Error('[keyService] Prefix must be alphanumeric only.');
  }
}

// ─── Exports ──────────────────────────────────────────────────────────────────

module.exports = {
  // Generation
  generateLicenseKey,
  generateBatch,

  // Validation
  isValidKeyFormat,
  normaliseKey,
  parseKeySegments,

  // Checksum
  computeKeyChecksum,
  validateKeyChecksum,

  // Lifecycle
  computeExpiryDate,
  isKeyExpired,
  getKeyStatus,

  // Utilities
  estimateKeyEntropy,
  sanitiseNote,

  // Exposed for testing
  CHARSET,
  DEFAULT_PREFIX,
  KEY_FORMAT_REGEX,
};
