'use strict';

/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║               GHOSTY Auth — hwidService.js                  ║
 * ║         HWID validation, binding, and comparison logic      ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * The HWID (Hardware ID) is a SHA-256 hash of a machine's hardware
 * fingerprint, generated on the client side by the SDK.
 *
 * Server responsibilities:
 *   1. Validate that the submitted HWID is well-formed
 *   2. On first use: bind the HWID to the license (store it)
 *   3. On subsequent uses: compare submitted HWID against stored HWID
 *      using constant-time comparison (prevent timing oracle attacks)
 *   4. Track HWID resets for audit purposes
 *
 * Exports:
 *   validateHWID(hwid)                   → boolean
 *   compareHWID(submitted, stored)       → boolean  (constant-time)
 *   shouldBindHWID(license)              → boolean
 *   bindHWID(license, hwid)              → Promise<void>
 *   verifyHWID(license, submittedHwid)   → HWIDResult
 *   maskHWID(hwid)                       → string  (safe for logging)
 *   isHWIDResetAllowed(license)          → boolean
 *   getHWIDStatus(license)               → HWIDStatus object
 */

const crypto  = require('crypto');
const logger  = require('../utils/logger');

// ─── Constants ────────────────────────────────────────────────────────────────

// A valid HWID is exactly a 64-character lowercase hex string (SHA-256 output)
const HWID_REGEX  = /^[0-9a-f]{64}$/;
const HWID_LENGTH = 64;

// Minimum days between HWID resets (cooldown — future feature hook)
const HWID_RESET_COOLDOWN_DAYS = 0;   // 0 = no cooldown enforced by this service

// ─── Types (JSDoc) ────────────────────────────────────────────────────────────

/**
 * @typedef {object} HWIDResult
 * @property {boolean} valid       — whether the HWID check passed
 * @property {string}  reason      — machine-readable reason code if invalid
 * @property {boolean} justBound   — true if this was the first use (binding event)
 */

/**
 * @typedef {object} HWIDStatus
 * @property {boolean}     bound        — whether a HWID is currently bound
 * @property {string|null} maskedHWID   — first 8 chars + '...' or null
 * @property {Date|null}   boundAt      — when first_used_at was set (proxy for bind time)
 */

// ─────────────────────────────────────────────────────────────────────────────
//  validateHWID
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns true if the submitted HWID is a valid SHA-256 hex string.
 * Does NOT check against any database — purely format validation.
 *
 * @param {string} hwid
 * @returns {boolean}
 */
function validateHWID(hwid) {
  if (typeof hwid !== 'string') return false;
  return HWID_REGEX.test(hwid);
}

// ─────────────────────────────────────────────────────────────────────────────
//  compareHWID
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Compares two HWID strings in constant time.
 * Prevents timing oracle attacks.
 *
 * Returns false immediately (fast path) if either value is missing,
 * or if lengths differ — but still runs the full comparison when lengths
 * match to prevent timing leakage based on missing-vs-wrong.
 *
 * @param {string} submitted   — HWID from the request
 * @param {string} stored      — HWID stored in the database
 * @returns {boolean}
 */
function compareHWID(submitted, stored) {
  if (!submitted || !stored) return false;
  if (typeof submitted !== 'string' || typeof stored !== 'string') return false;

  // Both must be valid format before comparing
  if (!validateHWID(submitted) || !validateHWID(stored)) return false;

  try {
    return crypto.timingSafeEqual(
      Buffer.from(submitted.toLowerCase(), 'hex'),
      Buffer.from(stored.toLowerCase(),   'hex')
    );
  } catch {
    // Buffer conversion failure (shouldn't happen given regex check above)
    return false;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  shouldBindHWID
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns true if the license has no HWID bound yet (first use).
 * Also considers the application's hwid_lock_enabled setting.
 *
 * @param {object} license           — Sequelize License instance or plain object
 * @param {object} [app]             — Application record (optional)
 * @returns {boolean}
 */
function shouldBindHWID(license, app = null) {
  // If app explicitly disables HWID locking, skip binding
  if (app && app.hwid_lock_enabled === false) return false;

  // If no HWID is stored yet, this is first use — bind it
  return !license.hwid;
}

// ─────────────────────────────────────────────────────────────────────────────
//  bindHWID
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Binds a HWID to a license on first use.
 * Also sets first_used_at if not already set.
 *
 * @param {object} license        — Sequelize License instance (must support .update())
 * @param {string} hwid           — validated HWID hex string
 * @returns {Promise<void>}
 */
async function bindHWID(license, hwid) {
  if (!validateHWID(hwid)) {
    throw new Error('[hwidService] bindHWID: invalid HWID format.');
  }

  if (license.hwid) {
    throw new Error('[hwidService] bindHWID: license already has a HWID bound. Use resetHWID first.');
  }

  const updates = {
    hwid:         hwid.toLowerCase(),
    first_used_at: license.first_used_at || new Date(),
  };

  await license.update(updates);

  logger.info(`[hwidService] HWID bound — license=${license.id} hwid=${maskHWID(hwid)}`);
}

// ─────────────────────────────────────────────────────────────────────────────
//  verifyHWID
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Full HWID check for an auth request.
 * Handles both "first use" (bind) and "repeat use" (verify) cases.
 *
 * Does NOT perform the DB write itself on bind — returns justBound=true
 * so the caller can decide when to commit (after all other checks pass).
 *
 * @param {object} license           — License record (plain object or Sequelize instance)
 * @param {string} submittedHwid     — HWID from the client request
 * @param {object} [app]             — Application record (for hwid_lock_enabled check)
 * @returns {HWIDResult}
 */
function verifyHWID(license, submittedHwid, app = null) {
  // ── 1. Validate format ────────────────────────────────────────────────────
  if (!validateHWID(submittedHwid)) {
    return { valid: false, reason: 'INVALID_HWID_FORMAT', justBound: false };
  }

  // ── 2. Check if HWID locking is disabled for this app ─────────────────────
  if (app && app.hwid_lock_enabled === false) {
    return { valid: true, reason: null, justBound: false };
  }

  // ── 3. First use — no HWID stored yet ─────────────────────────────────────
  if (!license.hwid) {
    // Signal to caller that binding should occur
    return { valid: true, reason: null, justBound: true };
  }

  // ── 4. Repeat use — compare submitted HWID against stored ─────────────────
  const match = compareHWID(submittedHwid, license.hwid);

  if (!match) {
    logger.warn(
      `[hwidService] HWID mismatch — license=${license.id} ` +
      `submitted=${maskHWID(submittedHwid)} stored=${maskHWID(license.hwid)}`
    );
    return { valid: false, reason: 'HWID_MISMATCH', justBound: false };
  }

  return { valid: true, reason: null, justBound: false };
}

// ─────────────────────────────────────────────────────────────────────────────
//  maskHWID
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns a safe partial representation of a HWID for logging.
 * Never logs the full HWID — even hashes shouldn't be fully exposed in logs.
 *
 * @param {string|null} hwid
 * @returns {string}
 */
function maskHWID(hwid) {
  if (!hwid || typeof hwid !== 'string') return '[none]';
  if (hwid.length < 8) return '[invalid]';
  return `${hwid.slice(0, 8)}...`;
}

// ─────────────────────────────────────────────────────────────────────────────
//  isHWIDResetAllowed
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns true if a HWID reset is permitted for the given license.
 *
 * Current rules:
 *   - License must have a HWID bound (nothing to reset otherwise)
 *   - License must not be banned
 *   - Cooldown: if HWID_RESET_COOLDOWN_DAYS > 0, checks first_used_at
 *
 * Sellers can override the cooldown from their dashboard —
 * this function enforces the system-level default only.
 *
 * @param {object} license
 * @returns {{ allowed: boolean, reason: string | null }}
 */
function isHWIDResetAllowed(license) {
  if (!license.hwid) {
    return { allowed: false, reason: 'NO_HWID_BOUND' };
  }

  if (license.is_banned) {
    return { allowed: false, reason: 'KEY_BANNED' };
  }

  if (HWID_RESET_COOLDOWN_DAYS > 0 && license.first_used_at) {
    const cooldownMs   = HWID_RESET_COOLDOWN_DAYS * 24 * 60 * 60 * 1000;
    const nextResetAt  = new Date(license.first_used_at).getTime() + cooldownMs;
    if (Date.now() < nextResetAt) {
      const remainingHours = Math.ceil((nextResetAt - Date.now()) / (60 * 60 * 1000));
      return {
        allowed: false,
        reason:  `COOLDOWN_ACTIVE`,
        detail:  `Reset available in ~${remainingHours} hour(s).`,
      };
    }
  }

  return { allowed: true, reason: null };
}

// ─────────────────────────────────────────────────────────────────────────────
//  getHWIDStatus
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns a summary of the HWID status for a license.
 * Used in dashboard API responses.
 *
 * @param {object} license
 * @returns {HWIDStatus}
 */
function getHWIDStatus(license) {
  return {
    bound:      !!license.hwid,
    maskedHWID: license.hwid ? maskHWID(license.hwid) : null,
    boundAt:    license.first_used_at || null,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
//  normaliseHWID
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Normalises a HWID string to lowercase for consistent storage and comparison.
 *
 * @param {string} hwid
 * @returns {string}
 */
function normaliseHWID(hwid) {
  if (!validateHWID(hwid)) {
    throw new Error('[hwidService] normaliseHWID: invalid HWID format.');
  }
  return hwid.toLowerCase();
}

// ─── Exports ──────────────────────────────────────────────────────────────────

module.exports = {
  validateHWID,
  compareHWID,
  shouldBindHWID,
  bindHWID,
  verifyHWID,
  maskHWID,
  normaliseHWID,
  isHWIDResetAllowed,
  getHWIDStatus,

  // Expose for testing
  HWID_REGEX,
  HWID_LENGTH,
};
