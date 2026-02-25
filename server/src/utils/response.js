'use strict';

/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║               GHOSTY Auth — response.js                     ║
 * ║         Standardised API response builder helpers           ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * All API responses follow one of two shapes:
 *
 * ── Unsigned response (seller/admin dashboard routes) ────────────
 * {
 *   "success":   true | false,
 *   "code":      "ERROR_CODE",          ← only on failure
 *   "message":   "Human-readable text",
 *   "data":      { ... } | null,
 *   "meta":      { pagination, ... },   ← optional
 *   "timestamp": 1700000000000
 * }
 *
 * ── Signed response (client SDK auth routes) ─────────────────────
 * {
 *   "success":   true | false,
 *   "message":   "...",
 *   "data":      { ... } | null,
 *   "timestamp": 1700000000000,
 *   "signature": "hmac_sha256_hex"      ← clients MUST verify this
 * }
 *
 * Usage:
 *   const { ok, fail, paginated, signResponse } = require('../utils/response');
 *
 *   // Simple success
 *   return res.status(200).json(ok('Operation completed.', { id: 1 }));
 *
 *   // Error
 *   return res.status(400).json(fail('MISSING_FIELDS', 'field is required.'));
 *
 *   // Paginated list
 *   return res.status(200).json(paginated(rows, count, page, limit));
 *
 *   // Signed (for auth routes)
 *   return res.status(200).json(signResponse(true, 'OK', data, appSecret));
 */

const crypto = require('crypto');

// ─── Unsigned Responses ───────────────────────────────────────────────────────

/**
 * Builds a successful API response.
 *
 * @param {string}        message    — Human-readable success message
 * @param {*}             [data]     — Response payload (any JSON value)
 * @param {object}        [meta]     — Optional metadata (pagination, counts, etc.)
 * @returns {object}
 */
function ok(message, data = null, meta = null) {
  const response = {
    success:   true,
    message,
    data:      data ?? null,
    timestamp: Date.now(),
  };

  if (meta && typeof meta === 'object') {
    response.meta = meta;
  }

  return response;
}

/**
 * Builds a failure API response.
 *
 * @param {string}  code     — Machine-readable error code (e.g. 'MISSING_FIELDS')
 * @param {string}  message  — Human-readable error description
 * @param {object}  [errors] — Optional array of field-level validation errors
 * @returns {object}
 */
function fail(code, message, errors = null) {
  const response = {
    success:   false,
    code:      code || 'ERROR',
    message:   message || 'An error occurred.',
    timestamp: Date.now(),
  };

  if (errors && Array.isArray(errors) && errors.length > 0) {
    response.errors = errors;
  }

  return response;
}

/**
 * Builds a validation error response with per-field error details.
 *
 * @param {Array<{ field: string, message: string }>} fieldErrors
 * @returns {object}
 */
function validationFail(fieldErrors) {
  return {
    success:   false,
    code:      'VALIDATION_ERROR',
    message:   'One or more fields failed validation.',
    errors:    fieldErrors,
    timestamp: Date.now(),
  };
}

// ─── Paginated Response ───────────────────────────────────────────────────────

/**
 * Builds a paginated list response.
 *
 * @param {Array}   rows        — The data rows for the current page
 * @param {number}  total       — Total record count across all pages
 * @param {number}  page        — Current page (1-indexed)
 * @param {number}  limit       — Page size
 * @param {string}  [message]
 * @returns {object}
 */
function paginated(rows, total, page, limit, message = 'OK') {
  const totalPages = Math.ceil(total / limit) || 1;

  return {
    success: true,
    message,
    data:    rows,
    meta: {
      pagination: {
        total,
        page,
        limit,
        total_pages: totalPages,
        has_next:    page < totalPages,
        has_prev:    page > 1,
      },
    },
    timestamp: Date.now(),
  };
}

// ─── Signed Response ──────────────────────────────────────────────────────────

/**
 * Builds a signed API response for auth routes.
 * The HMAC signature lets the SDK verify the response wasn't tampered with.
 *
 * Signature = HMAC-SHA256(appSecret, timestamp:JSON.stringify(data))
 *
 * @param {boolean}       success
 * @param {string}        message
 * @param {*}             data      — must be JSON-serialisable
 * @param {string}        secret    — the app's HMAC secret (hex string)
 * @returns {object}                — full response body
 */
function signResponse(success, message, data, secret) {
  if (!secret || typeof secret !== 'string') {
    throw new Error('[response] signResponse: secret is required.');
  }

  const timestamp = Date.now();
  const dataJson  = JSON.stringify(data ?? null);
  const sigInput  = `${timestamp}:${dataJson}`;

  const signature = crypto
    .createHmac('sha256', secret)
    .update(sigInput, 'utf8')
    .digest('hex');

  return {
    success,
    message,
    data:      data ?? null,
    timestamp,
    signature,
  };
}

/**
 * Verifies the signature on a signed response.
 * Used for testing and SDK-side verification.
 *
 * @param {object} response   — The full response object
 * @param {string} secret     — The app's HMAC secret
 * @returns {boolean}
 */
function verifySignedResponse(response, secret) {
  if (!response?.signature || !response?.timestamp || !secret) return false;

  const dataJson  = JSON.stringify(response.data ?? null);
  const sigInput  = `${response.timestamp}:${dataJson}`;
  const expected  = crypto
    .createHmac('sha256', secret)
    .update(sigInput, 'utf8')
    .digest('hex');

  try {
    return crypto.timingSafeEqual(
      Buffer.from(expected,            'hex'),
      Buffer.from(response.signature,  'hex')
    );
  } catch {
    return false;
  }
}

// ─── HTTP Status Helpers ──────────────────────────────────────────────────────

/**
 * Pre-built response objects for common HTTP scenarios.
 * Avoids magic strings scattered across controllers.
 */
const HTTP = Object.freeze({
  badRequest:       (detail = 'Bad request.')           => fail('BAD_REQUEST',       detail),
  unauthorized:     (detail = 'Unauthorized.')          => fail('UNAUTHORIZED',      detail),
  forbidden:        (detail = 'Forbidden.')             => fail('FORBIDDEN',         detail),
  notFound:         (detail = 'Resource not found.')    => fail('NOT_FOUND',         detail),
  conflict:         (detail = 'Resource conflict.')     => fail('CONFLICT',          detail),
  tooManyRequests:  (detail = 'Rate limit exceeded.')   => fail('RATE_LIMITED',      detail),
  serverError:      (detail = 'Internal server error.') => fail('SERVER_ERROR',      detail),
  notImplemented:   (detail = 'Not implemented.')       => fail('NOT_IMPLEMENTED',   detail),
});

// ─── Error Code Registry ──────────────────────────────────────────────────────

/**
 * Canonical error codes used across the system.
 * Import this instead of using magic strings in controllers.
 *
 * const { CODES } = require('../utils/response');
 * return res.status(401).json(fail(CODES.INVALID_KEY, '...'));
 */
const CODES = Object.freeze({
  // Generic
  MISSING_FIELDS:       'MISSING_FIELDS',
  VALIDATION_ERROR:     'VALIDATION_ERROR',
  INVALID_INPUT:        'INVALID_INPUT',
  NOT_FOUND:            'NOT_FOUND',
  CONFLICT:             'CONFLICT',
  FORBIDDEN:            'FORBIDDEN',
  UNAUTHORIZED:         'UNAUTHORIZED',
  SERVER_ERROR:         'SERVER_ERROR',
  RATE_LIMITED:         'RATE_LIMITED',
  NO_CHANGES:           'NO_CHANGES',
  LIMIT_REACHED:        'LIMIT_REACHED',
  UNSUPPORTED_MEDIA:    'UNSUPPORTED_MEDIA_TYPE',
  PAYLOAD_TOO_LARGE:    'PAYLOAD_TOO_LARGE',

  // Auth flow
  INVALID_KEY:          'INVALID_KEY',
  KEY_EXPIRED:          'KEY_EXPIRED',
  KEY_BANNED:           'KEY_BANNED',
  HWID_MISMATCH:        'HWID_MISMATCH',
  INVALID_HWID:         'INVALID_HWID',
  INVALID_APP:          'INVALID_APP',
  INVALID_SIGNATURE:    'INVALID_SIGNATURE',
  STALE_REQUEST:        'STALE_REQUEST',

  // Token
  INVALID_TOKEN:        'INVALID_TOKEN',
  TOKEN_EXPIRED:        'TOKEN_EXPIRED',
  TOKEN_REVOKED:        'TOKEN_REVOKED',

  // Account
  INVALID_CREDENTIALS:  'INVALID_CREDENTIALS',
  ACCOUNT_BANNED:       'ACCOUNT_BANNED',
  ALREADY_BANNED:       'ALREADY_BANNED',
  NOT_BANNED:           'NOT_BANNED',

  // Keys
  INVALID_QUANTITY:     'INVALID_QUANTITY',
  INVALID_EXPIRY:       'INVALID_EXPIRY',
  INVALID_VALUE:        'INVALID_VALUE',
  ALREADY_BANNED_KEY:   'ALREADY_BANNED',
  NOT_BANNED_KEY:       'NOT_BANNED',
  NO_HWID_BOUND:        'NO_HWID_BOUND',
  HWID_ALREADY_BOUND:   'HWID_ALREADY_BOUND',
});

// ─── Exports ──────────────────────────────────────────────────────────────────

module.exports = {
  ok,
  fail,
  validationFail,
  paginated,
  signResponse,
  verifySignedResponse,
  HTTP,
  CODES,
};
