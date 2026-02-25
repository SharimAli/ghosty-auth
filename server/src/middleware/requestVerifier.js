'use strict';

/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║           GHOSTY Auth — requestVerifier.js                  ║
 * ║     HMAC request signature + timestamp freshness checks     ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * This middleware is applied to the /auth/* routes.
 *
 * Every inbound auth request must carry:
 *   - timestamp         Unix ms timestamp (prevents replay attacks)
 *   - request_signature HMAC-SHA256(app_secret, app_id:license_key:hwid:timestamp)
 *
 * The middleware:
 *   1. Validates all required fields are present
 *   2. Checks timestamp freshness (within ±TOLERANCE window)
 *   3. Loads the Application by app_id to get its secret
 *   4. Recomputes the expected HMAC
 *   5. Compares using crypto.timingSafeEqual (prevents timing attacks)
 *   6. Rejects with 403 if invalid — no details given to caller
 *
 * The loaded application object is attached to req.app_record so
 * controllers don't need to re-query it.
 */

const crypto      = require('crypto');
const Application = require('../models/Application');
const Log         = require('../models/Log');
const { fail }    = require('../utils/response');
const logger      = require('../utils/logger');

// ─── Constants ────────────────────────────────────────────────────────────────

const TOLERANCE_MS = parseInt(
  process.env.REQUEST_TIMESTAMP_TOLERANCE_MS || '30000',
  10
);

// Minimum expected length of a valid hex HMAC-SHA256 (64 chars)
const HMAC_HEX_LENGTH = 64;

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Returns true if the timestamp is within ±TOLERANCE_MS of now.
 */
function isTimestampFresh(timestamp) {
  const ts   = Number(timestamp);
  if (!Number.isFinite(ts) || ts <= 0) return false;
  return Math.abs(Date.now() - ts) <= TOLERANCE_MS;
}

/**
 * Returns true if the string looks like a valid 64-char lowercase hex string.
 * Prevents waste processing obviously malformed signatures.
 */
function isValidHexString(str) {
  return typeof str === 'string' &&
         str.length === HMAC_HEX_LENGTH &&
         /^[0-9a-f]+$/.test(str);
}

/**
 * Computes the expected request signature.
 * HMAC-SHA256(app_secret, app_id:license_key:hwid:timestamp)
 */
function computeExpectedSignature({ secret, appId, licenseKey, hwid, timestamp }) {
  const message = `${appId}:${licenseKey}:${hwid}:${timestamp}`;
  return crypto
    .createHmac('sha256', secret)
    .update(message)
    .digest('hex');
}

/**
 * Constant-time hex string comparison.
 * Returns false on any error (length mismatch, invalid hex, etc.)
 */
function safeCompare(a, b) {
  try {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(
      Buffer.from(a, 'hex'),
      Buffer.from(b, 'hex')
    );
  } catch {
    return false;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  verifyAuthRequest
//  Middleware for POST /auth/init
//  Requires: license_key, hwid, app_id, timestamp, request_signature
// ─────────────────────────────────────────────────────────────────────────────

exports.verifyAuthRequest = async (req, res, next) => {
  const ip = req.ip || req.connection?.remoteAddress || 'unknown';

  const {
    license_key,
    hwid,
    app_id,
    timestamp,
    request_signature,
  } = req.body;

  // ── 1. Presence check ────────────────────────────────────────────────────
  if (!license_key || !hwid || !app_id || !timestamp || !request_signature) {
    return res.status(400).json(
      fail('MISSING_FIELDS', 'license_key, hwid, app_id, timestamp, and request_signature are all required.')
    );
  }

  // ── 2. Type checks ────────────────────────────────────────────────────────
  if (
    typeof license_key !== 'string' ||
    typeof hwid        !== 'string' ||
    typeof app_id      !== 'string'
  ) {
    return res.status(400).json(fail('INVALID_INPUT', 'Fields must be strings.'));
  }

  // ── 3. Signature format check ─────────────────────────────────────────────
  if (!isValidHexString(request_signature)) {
    logger.warn(`[VERIFIER] malformed signature — ip=${ip} app=${app_id}`);
    return res.status(403).json(fail('INVALID_SIGNATURE', 'Request signature is malformed.'));
  }

  // ── 4. Timestamp freshness ────────────────────────────────────────────────
  if (!isTimestampFresh(timestamp)) {
    logger.warn(
      `[VERIFIER] stale timestamp — ip=${ip} app=${app_id} ts=${timestamp} now=${Date.now()}`
    );
    await _logFailure(req, 'STALE_TIMESTAMP', ip, app_id, license_key);
    return res.status(400).json(
      fail('STALE_REQUEST', `Request timestamp is outside the ±${TOLERANCE_MS / 1000}s tolerance window.`)
    );
  }

  // ── 5. Load application ───────────────────────────────────────────────────
  let app;
  try {
    app = await Application.findOne({
      where:      { id: app_id },
      attributes: ['id', 'secret', 'is_active', 'owner_id', 'name'],
    });
  } catch (dbErr) {
    logger.error(`[VERIFIER] DB error loading app — ${dbErr.message}`);
    return res.status(500).json(fail('SERVER_ERROR', 'An internal error occurred.'));
  }

  if (!app) {
    // Don't reveal whether the app exists — return 403 same as bad sig
    logger.warn(`[VERIFIER] unknown app_id — ip=${ip} app=${app_id}`);
    return res.status(403).json(fail('INVALID_SIGNATURE', 'Request verification failed.'));
  }

  if (!app.is_active) {
    logger.warn(`[VERIFIER] inactive app — ip=${ip} app=${app_id}`);
    return res.status(401).json(fail('INVALID_APP', 'This application is currently inactive.'));
  }

  // ── 6. Compute & verify HMAC ──────────────────────────────────────────────
  const expected = computeExpectedSignature({
    secret:     app.secret,
    appId:      app_id,
    licenseKey: license_key.toUpperCase().trim(),
    hwid,
    timestamp,
  });

  if (!safeCompare(expected, request_signature)) {
    logger.warn(`[VERIFIER] signature mismatch — ip=${ip} app=${app_id}`);
    await _logFailure(req, 'INVALID_SIGNATURE', ip, app_id, license_key);
    return res.status(403).json(fail('INVALID_SIGNATURE', 'Request verification failed.'));
  }

  // ── 7. Attach app record and pass through ─────────────────────────────────
  // Controllers can use req.app_record instead of re-querying
  req.app_record = app;

  logger.debug(`[VERIFIER] passed — app=${app_id} ip=${ip}`);
  return next();
};

// ─────────────────────────────────────────────────────────────────────────────
//  verifyValidateRequest
//  Lighter middleware for POST /auth/validate and POST /auth/logout
//  These only need: token, hwid, app_id (no license_key, no HMAC)
//  The JWT itself is the credential — validated in authMiddleware.
// ─────────────────────────────────────────────────────────────────────────────

exports.verifyValidateRequest = (req, res, next) => {
  const { token, hwid, app_id } = req.body;

  if (!token || !hwid || !app_id) {
    return res.status(400).json(
      fail('MISSING_FIELDS', 'token, hwid, and app_id are required.')
    );
  }

  if (
    typeof token  !== 'string' ||
    typeof hwid   !== 'string' ||
    typeof app_id !== 'string'
  ) {
    return res.status(400).json(fail('INVALID_INPUT', 'Fields must be strings.'));
  }

  // Basic token format check — JWT is 3 base64url segments separated by dots
  const jwtParts = token.split('.');
  if (jwtParts.length !== 3) {
    return res.status(400).json(fail('INVALID_TOKEN', 'Malformed session token.'));
  }

  return next();
};

// ─────────────────────────────────────────────────────────────────────────────
//  verifyContentType
//  Ensures all requests send JSON. Rejects form data, plain text, etc.
// ─────────────────────────────────────────────────────────────────────────────

exports.verifyContentType = (req, res, next) => {
  // Only enforce on methods that carry a body
  if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
    const contentType = req.headers['content-type'] || '';
    if (!contentType.includes('application/json')) {
      return res.status(415).json(
        fail('UNSUPPORTED_MEDIA_TYPE', 'Content-Type must be application/json.')
      );
    }
  }
  return next();
};

// ─────────────────────────────────────────────────────────────────────────────
//  verifyBodySize
//  Guards against oversized request bodies (beyond what express.json handles).
//  An extra explicit check here for auth routes.
// ─────────────────────────────────────────────────────────────────────────────

exports.verifyBodySize = (maxBytes = 4096) => {
  return (req, res, next) => {
    const contentLength = parseInt(req.headers['content-length'] || '0', 10);
    if (contentLength > maxBytes) {
      return res.status(413).json(
        fail('PAYLOAD_TOO_LARGE', `Request body must not exceed ${maxBytes} bytes.`)
      );
    }
    return next();
  };
};

// ─────────────────────────────────────────────────────────────────────────────
//  Internal: log verification failures
// ─────────────────────────────────────────────────────────────────────────────

async function _logFailure(req, reason, ip, appId, licenseKey) {
  try {
    await Log.create({
      action:      'AUTH_VERIFY',
      status:      'failed',
      reason,
      ip,
      app_id:      appId || null,
      license_key: licenseKey || null,
    });
  } catch (err) {
    // Non-fatal — don't let a log failure break the response
    logger.error(`[VERIFIER] failed to write log — ${err.message}`);
  }
}
