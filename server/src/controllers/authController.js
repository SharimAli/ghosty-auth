'use strict';

/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║              GHOSTY Auth — authController.js                ║
 * ║         Handles /auth/init  /auth/validate  /auth/logout    ║
 * ╚══════════════════════════════════════════════════════════════╝
 */

const crypto      = require('crypto');
const License     = require('../models/License');
const Log         = require('../models/Log');
const Application = require('../models/Application');
const { signToken, verifyToken } = require('../services/tokenService');
const { signResponse }           = require('../services/cryptoService');
const { validateHWID }           = require('../services/hwidService');
const { ok, fail }               = require('../utils/response');
const logger                     = require('../utils/logger');

// ─── Constants ───────────────────────────────────────────────────────────────

// Max age of a request timestamp before we reject it (30 seconds)
const REQUEST_TIMESTAMP_TOLERANCE_MS = parseInt(process.env.REQUEST_TIMESTAMP_TOLERANCE_MS || '30000', 10);

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Verifies that the client's request_signature is valid.
 * Prevents forged / replayed requests.
 *
 * Signature = HMAC-SHA256(app_secret, app_id:license_key:hwid:timestamp)
 */
function verifyRequestSignature({ appSecret, appId, licenseKey, hwid, timestamp, providedSig }) {
  const message  = `${appId}:${licenseKey}:${hwid}:${timestamp}`;
  const expected = crypto
    .createHmac('sha256', appSecret)
    .update(message)
    .digest('hex');

  // Constant-time comparison to prevent timing attacks
  try {
    return crypto.timingSafeEqual(
      Buffer.from(expected, 'hex'),
      Buffer.from(providedSig, 'hex')
    );
  } catch {
    return false;
  }
}

/**
 * Checks that the request timestamp is within the allowed tolerance window.
 * Prevents replay attacks.
 */
function isTimestampFresh(timestamp) {
  const now  = Date.now();
  const diff = Math.abs(now - Number(timestamp));
  return diff <= REQUEST_TIMESTAMP_TOLERANCE_MS;
}

/**
 * Masks an email for safe display: j***@example.com
 */
function maskEmail(email) {
  if (!email || !email.includes('@')) return '';
  const [local, domain] = email.split('@');
  return `${local[0]}***@${domain}`;
}

// ─────────────────────────────────────────────────────────────────────────────
//  POST /auth/init
//  Validate license key, bind HWID on first use, issue session token.
// ─────────────────────────────────────────────────────────────────────────────

exports.init = async (req, res) => {
  const ip = req.ip || req.connection.remoteAddress;

  const {
    license_key,
    hwid,
    app_id,
    timestamp,
    request_signature,
  } = req.body;

  // ── 1. Input validation ───────────────────────────────────────────────────
  if (!license_key || !hwid || !app_id || !timestamp || !request_signature) {
    await Log.create({
      action:    'AUTH_INIT',
      status:    'failed',
      reason:    'MISSING_FIELDS',
      ip,
      app_id:    app_id || null,
      license_key: license_key || null,
    });
    return res.status(400).json(fail('MISSING_FIELDS', 'Required fields are missing.'));
  }

  // ── 2. Timestamp freshness check (replay attack prevention) ──────────────
  if (!isTimestampFresh(timestamp)) {
    await Log.create({
      action:  'AUTH_INIT',
      status:  'failed',
      reason:  'STALE_REQUEST',
      ip,
      app_id,
      license_key,
    });
    return res.status(400).json(fail('STALE_REQUEST', 'Request timestamp is too old or too far in the future.'));
  }

  // ── 3. HWID format validation ─────────────────────────────────────────────
  if (!validateHWID(hwid)) {
    await Log.create({
      action:  'AUTH_INIT',
      status:  'failed',
      reason:  'INVALID_HWID',
      ip,
      app_id,
      license_key,
    });
    return res.status(400).json(fail('INVALID_HWID', 'Invalid hardware ID format.'));
  }

  try {
    // ── 4. Load the application ───────────────────────────────────────────
    const app = await Application.findByPk(app_id);
    if (!app || !app.is_active) {
      return res.status(401).json(fail('INVALID_APP', 'Application not found or inactive.'));
    }

    // ── 5. Verify request signature using app secret ──────────────────────
    const sigValid = verifyRequestSignature({
      appSecret:   app.secret,
      appId:       app_id,
      licenseKey:  license_key.toUpperCase(),
      hwid,
      timestamp,
      providedSig: request_signature,
    });

    if (!sigValid) {
      await Log.create({
        action:      'AUTH_INIT',
        status:      'failed',
        reason:      'INVALID_SIGNATURE',
        ip,
        app_id,
        license_key,
      });
      return res.status(403).json(fail('INVALID_SIGNATURE', 'Request signature verification failed.'));
    }

    // ── 6. Load the license key ───────────────────────────────────────────
    const license = await License.findOne({
      where: {
        key:    license_key.toUpperCase(),
        app_id,
      },
    });

    if (!license) {
      await Log.create({
        action:      'AUTH_INIT',
        status:      'failed',
        reason:      'INVALID_KEY',
        ip,
        app_id,
        license_key,
      });
      return res.status(401).json(fail('INVALID_KEY', 'License key does not exist.'));
    }

    // ── 7. Check if key is banned ─────────────────────────────────────────
    if (license.is_banned) {
      await Log.create({
        action:      'AUTH_INIT',
        status:      'failed',
        reason:      'KEY_BANNED',
        ip,
        app_id,
        license_id:  license.id,
        license_key,
      });
      return res.status(401).json(fail('KEY_BANNED', 'This license key has been banned.'));
    }

    // ── 8. Check expiry ───────────────────────────────────────────────────
    if (license.expires_at && new Date(license.expires_at) < new Date()) {
      await Log.create({
        action:      'AUTH_INIT',
        status:      'failed',
        reason:      'KEY_EXPIRED',
        ip,
        app_id,
        license_id:  license.id,
        license_key,
      });
      return res.status(401).json(fail('KEY_EXPIRED', 'This license key has expired.'));
    }

    // ── 9. HWID binding ───────────────────────────────────────────────────
    let hwidLocked = false;

    if (!license.hwid) {
      // First use — bind HWID
      await license.update({ hwid, first_used_at: new Date() });
    } else {
      // Existing binding — verify match (constant-time)
      hwidLocked = true;
      const hwidMatch = crypto.timingSafeEqual(
        Buffer.from(license.hwid),
        Buffer.from(hwid)
      );
      if (!hwidMatch) {
        await Log.create({
          action:      'AUTH_INIT',
          status:      'failed',
          reason:      'HWID_MISMATCH',
          ip,
          app_id,
          license_id:  license.id,
          license_key,
          hwid,
        });
        return res.status(401).json(fail('HWID_MISMATCH', 'Hardware ID does not match the bound device.'));
      }
    }

    // ── 10. Update last_used_at ───────────────────────────────────────────
    await license.update({ last_used_at: new Date(), last_used_ip: ip });

    // ── 11. Issue session token ───────────────────────────────────────────
    const tokenPayload = {
      license_id: license.id,
      app_id,
      hwid,
      username:   license.username || '',
    };

    const { token, expiresAt } = await signToken(tokenPayload);

    // ── 12. Log success ───────────────────────────────────────────────────
    await Log.create({
      action:      'AUTH_INIT',
      status:      'success',
      ip,
      app_id,
      license_id:  license.id,
      license_key,
      hwid,
    });

    logger.info(`[AUTH] init success — key=${license_key} app=${app_id} ip=${ip}`);

    // ── 13. Build signed response ─────────────────────────────────────────
    const data = {
      token,
      token_expires: expiresAt,
      username:      license.username   || '',
      email:         maskEmail(license.email),
      expires_at:    license.expires_at ? license.expires_at.toISOString() : null,
      hwid_locked:   hwidLocked,
    };

    return res.status(200).json(signResponse(true, 'Authentication successful.', data, app.secret));

  } catch (err) {
    logger.error(`[AUTH] init error — ${err.message}`, { stack: err.stack });
    return res.status(500).json(fail('SERVER_ERROR', 'An internal error occurred.'));
  }
};

// ─────────────────────────────────────────────────────────────────────────────
//  POST /auth/validate
//  Validate an existing session token.
// ─────────────────────────────────────────────────────────────────────────────

exports.validate = async (req, res) => {
  const ip = req.ip || req.connection.remoteAddress;
  const { token, hwid, app_id } = req.body;

  // ── 1. Input validation ───────────────────────────────────────────────────
  if (!token || !hwid || !app_id) {
    return res.status(400).json(fail('MISSING_FIELDS', 'token, hwid, and app_id are required.'));
  }

  try {
    // ── 2. Load the application ───────────────────────────────────────────
    const app = await Application.findByPk(app_id);
    if (!app || !app.is_active) {
      return res.status(401).json(fail('INVALID_APP', 'Application not found or inactive.'));
    }

    // ── 3. Verify JWT ─────────────────────────────────────────────────────
    let decoded;
    try {
      decoded = verifyToken(token);
    } catch {
      return res.status(401).json(fail('INVALID_TOKEN', 'Session token is invalid or expired.'));
    }

    // ── 4. Ensure HWID matches token payload ──────────────────────────────
    if (decoded.app_id !== app_id) {
      return res.status(401).json(fail('INVALID_TOKEN', 'Token does not belong to this application.'));
    }

    let hwidMatch = false;
    try {
      hwidMatch = crypto.timingSafeEqual(
        Buffer.from(decoded.hwid),
        Buffer.from(hwid)
      );
    } catch { /* length mismatch = false */ }

    if (!hwidMatch) {
      await Log.create({
        action:     'AUTH_VALIDATE',
        status:     'failed',
        reason:     'HWID_MISMATCH',
        ip,
        app_id,
        license_id: decoded.license_id,
        hwid,
      });
      return res.status(401).json(fail('HWID_MISMATCH', 'Hardware ID does not match this session.'));
    }

    // ── 5. Load license and check it's still valid ────────────────────────
    const license = await License.findByPk(decoded.license_id);
    if (!license || license.is_banned) {
      return res.status(401).json(fail('KEY_BANNED', 'License is no longer valid.'));
    }
    if (license.expires_at && new Date(license.expires_at) < new Date()) {
      return res.status(401).json(fail('KEY_EXPIRED', 'License has expired.'));
    }

    // ── 6. Calculate remaining token TTL ──────────────────────────────────
    const expiresIn = Math.max(0, Math.floor((decoded.exp * 1000 - Date.now()) / 1000));

    const data = { valid: true, expires_in: expiresIn };

    logger.info(`[AUTH] validate success — license=${decoded.license_id} ip=${ip}`);

    return res.status(200).json(signResponse(true, 'Session valid.', data, app.secret));

  } catch (err) {
    logger.error(`[AUTH] validate error — ${err.message}`, { stack: err.stack });
    return res.status(500).json(fail('SERVER_ERROR', 'An internal error occurred.'));
  }
};

// ─────────────────────────────────────────────────────────────────────────────
//  POST /auth/logout
//  Invalidate a session token server-side.
// ─────────────────────────────────────────────────────────────────────────────

exports.logout = async (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json(fail('MISSING_FIELDS', 'token is required.'));
  }

  try {
    // Decode without throwing — we still want to blacklist even expired tokens
    let decoded;
    try {
      decoded = verifyToken(token);
    } catch {
      // Token already invalid — that's fine
      return res.status(200).json({ success: true, message: 'Session terminated.' });
    }

    // Blacklist the token in Redis so it cannot be reused even within its TTL
    const { blacklistToken } = require('../services/tokenService');
    await blacklistToken(token, decoded.exp);

    logger.info(`[AUTH] logout — license=${decoded.license_id}`);

    return res.status(200).json({ success: true, message: 'Session terminated.' });

  } catch (err) {
    logger.error(`[AUTH] logout error — ${err.message}`, { stack: err.stack });
    return res.status(500).json(fail('SERVER_ERROR', 'An internal error occurred.'));
  }
};
