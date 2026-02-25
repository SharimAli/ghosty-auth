'use strict';

/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║               GHOSTY Auth — tokenService.js                 ║
 * ║    Session token issuance, verification, and blacklisting   ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * Tokens:
 *   - Algorithm:  RS256  (asymmetric — public key can be shared safely)
 *   - Issuer:     'ghosty-auth'
 *   - TTL:        Configurable via JWT_EXPIRES_IN (default: 1h)
 *
 * Blacklist:
 *   - Logged-out tokens are stored in Redis with TTL = token's remaining lifetime
 *   - Checked in authMiddleware.requireAuth before every protected request
 *   - Key format: bl:{sha256(token)}  (hashed to keep Redis keys short)
 *
 * Exports:
 *   signToken(payload)              → { token, expiresAt }
 *   verifyToken(token)              → decoded payload
 *   decodeTokenUnsafe(token)        → decoded payload (no signature check)
 *   blacklistToken(token, expUnix)  → void
 *   isTokenBlacklisted(token)       → boolean
 *   getTokenTTL(token)              → seconds remaining
 *   revokeAllUserTokens(userId)     → void  (marks a user-level revocation)
 *   isUserRevoked(userId)           → boolean
 */

const jwt    = require('jsonwebtoken');
const crypto = require('crypto');
const redis  = require('../config/redis');
const logger = require('../utils/logger');

// ─── Constants ────────────────────────────────────────────────────────────────

const ISSUER            = 'ghosty-auth';
const ALGORITHM         = 'RS256';
const BLACKLIST_PREFIX  = 'bl:';
const REVOKE_PREFIX     = 'rv:';
const DEFAULT_EXPIRES   = '1h';

// ─── Key Loading ──────────────────────────────────────────────────────────────

/**
 * Load RSA keys from environment.
 * Keys are stored as newline-escaped strings in .env:
 *   JWT_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
 *   JWT_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
 */
function _loadPrivateKey() {
  const raw = process.env.JWT_PRIVATE_KEY;
  if (!raw) throw new Error('[tokenService] JWT_PRIVATE_KEY is not set in environment.');
  // Replace literal \n with actual newlines (env var storage format)
  return raw.replace(/\\n/g, '\n');
}

function _loadPublicKey() {
  const raw = process.env.JWT_PUBLIC_KEY;
  if (!raw) throw new Error('[tokenService] JWT_PUBLIC_KEY is not set in environment.');
  return raw.replace(/\\n/g, '\n');
}

// Cache keys in memory — they don't change between requests
let _privateKey = null;
let _publicKey  = null;

function getPrivateKey() {
  if (!_privateKey) _privateKey = _loadPrivateKey();
  return _privateKey;
}

function getPublicKey() {
  if (!_publicKey) _publicKey = _loadPublicKey();
  return _publicKey;
}

// ─── TTL Helper ───────────────────────────────────────────────────────────────

/**
 * Converts a JWT expiry string like '1h', '30m', '7d' into seconds.
 *
 * @param {string} expiresIn
 * @returns {number}  seconds
 */
function _expiresInToSeconds(expiresIn) {
  const units = { s: 1, m: 60, h: 3600, d: 86400 };
  const match = String(expiresIn).match(/^(\d+)([smhd])$/i);
  if (!match) throw new Error(`[tokenService] Invalid JWT_EXPIRES_IN format: "${expiresIn}"`);
  return parseInt(match[1], 10) * units[match[2].toLowerCase()];
}

// ─────────────────────────────────────────────────────────────────────────────
//  signToken
//  Issues a signed RS256 JWT for a session.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Signs and issues a new JWT session token.
 *
 * @param {object} payload
 * @param {string} payload.user_id     — seller/admin UUID
 * @param {string} payload.username
 * @param {string} payload.role        — 'seller' | 'admin'
 *
 * @param {object} [options]
 * @param {string} [options.expiresIn] — override default TTL (e.g. '2h')
 *
 * @returns {{ token: string, expiresAt: number }}
 *   expiresAt is Unix ms timestamp (compatible with Date constructor)
 */
function signToken(payload, options = {}) {
  _validatePayload(payload);

  const expiresIn = options.expiresIn || process.env.JWT_EXPIRES_IN || DEFAULT_EXPIRES;
  const ttlSecs   = _expiresInToSeconds(expiresIn);

  const jwtPayload = {
    user_id:  payload.user_id,
    username: payload.username,
    role:     payload.role,
    // Sub for standards compliance
    sub:      payload.user_id,
  };

  const token = jwt.sign(jwtPayload, getPrivateKey(), {
    algorithm: ALGORITHM,
    issuer:    ISSUER,
    expiresIn: ttlSecs,
  });

  const expiresAt = Date.now() + ttlSecs * 1000;

  logger.debug(`[tokenService] issued token — user=${payload.user_id} ttl=${ttlSecs}s`);

  return { token, expiresAt };
}

// ─────────────────────────────────────────────────────────────────────────────
//  verifyToken
//  Verifies signature and expiry. Throws on any failure.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Verifies a JWT and returns its decoded payload.
 * Throws jsonwebtoken errors on invalid/expired tokens — callers must catch.
 *
 * Error names to catch:
 *   JsonWebTokenError  — invalid signature, malformed
 *   TokenExpiredError  — past expiry
 *   NotBeforeError     — not yet valid
 *
 * @param {string} token
 * @returns {object}  decoded payload (includes iat, exp, iss, sub)
 */
function verifyToken(token) {
  if (!token || typeof token !== 'string') {
    throw new jwt.JsonWebTokenError('Token must be a non-empty string.');
  }

  return jwt.verify(token, getPublicKey(), {
    algorithms: [ALGORITHM],
    issuer:     ISSUER,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
//  decodeTokenUnsafe
//  Decodes WITHOUT verifying signature — use only for non-security purposes.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Decodes a JWT without verifying its signature.
 * ⚠ NEVER use this to make auth decisions.
 * Safe uses: extracting user_id from an expired token for logging.
 *
 * @param {string} token
 * @returns {object|null}  decoded payload or null
 */
function decodeTokenUnsafe(token) {
  try {
    return jwt.decode(token);
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  getTokenTTL
//  Returns seconds remaining until the token expires.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @param {string} token
 * @returns {number}  seconds remaining (0 if expired)
 */
function getTokenTTL(token) {
  const decoded = decodeTokenUnsafe(token);
  if (!decoded || !decoded.exp) return 0;
  return Math.max(0, Math.floor(decoded.exp - Date.now() / 1000));
}

// ─────────────────────────────────────────────────────────────────────────────
//  Token Blacklist
//  Invalidates specific tokens (logout / revocation).
//  Keys expire automatically from Redis once the token's TTL runs out.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Adds a token to the blacklist.
 * The Redis key expires when the token itself would have expired,
 * so the blacklist self-cleans over time.
 *
 * @param {string}        token       — the raw JWT string
 * @param {number|null}   expUnix     — Unix seconds (token's exp claim), or null to decode it
 */
async function blacklistToken(token, expUnix = null) {
  try {
    const client = redis.getClient();

    // Use a hash of the token as the Redis key — keeps keys short
    // and avoids storing JWTs in Redis key names
    const tokenHash = _hashToken(token);
    const redisKey  = `${BLACKLIST_PREFIX}${tokenHash}`;

    // Determine TTL
    let ttlSecs;
    if (expUnix) {
      ttlSecs = Math.max(1, Math.floor(expUnix - Date.now() / 1000));
    } else {
      ttlSecs = getTokenTTL(token);
    }

    if (ttlSecs <= 0) {
      // Already expired — no need to blacklist
      return;
    }

    await client.set(redisKey, '1', { EX: ttlSecs });

    logger.info(`[tokenService] blacklisted token hash=${tokenHash.slice(0, 12)}... ttl=${ttlSecs}s`);

  } catch (err) {
    // Non-fatal — log and continue
    logger.error(`[tokenService] blacklistToken failed — ${err.message}`);
  }
}

/**
 * Returns true if a token has been blacklisted (logged out).
 *
 * @param {string} token
 * @returns {Promise<boolean>}
 */
async function isTokenBlacklisted(token) {
  try {
    const client    = redis.getClient();
    const tokenHash = _hashToken(token);
    const redisKey  = `${BLACKLIST_PREFIX}${tokenHash}`;
    const value     = await client.get(redisKey);
    return value !== null;
  } catch (err) {
    logger.error(`[tokenService] isTokenBlacklisted error — ${err.message}`);
    // Fail safe: if Redis is down, don't block all requests
    return false;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  User-level Revocation
//  Revokes ALL tokens for a user (e.g. on ban or password change).
//  Every token check verifies this flag — more aggressive than per-token blacklist.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Marks all tokens for a user as revoked.
 * Stores a revocation timestamp in Redis — any token issued BEFORE
 * this timestamp is considered revoked.
 *
 * @param {string} userId
 * @param {number} [ttlSecs=86400]  — how long to keep the revocation marker (default 24h)
 */
async function revokeAllUserTokens(userId, ttlSecs = 86400) {
  try {
    const client   = redis.getClient();
    const redisKey = `${REVOKE_PREFIX}${userId}`;
    const revokedAt = Math.floor(Date.now() / 1000);

    await client.set(redisKey, String(revokedAt), { EX: ttlSecs });

    logger.info(`[tokenService] revoked all tokens — user=${userId} at=${revokedAt}`);
  } catch (err) {
    logger.error(`[tokenService] revokeAllUserTokens error — ${err.message}`);
  }
}

/**
 * Returns true if a token was issued before the user's revocation timestamp.
 *
 * @param {string} userId
 * @param {number} tokenIat  — token's iat (issued-at) Unix timestamp in seconds
 * @returns {Promise<boolean>}
 */
async function isUserRevoked(userId, tokenIat) {
  try {
    const client   = redis.getClient();
    const redisKey = `${REVOKE_PREFIX}${userId}`;
    const value    = await client.get(redisKey);

    if (!value) return false;

    const revokedAt = parseInt(value, 10);
    // Token is revoked if it was issued BEFORE the revocation event
    return tokenIat < revokedAt;
  } catch (err) {
    logger.error(`[tokenService] isUserRevoked error — ${err.message}`);
    return false;
  }
}

/**
 * Clears the user-level revocation marker.
 * Call this after a user re-authenticates following a password reset.
 *
 * @param {string} userId
 */
async function clearUserRevocation(userId) {
  try {
    const client   = redis.getClient();
    const redisKey = `${REVOKE_PREFIX}${userId}`;
    await client.del(redisKey);
    logger.info(`[tokenService] cleared revocation — user=${userId}`);
  } catch (err) {
    logger.error(`[tokenService] clearUserRevocation error — ${err.message}`);
  }
}

// ─── Internal Helpers ─────────────────────────────────────────────────────────

/**
 * Hashes a token for use as a Redis key.
 * SHA-256 of the raw token string → 64-char hex.
 * This keeps Redis keys short and avoids storing JWTs in key names.
 */
function _hashToken(token) {
  return crypto.createHash('sha256').update(token, 'utf8').digest('hex');
}

/**
 * Validates the token payload before signing.
 */
function _validatePayload(payload) {
  if (!payload || typeof payload !== 'object') {
    throw new TypeError('[tokenService] payload must be an object.');
  }

  const required = ['user_id', 'username', 'role'];
  for (const field of required) {
    if (!payload[field] || typeof payload[field] !== 'string') {
      throw new TypeError(`[tokenService] payload.${field} must be a non-empty string.`);
    }
  }

  const validRoles = ['seller', 'admin'];
  if (!validRoles.includes(payload.role)) {
    throw new RangeError(`[tokenService] Invalid role: "${payload.role}". Must be one of: ${validRoles.join(', ')}`);
  }
}

// ─── Exports ──────────────────────────────────────────────────────────────────

module.exports = {
  signToken,
  verifyToken,
  decodeTokenUnsafe,
  getTokenTTL,
  blacklistToken,
  isTokenBlacklisted,
  revokeAllUserTokens,
  isUserRevoked,
  clearUserRevocation,
};
