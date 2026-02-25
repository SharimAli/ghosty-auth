'use strict';

/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║             GHOSTY Auth — rateLimiter.js                    ║
 * ║   Redis-backed sliding window rate limiter middleware        ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * Provides multiple rate limiter presets:
 *
 *   rateLimiter.auth       → /auth/init          (10 req / 60s / IP)
 *   rateLimiter.validate   → /auth/validate       (60 req / 60s / token)
 *   rateLimiter.keys       → /keys/*              (30 req / 60s / seller)
 *   rateLimiter.general    → everything else      (100 req / 60s / IP)
 *   rateLimiter.login      → /users/login         (10 req / 15min / IP)  ← brute-force guard
 *   rateLimiter.register   → /users/register      (5 req / 60min / IP)
 *
 * Algorithm: sliding window counter using Redis INCR + EXPIRE.
 * Falls back gracefully if Redis is unavailable (allows request, logs warning).
 */

const redis  = require('../config/redis');
const logger = require('../utils/logger');
const { fail } = require('../utils/response');

// ─── Constants ────────────────────────────────────────────────────────────────

const REDIS_KEY_PREFIX = 'rl:';

// ─── Core Factory ─────────────────────────────────────────────────────────────

/**
 * Creates a rate limiter middleware.
 *
 * @param {object} options
 * @param {number}   options.max          Max requests allowed in the window
 * @param {number}   options.windowSec    Window size in seconds
 * @param {string}   options.keyPrefix    Redis key prefix to namespace this limiter
 * @param {Function} options.keyFn        (req) => string  — extracts the identity to rate-limit by
 * @param {string}   [options.errorCode]  Error code returned when limited
 * @param {string}   [options.errorMsg]   Human-readable message when limited
 */
function createLimiter({
  max,
  windowSec,
  keyPrefix,
  keyFn,
  errorCode = 'RATE_LIMITED',
  errorMsg  = 'Too many requests. Please slow down.',
}) {
  return async function rateLimitMiddleware(req, res, next) {
    let identity;

    try {
      identity = keyFn(req);
    } catch {
      // If we can't derive an identity, let the request through
      // (e.g. keyFn tries to read req.user before auth runs)
      return next();
    }

    if (!identity) return next();

    const redisKey = `${REDIS_KEY_PREFIX}${keyPrefix}:${identity}`;

    try {
      const client = redis.getClient();

      // Atomic increment
      const current = await client.incr(redisKey);

      // Set expiry only on the first request in this window
      if (current === 1) {
        await client.expire(redisKey, windowSec);
      }

      // Get the actual TTL for the header
      const ttl = await client.ttl(redisKey);

      // ── Set rate-limit headers ─────────────────────────────────────────
      res.set({
        'X-RateLimit-Limit':     String(max),
        'X-RateLimit-Remaining': String(Math.max(0, max - current)),
        'X-RateLimit-Reset':     String(Math.floor(Date.now() / 1000) + ttl),
      });

      if (current > max) {
        res.set('Retry-After', String(ttl));

        logger.warn(
          `[RATE_LIMIT] blocked — key=${redisKey} count=${current}/${max} ttl=${ttl}s ip=${
            req.ip || req.connection?.remoteAddress
          }`
        );

        return res.status(429).json(fail(errorCode, errorMsg));
      }

      return next();

    } catch (redisErr) {
      // Redis is down — fail open (allow request) but log loudly
      logger.error(`[RATE_LIMIT] Redis error — falling back to allow. ${redisErr.message}`);
      return next();
    }
  };
}

// ─── Key Extractors ───────────────────────────────────────────────────────────

/** Rate-limit by client IP address. */
function byIP(req) {
  return (
    req.ip ||
    req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    req.connection?.remoteAddress ||
    'unknown'
  );
}

/** Rate-limit by authenticated seller ID (falls back to IP). */
function byUser(req) {
  return req.user?.id ? `user:${req.user.id}` : byIP(req);
}

/**
 * Rate-limit by the session token in the request body.
 * Used for /auth/validate so each token has its own bucket.
 */
function byToken(req) {
  const token = req.body?.token;
  if (!token || typeof token !== 'string') return byIP(req);
  // Use only the last 16 chars of token as the bucket key (don't store full JWT in Redis keys)
  return `tok:${token.slice(-16)}`;
}

// ─── Exported Limiter Presets ─────────────────────────────────────────────────

/**
 * /auth/init — strict limit to prevent license key brute-forcing.
 * 10 requests per 60 seconds per IP.
 */
exports.auth = createLimiter({
  max:       parseInt(process.env.RATE_LIMIT_MAX_AUTH || '10', 10),
  windowSec: 60,
  keyPrefix: 'auth_init',
  keyFn:     byIP,
  errorCode: 'RATE_LIMITED',
  errorMsg:  'Too many authentication attempts. Please wait before trying again.',
});

/**
 * /auth/validate — more lenient, per session token.
 * 60 requests per 60 seconds per token.
 */
exports.validate = createLimiter({
  max:       60,
  windowSec: 60,
  keyPrefix: 'auth_validate',
  keyFn:     byToken,
  errorCode: 'RATE_LIMITED',
  errorMsg:  'Validation rate limit exceeded.',
});

/**
 * /users/login — brute-force protection.
 * 10 attempts per 15 minutes per IP.
 */
exports.login = createLimiter({
  max:       10,
  windowSec: 15 * 60,
  keyPrefix: 'user_login',
  keyFn:     byIP,
  errorCode: 'RATE_LIMITED',
  errorMsg:  'Too many login attempts. Please wait 15 minutes before trying again.',
});

/**
 * /users/register — prevent mass account creation.
 * 5 requests per 60 minutes per IP.
 */
exports.register = createLimiter({
  max:       5,
  windowSec: 60 * 60,
  keyPrefix: 'user_register',
  keyFn:     byIP,
  errorCode: 'RATE_LIMITED',
  errorMsg:  'Too many registration attempts. Please try again later.',
});

/**
 * /keys/* — per authenticated seller.
 * 30 requests per 60 seconds.
 */
exports.keys = createLimiter({
  max:       parseInt(process.env.RATE_LIMIT_MAX_KEYS || '30', 10),
  windowSec: 60,
  keyPrefix: 'keys',
  keyFn:     byUser,
  errorCode: 'RATE_LIMITED',
  errorMsg:  'Key management rate limit exceeded.',
});

/**
 * General — applied to all other routes.
 * 100 requests per 60 seconds per IP.
 */
exports.general = createLimiter({
  max:       parseInt(process.env.RATE_LIMIT_MAX_GENERAL || '100', 10),
  windowSec: 60,
  keyPrefix: 'general',
  keyFn:     byIP,
  errorCode: 'RATE_LIMITED',
  errorMsg:  'Rate limit exceeded. Please slow down.',
});

/**
 * Admin endpoints — tighter limit for admin actions.
 * 60 requests per 60 seconds per admin user.
 */
exports.admin = createLimiter({
  max:       60,
  windowSec: 60,
  keyPrefix: 'admin',
  keyFn:     byUser,
  errorCode: 'RATE_LIMITED',
  errorMsg:  'Admin rate limit exceeded.',
});

// ─── Utility: Manual reset (for testing / admin tools) ───────────────────────

/**
 * Manually clears a rate limit bucket for a given key.
 * Useful for admin unlocking a banned IP.
 *
 * @param {string} keyPrefix   e.g. 'auth_init'
 * @param {string} identity    e.g. '1.2.3.4'
 */
exports.resetBucket = async (keyPrefix, identity) => {
  try {
    const client   = redis.getClient();
    const redisKey = `${REDIS_KEY_PREFIX}${keyPrefix}:${identity}`;
    await client.del(redisKey);
    logger.info(`[RATE_LIMIT] manually reset bucket — ${redisKey}`);
    return true;
  } catch (err) {
    logger.error(`[RATE_LIMIT] resetBucket error — ${err.message}`);
    return false;
  }
};

/**
 * Returns current count for a bucket (for admin dashboards).
 *
 * @param {string} keyPrefix
 * @param {string} identity
 * @returns {{ count: number, ttl: number } | null}
 */
exports.getBucketInfo = async (keyPrefix, identity) => {
  try {
    const client   = redis.getClient();
    const redisKey = `${REDIS_KEY_PREFIX}${keyPrefix}:${identity}`;
    const [count, ttl] = await Promise.all([
      client.get(redisKey),
      client.ttl(redisKey),
    ]);
    return { count: parseInt(count || '0', 10), ttl: Math.max(0, ttl) };
  } catch {
    return null;
  }
};
