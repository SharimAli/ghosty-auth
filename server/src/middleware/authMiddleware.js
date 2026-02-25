'use strict';

/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║             GHOSTY Auth — authMiddleware.js                 ║
 * ║         JWT verification + role-based access control        ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * Exports:
 *
 *   requireAuth          — verifies JWT, attaches req.user, checks blacklist
 *   requireRole(...roles) — role guard (use after requireAuth)
 *   requireAdmin         — shorthand for requireRole('admin')
 *   optionalAuth         — attaches req.user if token present, never rejects
 *
 * JWT payload shape (set by tokenService.signToken):
 * {
 *   user_id:    string  (seller/admin user ID)
 *   username:   string
 *   role:       'seller' | 'admin'
 *   iat:        number
 *   exp:        number
 * }
 *
 * Token blacklist:
 *   Logout calls tokenService.blacklistToken which sets a Redis key.
 *   requireAuth checks that key and rejects blacklisted tokens.
 */

const { verifyToken, isTokenBlacklisted } = require('../services/tokenService');
const User   = require('../models/User');
const { fail } = require('../utils/response');
const logger   = require('../utils/logger');

// ─── Constants ────────────────────────────────────────────────────────────────

const BEARER_PREFIX = 'Bearer ';
const VALID_ROLES   = new Set(['seller', 'admin']);

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Extracts the raw JWT string from the Authorization header.
 * Returns null if the header is missing or malformed.
 */
function extractToken(req) {
  const header = req.headers['authorization'];
  if (!header || !header.startsWith(BEARER_PREFIX)) return null;
  const token = header.slice(BEARER_PREFIX.length).trim();
  return token.length > 0 ? token : null;
}

/**
 * Validates the JWT payload has the required structure.
 * Returns true if valid, false otherwise.
 */
function isPayloadValid(payload) {
  return (
    payload &&
    typeof payload.user_id  === 'string' &&
    typeof payload.username === 'string' &&
    typeof payload.role     === 'string' &&
    VALID_ROLES.has(payload.role)
  );
}

// ─────────────────────────────────────────────────────────────────────────────
//  requireAuth
//  Verifies the JWT, checks the token blacklist, loads the user from DB,
//  checks the user account is not banned, then attaches req.user.
// ─────────────────────────────────────────────────────────────────────────────

exports.requireAuth = async (req, res, next) => {
  const ip = req.ip || req.connection?.remoteAddress || 'unknown';

  // ── 1. Extract token from Authorization header ────────────────────────────
  const token = extractToken(req);

  if (!token) {
    return res.status(401).json(
      fail('UNAUTHORIZED', 'Authorization header is missing or malformed. Expected: Bearer <token>')
    );
  }

  // ── 2. Verify JWT signature and expiry ────────────────────────────────────
  let decoded;
  try {
    decoded = verifyToken(token);
  } catch (err) {
    const isExpired = err.name === 'TokenExpiredError';

    logger.warn(
      `[AUTH_MW] invalid token — ip=${ip} reason=${err.name}`
    );

    return res.status(401).json(
      fail(
        isExpired ? 'TOKEN_EXPIRED' : 'INVALID_TOKEN',
        isExpired
          ? 'Your session has expired. Please log in again.'
          : 'Invalid session token.'
      )
    );
  }

  // ── 3. Validate payload structure ─────────────────────────────────────────
  if (!isPayloadValid(decoded)) {
    logger.warn(`[AUTH_MW] malformed payload — ip=${ip}`);
    return res.status(401).json(fail('INVALID_TOKEN', 'Malformed token payload.'));
  }

  // ── 4. Check token blacklist (logout / revocation) ────────────────────────
  try {
    const blacklisted = await isTokenBlacklisted(token);
    if (blacklisted) {
      logger.warn(`[AUTH_MW] blacklisted token used — user=${decoded.user_id} ip=${ip}`);
      return res.status(401).json(
        fail('TOKEN_REVOKED', 'This session has been terminated. Please log in again.')
      );
    }
  } catch (redisErr) {
    // Redis is down — log and continue (don't block all authed requests)
    logger.error(`[AUTH_MW] Redis blacklist check failed — ${redisErr.message}. Allowing request.`);
  }

  // ── 5. Load fresh user record from DB ────────────────────────────────────
  // This ensures bans and role changes take effect immediately
  let user;
  try {
    user = await User.findByPk(decoded.user_id, {
      attributes: ['id', 'username', 'email', 'role', 'is_banned'],
    });
  } catch (dbErr) {
    logger.error(`[AUTH_MW] DB error loading user — ${dbErr.message}`);
    return res.status(500).json(fail('SERVER_ERROR', 'An internal error occurred.'));
  }

  if (!user) {
    logger.warn(`[AUTH_MW] token for deleted user — user_id=${decoded.user_id} ip=${ip}`);
    return res.status(401).json(fail('INVALID_TOKEN', 'User account no longer exists.'));
  }

  // ── 6. Check if account is banned ────────────────────────────────────────
  if (user.is_banned) {
    logger.warn(`[AUTH_MW] banned user attempted access — user=${user.id} ip=${ip}`);
    return res.status(401).json(
      fail('ACCOUNT_BANNED', 'Your account has been suspended.')
    );
  }

  // ── 7. Attach user and token to request ───────────────────────────────────
  req.user       = {
    id:       user.id,
    username: user.username,
    email:    user.email,
    role:     user.role,
  };
  req.token      = token;
  req.tokenData  = decoded;

  logger.debug(`[AUTH_MW] authed — user=${user.id} role=${user.role} ip=${ip}`);

  return next();
};

// ─────────────────────────────────────────────────────────────────────────────
//  requireRole(...roles)
//  Role guard — must be used AFTER requireAuth.
//  Usage: router.get('/admin/x', requireAuth, requireRole('admin'), handler)
// ─────────────────────────────────────────────────────────────────────────────

exports.requireRole = (...roles) => {
  // Normalise roles and validate them at startup time
  const allowed = new Set(roles.map(r => r.toLowerCase()));

  for (const role of allowed) {
    if (!VALID_ROLES.has(role)) {
      throw new Error(`[requireRole] Unknown role: "${role}". Valid roles: ${[...VALID_ROLES].join(', ')}`);
    }
  }

  return (req, res, next) => {
    if (!req.user) {
      // requireAuth was not called before this middleware
      logger.error('[AUTH_MW] requireRole used without requireAuth');
      return res.status(500).json(fail('SERVER_ERROR', 'Middleware misconfiguration.'));
    }

    if (!allowed.has(req.user.role)) {
      logger.warn(
        `[AUTH_MW] forbidden — user=${req.user.id} role=${req.user.role} required=${[...allowed].join('|')}`
      );
      return res.status(403).json(
        fail('FORBIDDEN', 'You do not have permission to access this resource.')
      );
    }

    return next();
  };
};

// ─────────────────────────────────────────────────────────────────────────────
//  requireAdmin
//  Shorthand for requireRole('admin').
//  Usage: router.get('/admin/stats', requireAuth, requireAdmin, handler)
// ─────────────────────────────────────────────────────────────────────────────

exports.requireAdmin = exports.requireRole('admin');

// ─────────────────────────────────────────────────────────────────────────────
//  optionalAuth
//  Attaches req.user if a valid token is present, but never rejects.
//  Useful for routes that behave differently for authed vs anon users.
// ─────────────────────────────────────────────────────────────────────────────

exports.optionalAuth = async (req, _res, next) => {
  const token = extractToken(req);
  if (!token) return next();

  try {
    const decoded = verifyToken(token);
    if (!isPayloadValid(decoded)) return next();

    const blacklisted = await isTokenBlacklisted(token).catch(() => false);
    if (blacklisted) return next();

    const user = await User.findByPk(decoded.user_id, {
      attributes: ['id', 'username', 'email', 'role', 'is_banned'],
    });

    if (user && !user.is_banned) {
      req.user      = { id: user.id, username: user.username, email: user.email, role: user.role };
      req.token     = token;
      req.tokenData = decoded;
    }
  } catch {
    // Silently skip — optionalAuth never blocks
  }

  return next();
};

// ─────────────────────────────────────────────────────────────────────────────
//  requireOwnership(getResourceFn)
//  Dynamic ownership guard — verifies the authenticated user owns the resource.
//  Admin users bypass this check.
//
//  Usage:
//    router.delete('/applications/:id',
//      requireAuth,
//      requireOwnership(async (req) => Application.findByPk(req.params.id)),
//      handler
//    )
// ─────────────────────────────────────────────────────────────────────────────

exports.requireOwnership = (getResourceFn) => {
  return async (req, res, next) => {
    if (!req.user) {
      return res.status(500).json(fail('SERVER_ERROR', 'Middleware misconfiguration.'));
    }

    // Admins bypass ownership checks
    if (req.user.role === 'admin') return next();

    let resource;
    try {
      resource = await getResourceFn(req);
    } catch (err) {
      logger.error(`[AUTH_MW] requireOwnership fetch error — ${err.message}`);
      return res.status(500).json(fail('SERVER_ERROR', 'An internal error occurred.'));
    }

    if (!resource) {
      return res.status(404).json(fail('NOT_FOUND', 'Resource not found.'));
    }

    // Resource must have an owner_id or created_by field
    const ownerId = resource.owner_id || resource.created_by;

    if (!ownerId || String(ownerId) !== String(req.user.id)) {
      logger.warn(
        `[AUTH_MW] ownership denied — user=${req.user.id} resource.owner=${ownerId}`
      );
      return res.status(403).json(fail('FORBIDDEN', 'You do not own this resource.'));
    }

    // Attach for use in the handler
    req.resource = resource;
    return next();
  };
};

// ─────────────────────────────────────────────────────────────────────────────
//  Global error handler for async middleware
//  Catches any unhandled promise rejections that bubble up to Express.
// ─────────────────────────────────────────────────────────────────────────────

exports.asyncGuard = (fn) => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch((err) => {
      logger.error(`[AUTH_MW] unhandled async error — ${err.message}`, { stack: err.stack });
      if (!res.headersSent) {
        res.status(500).json(fail('SERVER_ERROR', 'An unexpected error occurred.'));
      }
    });
  };
};
