'use strict';

/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║               GHOSTY Auth — routes/auth.js                  ║
 * ║                  Mounts at: /api/v1/auth                    ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * Routes:
 *   POST /api/v1/auth/init        — Authenticate a license key
 *   POST /api/v1/auth/validate    — Validate an active session token
 *   POST /api/v1/auth/logout      — Terminate a session
 *
 * Middleware stack (in order):
 *   verifyContentType     → Reject non-JSON bodies
 *   verifyBodySize        → Reject oversized payloads
 *   rateLimiter.*         → Redis sliding window rate limits
 *   verifyAuthRequest     → HMAC signature + timestamp freshness (init only)
 *   verifyValidateRequest → Basic shape check (validate/logout)
 *   controller            → Business logic
 */

const { Router } = require('express');

const authController  = require('../controllers/authController');
const rateLimiter     = require('../middleware/rateLimiter');
const {
  verifyContentType,
  verifyBodySize,
  verifyAuthRequest,
  verifyValidateRequest,
} = require('../middleware/requestVerifier');

const router = Router();

// ─── Apply to all /auth routes ────────────────────────────────────────────────

// All auth routes must send JSON
router.use(verifyContentType);

// ─────────────────────────────────────────────────────────────────────────────
//  POST /auth/init
//  Validate a license key and issue a session token.
//
//  Middleware order:
//    1. verifyBodySize(2048)  — cap body at 2 KB (auth payloads are tiny)
//    2. rateLimiter.auth      — 10 req/60s per IP
//    3. verifyAuthRequest     — timestamp freshness + HMAC signature
//    4. authController.init   — core validation logic
// ─────────────────────────────────────────────────────────────────────────────

router.post(
  '/init',
  verifyBodySize(2048),
  rateLimiter.auth,
  verifyAuthRequest,
  authController.init
);

// ─────────────────────────────────────────────────────────────────────────────
//  POST /auth/validate
//  Validate an active session token.
//
//  Middleware order:
//    1. verifyBodySize(1024)
//    2. rateLimiter.validate      — 60 req/60s per token
//    3. verifyValidateRequest     — basic shape/type check
//    4. authController.validate
// ─────────────────────────────────────────────────────────────────────────────

router.post(
  '/validate',
  verifyBodySize(1024),
  rateLimiter.validate,
  verifyValidateRequest,
  authController.validate
);

// ─────────────────────────────────────────────────────────────────────────────
//  POST /auth/logout
//  Blacklist the session token server-side.
//
//  Middleware order:
//    1. verifyBodySize(512)
//    2. rateLimiter.general       — 100 req/60s per IP
//    3. authController.logout
// ─────────────────────────────────────────────────────────────────────────────

router.post(
  '/logout',
  verifyBodySize(512),
  rateLimiter.general,
  authController.logout
);

// ─────────────────────────────────────────────────────────────────────────────
//  Catch-all: unknown /auth/* paths
// ─────────────────────────────────────────────────────────────────────────────

router.all('*', (req, res) => {
  res.status(404).json({
    success: false,
    code:    'NOT_FOUND',
    message: `Auth route not found: ${req.method} ${req.originalUrl}`,
  });
});

module.exports = router;
