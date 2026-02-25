'use strict';

/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║               GHOSTY Auth — routes/keys.js                  ║
 * ║                  Mounts at: /api/v1/keys                    ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * All routes require a valid seller or admin JWT.
 *
 * Routes:
 *   POST   /api/v1/keys/generate       — Generate license keys
 *   GET    /api/v1/keys                — List keys for an app
 *   GET    /api/v1/keys/:id            — Get a single key
 *   POST   /api/v1/keys/ban            — Ban a key
 *   POST   /api/v1/keys/unban          — Unban a key
 *   POST   /api/v1/keys/reset-hwid     — Reset HWID binding
 *   POST   /api/v1/keys/extend         — Extend key expiry
 *   DELETE /api/v1/keys/:id            — Permanently delete a key
 *
 * Middleware stack (in order for all routes):
 *   verifyContentType  → JSON only
 *   requireAuth        → Valid JWT + non-banned account
 *   requireRole        → seller or admin only
 *   rateLimiter.keys   → 30 req/60s per seller
 *   controller         → Business logic
 */

const { Router } = require('express');

const keyController  = require('../controllers/keyController');
const rateLimiter    = require('../middleware/rateLimiter');
const { requireAuth, requireRole } = require('../middleware/authMiddleware');
const { verifyContentType, verifyBodySize } = require('../middleware/requestVerifier');

const router = Router();

// ─── Apply to ALL /keys routes ────────────────────────────────────────────────

router.use(verifyContentType);
router.use(requireAuth);
router.use(requireRole('seller', 'admin'));
router.use(rateLimiter.keys);

// ─────────────────────────────────────────────────────────────────────────────
//  POST /keys/generate
//  Generate one or more license keys for an application.
//
//  Body: { app_id, quantity, expires_in_days?, note? }
// ─────────────────────────────────────────────────────────────────────────────

router.post(
  '/generate',
  verifyBodySize(1024),
  keyController.generate
);

// ─────────────────────────────────────────────────────────────────────────────
//  GET /keys
//  List keys for an application with optional filters and pagination.
//
//  Query params: app_id (required), status?, search?, page?, limit?
// ─────────────────────────────────────────────────────────────────────────────

router.get(
  '/',
  keyController.list
);

// ─────────────────────────────────────────────────────────────────────────────
//  GET /keys/:id
//  Get full details for a single license key.
// ─────────────────────────────────────────────────────────────────────────────

router.get(
  '/:id',
  keyController.getOne
);

// ─────────────────────────────────────────────────────────────────────────────
//  POST /keys/ban
//  Ban a license key.
//
//  Body: { key_id, reason? }
// ─────────────────────────────────────────────────────────────────────────────

router.post(
  '/ban',
  verifyBodySize(512),
  keyController.ban
);

// ─────────────────────────────────────────────────────────────────────────────
//  POST /keys/unban
//  Unban a license key.
//
//  Body: { key_id }
// ─────────────────────────────────────────────────────────────────────────────

router.post(
  '/unban',
  verifyBodySize(512),
  keyController.unban
);

// ─────────────────────────────────────────────────────────────────────────────
//  POST /keys/reset-hwid
//  Reset the HWID binding on a key (allows re-use on new hardware).
//
//  Body: { key_id }
// ─────────────────────────────────────────────────────────────────────────────

router.post(
  '/reset-hwid',
  verifyBodySize(512),
  keyController.resetHwid
);

// ─────────────────────────────────────────────────────────────────────────────
//  POST /keys/extend
//  Extend the expiry of a key by N days.
//
//  Body: { key_id, days }
// ─────────────────────────────────────────────────────────────────────────────

router.post(
  '/extend',
  verifyBodySize(512),
  keyController.extend
);

// ─────────────────────────────────────────────────────────────────────────────
//  DELETE /keys/:id
//  Permanently delete a license key.
// ─────────────────────────────────────────────────────────────────────────────

router.delete(
  '/:id',
  keyController.deleteKey
);

// ─────────────────────────────────────────────────────────────────────────────
//  Catch-all
// ─────────────────────────────────────────────────────────────────────────────

router.all('*', (req, res) => {
  res.status(404).json({
    success: false,
    code:    'NOT_FOUND',
    message: `Keys route not found: ${req.method} ${req.originalUrl}`,
  });
});

module.exports = router;
