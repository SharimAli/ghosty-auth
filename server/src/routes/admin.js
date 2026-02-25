'use strict';

/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║               GHOSTY Auth — routes/admin.js                 ║
 * ║                  Mounts at: /api/v1/admin                   ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * ALL routes require: valid JWT + role === 'admin'
 *
 * Routes:
 *
 *  Stats
 *   GET    /api/v1/admin/stats                    — System-wide stats
 *
 *  User management
 *   GET    /api/v1/admin/users                    — List all users
 *   GET    /api/v1/admin/users/:id                — Get user + their apps
 *   PATCH  /api/v1/admin/users/:id                — Update role / force pw reset
 *   POST   /api/v1/admin/users/ban                — Ban a seller account
 *   POST   /api/v1/admin/users/unban              — Unban a seller account
 *   DELETE /api/v1/admin/users/:id                — Delete user + all data
 *
 *  Application management
 *   GET    /api/v1/admin/applications             — List all apps (all sellers)
 *   POST   /api/v1/admin/applications/:id/toggle  — Enable / disable an app
 *
 *  Log management
 *   GET    /api/v1/admin/logs                     — Query system logs
 *   DELETE /api/v1/admin/logs                     — Purge old logs
 *
 * Middleware stack (all routes):
 *   verifyContentType → requireAuth → requireAdmin → rateLimiter.admin → controller
 */

const { Router } = require('express');

const adminController = require('../controllers/adminController');
const rateLimiter     = require('../middleware/rateLimiter');
const { requireAuth, requireAdmin } = require('../middleware/authMiddleware');
const { verifyContentType, verifyBodySize } = require('../middleware/requestVerifier');

const router = Router();

// ─── Apply to ALL /admin routes ───────────────────────────────────────────────

router.use(verifyContentType);
router.use(requireAuth);
router.use(requireAdmin);
router.use(rateLimiter.admin);

// ─────────────────────────────────────────────────────────────────────────────
//  STATS
// ─────────────────────────────────────────────────────────────────────────────

// ── GET /admin/stats ──────────────────────────────────────────────────────────
// Returns system-wide counts: users, apps, keys by status, 24h auth activity.

router.get(
  '/stats',
  adminController.getStats
);

// ─────────────────────────────────────────────────────────────────────────────
//  USER MANAGEMENT
//
//  NOTE: Specific action routes (/ban, /unban) are declared BEFORE the
//  wildcard /:id route to ensure they are matched correctly by Express.
// ─────────────────────────────────────────────────────────────────────────────

// ── GET /admin/users ──────────────────────────────────────────────────────────
// List all seller accounts with optional filters.
// Query params: search?, role?, is_banned?, page?, limit?

router.get(
  '/users',
  adminController.listUsers
);

// ── POST /admin/users/ban ─────────────────────────────────────────────────────
// Ban a seller account.
// Body: { user_id, reason? }

router.post(
  '/users/ban',
  verifyBodySize(512),
  adminController.banUser
);

// ── POST /admin/users/unban ───────────────────────────────────────────────────
// Unban a seller account.
// Body: { user_id }

router.post(
  '/users/unban',
  verifyBodySize(256),
  adminController.unbanUser
);

// ── GET /admin/users/:id ──────────────────────────────────────────────────────
// Get a single user with their applications and key count.

router.get(
  '/users/:id',
  adminController.getUser
);

// ── PATCH /admin/users/:id ────────────────────────────────────────────────────
// Update a user's role or force-reset their password.
// Body: { role?, new_password? }

router.patch(
  '/users/:id',
  verifyBodySize(512),
  adminController.updateUser
);

// ── DELETE /admin/users/:id ───────────────────────────────────────────────────
// Permanently delete a user and all their data (cascade).

router.delete(
  '/users/:id',
  adminController.deleteUser
);

// ─────────────────────────────────────────────────────────────────────────────
//  APPLICATION MANAGEMENT
// ─────────────────────────────────────────────────────────────────────────────

// ── GET /admin/applications ───────────────────────────────────────────────────
// List all applications across all sellers.
// Query params: search?, owner_id?, page?, limit?
// NOTE: Secrets are NOT included in this response.

router.get(
  '/applications',
  adminController.listApps
);

// ── POST /admin/applications/:id/toggle ───────────────────────────────────────
// Enable or disable an application globally.
// When disabled, all /auth/init calls for that app return 401 INVALID_APP.

router.post(
  '/applications/:id/toggle',
  adminController.toggleApp
);

// ─────────────────────────────────────────────────────────────────────────────
//  LOG MANAGEMENT
// ─────────────────────────────────────────────────────────────────────────────

// ── GET /admin/logs ───────────────────────────────────────────────────────────
// Query system logs with rich filtering.
// Query params: app_id?, license_id?, action?, status?, ip?, from?, to?, page?, limit?

router.get(
  '/logs',
  adminController.getLogs
);

// ── DELETE /admin/logs ────────────────────────────────────────────────────────
// Purge log entries older than N days.
// Body: { older_than_days? }  (default: 90)

router.delete(
  '/logs',
  verifyBodySize(256),
  adminController.purgeLogs
);

// ─────────────────────────────────────────────────────────────────────────────
//  Catch-all
// ─────────────────────────────────────────────────────────────────────────────

router.all('*', (req, res) => {
  res.status(404).json({
    success: false,
    code:    'NOT_FOUND',
    message: `Admin route not found: ${req.method} ${req.originalUrl}`,
  });
});

module.exports = router;
