'use strict';

/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║               GHOSTY Auth — routes/users.js                 ║
 * ║                  Mounts at: /api/v1/users                   ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * Public routes (no auth required):
 *   POST   /api/v1/users/register           — Create a seller account
 *   POST   /api/v1/users/login              — Authenticate, receive JWT
 *
 * Protected routes (valid JWT required):
 *   GET    /api/v1/users/me                 — Get own profile
 *   PATCH  /api/v1/users/me                 — Update username / password
 *
 * Application management (protected):
 *   POST   /api/v1/users/applications       — Create a new application
 *   GET    /api/v1/users/applications       — List own applications
 *   DELETE /api/v1/users/applications/:id   — Delete an application
 *
 * Middleware stack:
 *   Public:    verifyContentType → rateLimiter.* → controller
 *   Protected: verifyContentType → requireAuth   → rateLimiter.general → controller
 */

const { Router } = require('express');

const userController = require('../controllers/userController');
const rateLimiter    = require('../middleware/rateLimiter');
const { requireAuth, requireRole } = require('../middleware/authMiddleware');
const { verifyContentType, verifyBodySize } = require('../middleware/requestVerifier');

const router = Router();

// ─── Apply to ALL /users routes ───────────────────────────────────────────────

router.use(verifyContentType);

// ─────────────────────────────────────────────────────────────────────────────
//  PUBLIC ROUTES  (no JWT required)
// ─────────────────────────────────────────────────────────────────────────────

// ── POST /users/register ──────────────────────────────────────────────────────
// Create a new seller account.
// Rate limited to 5/hr per IP to prevent mass account creation.
//
// Body: { username, email, password, registration_key? }

router.post(
  '/register',
  verifyBodySize(1024),
  rateLimiter.register,
  userController.register
);

// ── POST /users/login ─────────────────────────────────────────────────────────
// Authenticate and receive a JWT.
// Rate limited to 10 attempts per 15 min per IP (brute-force guard).
//
// Body: { email, password }

router.post(
  '/login',
  verifyBodySize(512),
  rateLimiter.login,
  userController.login
);

// ─────────────────────────────────────────────────────────────────────────────
//  PROTECTED ROUTES  (valid JWT required)
// ─────────────────────────────────────────────────────────────────────────────

// Apply auth to everything below this line
router.use(requireAuth);
router.use(rateLimiter.general);

// ── GET /users/me ─────────────────────────────────────────────────────────────
// Return the authenticated user's own profile.

router.get(
  '/me',
  userController.me
);

// ── PATCH /users/me ───────────────────────────────────────────────────────────
// Update own username or password.
//
// Body: { username?, current_password?, new_password? }

router.patch(
  '/me',
  verifyBodySize(1024),
  userController.updateMe
);

// ─────────────────────────────────────────────────────────────────────────────
//  APPLICATION MANAGEMENT  (protected — seller or admin)
// ─────────────────────────────────────────────────────────────────────────────

router.use(requireRole('seller', 'admin'));

// ── POST /users/applications ──────────────────────────────────────────────────
// Create a new application under the authenticated seller.
//
// Body: { name, description? }
// Returns: { id, name, description, secret, created_at }
// ⚠ Secret is ONLY returned at creation time — not stored again

router.post(
  '/applications',
  verifyBodySize(1024),
  userController.createApp
);

// ── GET /users/applications ───────────────────────────────────────────────────
// List all applications belonging to the authenticated seller.
// Secrets are NOT included in list responses.

router.get(
  '/applications',
  userController.listApps
);

// ── DELETE /users/applications/:id ────────────────────────────────────────────
// Delete an application and all its license keys (CASCADE).

router.delete(
  '/applications/:id',
  userController.deleteApp
);

// ─────────────────────────────────────────────────────────────────────────────
//  Catch-all
// ─────────────────────────────────────────────────────────────────────────────

router.all('*', (req, res) => {
  res.status(404).json({
    success: false,
    code:    'NOT_FOUND',
    message: `Users route not found: ${req.method} ${req.originalUrl}`,
  });
});

module.exports = router;
