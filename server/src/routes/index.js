'use strict';

/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║             GHOSTY Auth — routes/index.js                   ║
 * ║         Mounts all route groups under /api/v1               ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * Route map:
 *
 *   /api/v1/auth/*         — License authentication (public, HMAC-signed)
 *   /api/v1/keys/*         — Key management         (requires seller JWT)
 *   /api/v1/users/*        — Account management     (mixed public/protected)
 *   /api/v1/admin/*        — Admin operations        (requires admin JWT)
 *
 * Usage in app.js:
 *   const routes = require('./routes');
 *   app.use('/api/v1', routes);
 */

const { Router } = require('express');
const logger = require('../utils/logger');

const authRouter  = require('./auth');
const keysRouter  = require('./keys');
const usersRouter = require('./users');
const adminRouter = require('./admin');

const router = Router();

// ─── Request logger ───────────────────────────────────────────────────────────
// Logs every inbound API request with method, path, IP, and timing.

router.use((req, res, next) => {
  const start = Date.now();
  const ip    = req.ip || req.connection?.remoteAddress || 'unknown';

  res.on('finish', () => {
    const ms     = Date.now() - start;
    const level  = res.statusCode >= 500 ? 'error'
                 : res.statusCode >= 400 ? 'warn'
                 : 'info';

    logger[level](
      `[HTTP] ${req.method} ${req.originalUrl} ${res.statusCode} — ${ms}ms — ip=${ip}`
    );
  });

  next();
});

// ─── Health check (no rate limit, no auth) ────────────────────────────────────

router.get('/health', (_req, res) => {
  res.status(200).json({
    success:   true,
    service:   'GHOSTY Auth',
    status:    'online',
    timestamp: new Date().toISOString(),
    version:   process.env.npm_package_version || '1.0.0',
  });
});

// ─── Mount route groups ───────────────────────────────────────────────────────

router.use('/auth',  authRouter);
router.use('/keys',  keysRouter);
router.use('/users', usersRouter);
router.use('/admin', adminRouter);

// ─── 404 for any unmatched /api/v1/* path ─────────────────────────────────────

router.use((req, res) => {
  res.status(404).json({
    success: false,
    code:    'NOT_FOUND',
    message: `Endpoint not found: ${req.method} ${req.originalUrl}`,
  });
});

module.exports = router;
