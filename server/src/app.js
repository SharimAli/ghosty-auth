'use strict';

/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║               GHOSTY Auth — app.js                          ║
 * ║     Express application setup — middleware, routes, errors  ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * This file builds and exports the Express app.
 * It does NOT start the HTTP server — that is server.js's job.
 *
 * Middleware order (matters):
 *   1.  Trust proxy            — correct IP behind Nginx
 *   2.  Security headers       — helmet
 *   3.  CORS                   — preflight + headers
 *   4.  Request logger         — timing on every request
 *   5.  Body parser            — JSON only, 16kb hard cap
 *   6.  Request ID             — unique ID on every request
 *   7.  Rate limiter (global)  — general bucket
 *   8.  Routes                 — /api/v1/*
 *   9.  404 handler            — unmatched paths
 *   10. Global error handler   — catches anything that slips through
 */

const express  = require('express');
const helmet   = require('helmet');
const cors     = require('cors');
const crypto   = require('crypto');

const env    = require('./src/config/env');
const logger = require('./src/utils/logger');
const { fail } = require('./src/utils/response');
const routes   = require('./src/routes/index');

// ─── App ──────────────────────────────────────────────────────────────────────

const app = express();

// ─── 1. Trust Proxy ───────────────────────────────────────────────────────────
// Trust the first proxy hop (Nginx) so req.ip gives the real client IP.
// In production with multiple proxy layers, set this to the number of hops.

app.set('trust proxy', 1);

// Disable the X-Powered-By header (don't advertise Express)
app.disable('x-powered-by');

// ─── 2. Security Headers (Helmet) ─────────────────────────────────────────────

app.use(helmet({
  // Content Security Policy — restrict what the API can load
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'none'"],
      scriptSrc:  ["'none'"],
      objectSrc:  ["'none'"],
      frameAncestors: ["'none'"],
    },
  },
  // Prevent MIME-type sniffing
  noSniff: true,
  // Force HTTPS in production
  hsts: env.IS_PROD
    ? { maxAge: 31536000, includeSubDomains: true, preload: true }
    : false,
  // Prevent clickjacking
  frameguard: { action: 'deny' },
  // XSS protection header (legacy browsers)
  xssFilter: true,
  // Remove referrer info on cross-origin requests
  referrerPolicy: { policy: 'no-referrer' },
  // Disable DNS prefetching
  dnsPrefetchControl: { allow: false },
  // Prevent IE from opening downloads in site context
  ieNoOpen: true,
  // Don't send X-Download-Options
  permittedCrossDomainPolicies: { permittedPolicies: 'none' },
}));

// ─── 3. CORS ──────────────────────────────────────────────────────────────────

const corsOptions = {
  origin: (origin, callback) => {
    // Allow requests with no origin (curl, Postman, server-to-server, SDKs)
    if (!origin) return callback(null, true);

    // Wildcard — allow all (dev only)
    if (env.CORS_ORIGIN === '*') return callback(null, true);

    // Comma-separated whitelist of allowed origins
    const allowed = env.CORS_ORIGIN
      .split(',')
      .map(o => o.trim())
      .filter(Boolean);

    if (allowed.includes(origin)) {
      return callback(null, true);
    }

    logger.warn(`[CORS] Blocked origin: ${origin}`);
    return callback(new Error(`CORS: Origin "${origin}" is not allowed.`));
  },

  methods:          ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders:   ['Content-Type', 'Authorization', 'X-Client'],
  exposedHeaders:   [
    'X-RateLimit-Limit',
    'X-RateLimit-Remaining',
    'X-RateLimit-Reset',
    'Retry-After',
  ],
  credentials:      true,
  maxAge:           86400,    // Cache preflight for 24h
  optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));

// Handle CORS errors
app.use((err, req, res, next) => {
  if (err.message && err.message.startsWith('CORS:')) {
    return res.status(403).json(fail('CORS_BLOCKED', err.message));
  }
  return next(err);
});

// ─── 4. Request Logger ────────────────────────────────────────────────────────

app.use(logger.requestMiddleware);

// ─── 5. Body Parser ───────────────────────────────────────────────────────────
// Hard cap body at 16kb — auth payloads are tiny, there is no reason
// to accept anything larger.

app.use(express.json({
  limit:  '16kb',
  strict: true,   // Only accept arrays and objects (reject primitives)
  type:   'application/json',
  verify: (req, _res, buf) => {
    // Attach raw body buffer for HMAC verification if ever needed
    req.rawBody = buf;
  },
}));

// Reject malformed JSON with a clean error (instead of Express's default HTML)
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json(fail('INVALID_JSON', 'Request body contains malformed JSON.'));
  }
  if (err.type === 'entity.too.large') {
    return res.status(413).json(fail('PAYLOAD_TOO_LARGE', 'Request body exceeds the 16kb size limit.'));
  }
  return next(err);
});

// ─── 6. Request ID ────────────────────────────────────────────────────────────
// Attaches a unique UUID to every request for log correlation.
// Returned in the X-Request-ID response header.

app.use((req, res, next) => {
  const requestId = crypto.randomUUID();
  req.requestId   = requestId;
  res.set('X-Request-ID', requestId);
  next();
});

// ─── 7. Prevent Parameter Pollution ──────────────────────────────────────────
// If the same query param appears multiple times Express puts them in an array.
// This middleware collapses duplicates to the last value.

app.use((req, _res, next) => {
  if (req.query) {
    for (const key of Object.keys(req.query)) {
      if (Array.isArray(req.query[key])) {
        req.query[key] = req.query[key][req.query[key].length - 1];
      }
    }
  }
  next();
});

// ─── 8. Routes ────────────────────────────────────────────────────────────────

app.use('/api/v1', routes);

// ─── 9. 404 — Unmatched Routes ────────────────────────────────────────────────

app.use((req, res) => {
  res.status(404).json(
    fail('NOT_FOUND', `Cannot ${req.method} ${req.originalUrl}`)
  );
});

// ─── 10. Global Error Handler ─────────────────────────────────────────────────
// Catches any error passed via next(err) from routes or middleware.
// Always returns JSON — never HTML.

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, _next) => {
  const requestId = req.requestId || 'unknown';

  // Don't leak internal error details to clients in production
  if (env.IS_PROD) {
    logger.error(`[APP] Unhandled error — req=${requestId}`, {
      method: req.method,
      url:    req.originalUrl,
      name:   err.name,
      msg:    err.message,
      stack:  err.stack,
    });

    return res.status(500).json(
      fail('SERVER_ERROR', 'An unexpected error occurred. Please try again.')
    );
  }

  // Development — include error details in response for debugging
  logger.error(`[APP] Unhandled error`, {
    method: req.method,
    url:    req.originalUrl,
    error:  err,
  });

  return res.status(err.status || 500).json({
    success:    false,
    code:       err.code || 'SERVER_ERROR',
    message:    err.message || 'An unexpected error occurred.',
    stack:      err.stack?.split('\n').slice(0, 6),
    request_id: requestId,
  });
});

module.exports = app;
