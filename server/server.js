'use strict';

/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║               GHOSTY Auth — server.js                       ║
 * ║   Entry point — boot sequence and graceful shutdown         ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * Boot sequence:
 *   1. Load & validate environment variables  (env.js)
 *   2. Connect to PostgreSQL                  (db.js → connectDB)
 *   3. Connect to Redis                       (redis.js → connectRedis)
 *   4. Start HTTP server                      (app.js → listen)
 *   5. Register signal handlers               (SIGTERM, SIGINT)
 *
 * Shutdown sequence (on SIGTERM / SIGINT):
 *   1. Stop accepting new HTTP connections
 *   2. Wait for in-flight requests to finish  (30s grace period)
 *   3. Close Redis connection
 *   4. Close PostgreSQL pool
 *   5. Exit 0
 */

// ── env MUST be the first require — validates all env vars before anything else
const env = require('./src/config/env');

const http   = require('http');
const app    = require('./src/app');
const logger = require('./src/utils/logger');
const { connectDB, disconnectDB }       = require('./src/config/db');
const { connectRedis, disconnectRedis } = require('./src/config/redis');

// ─── Constants ────────────────────────────────────────────────────────────────

const SHUTDOWN_GRACE_MS = 30_000;   // Max time to drain in-flight requests

// ─── HTTP Server ──────────────────────────────────────────────────────────────

const server = http.createServer(app);

// Keep-alive and header timeout hardening
// Prevents Slowloris-style attacks and proxy timeout mismatches
server.keepAliveTimeout    = 65_000;   // Must be > Nginx's keepalive_timeout (60s)
server.headersTimeout      = 66_000;   // Must be > keepAliveTimeout
server.requestTimeout      = 30_000;   // Hard cap per request
server.maxHeadersCount     = 50;

// ─── Boot ─────────────────────────────────────────────────────────────────────

async function boot() {
  logger.info('╔══════════════════════════════════════════════╗');
  logger.info('║          GHOSTY Auth — Starting up          ║');
  logger.info('╚══════════════════════════════════════════════╝');
  logger.info(`[BOOT] Environment : ${env.NODE_ENV}`);
  logger.info(`[BOOT] Node.js     : ${process.version}`);
  logger.info(`[BOOT] PID         : ${process.pid}`);

  // ── Step 1: PostgreSQL ─────────────────────────────────────────────────────
  try {
    await connectDB({
      sync:  true,
      force: false,
      // In production: alter=false (use migrations instead)
      // In dev:        alter=true  (auto-migrate during development)
      alter: env.IS_DEV,
    });
  } catch (err) {
    logger.fatal(`[BOOT] PostgreSQL connection failed — ${err.message}`);
    process.exit(1);
  }

  // ── Step 2: Redis ──────────────────────────────────────────────────────────
  try {
    await connectRedis();
  } catch (err) {
    logger.fatal(`[BOOT] Redis connection failed — ${err.message}`);
    // Gracefully disconnect DB before exiting
    await disconnectDB().catch(() => {});
    process.exit(1);
  }

  // ── Step 3: HTTP Server ────────────────────────────────────────────────────
  await new Promise((resolve, reject) => {
    server.listen(env.PORT, env.HOST, (err) => {
      if (err) return reject(err);
      resolve();
    });

    server.once('error', reject);
  }).catch((err) => {
    logger.fatal(`[BOOT] HTTP server failed to start — ${err.message}`);
    process.exit(1);
  });

  // ── Ready ──────────────────────────────────────────────────────────────────
  logger.info('╔══════════════════════════════════════════════╗');
  logger.info('║         GHOSTY Auth — Ready  ✓              ║');
  logger.info('╚══════════════════════════════════════════════╝');
  logger.info(`[BOOT] Listening on http://${env.HOST}:${env.PORT}`);
  logger.info(`[BOOT] API base    : http://${env.HOST}:${env.PORT}/api/v1`);
  logger.info(`[BOOT] Health      : http://${env.HOST}:${env.PORT}/api/v1/health`);
}

// ─── Graceful Shutdown ────────────────────────────────────────────────────────

let isShuttingDown = false;

async function shutdown(signal) {
  if (isShuttingDown) {
    logger.warn(`[SHUTDOWN] Already shutting down — ignoring ${signal}`);
    return;
  }

  isShuttingDown = true;
  logger.info(`[SHUTDOWN] ${signal} received — beginning graceful shutdown`);

  // ── Step 1: Stop accepting new connections ─────────────────────────────────
  // server.close() stops new connections but lets in-flight requests finish
  const closeServer = new Promise((resolve, reject) => {
    server.close((err) => {
      if (err && err.code !== 'ERR_SERVER_NOT_RUNNING') return reject(err);
      resolve();
    });
  });

  // ── Step 2: Enforce grace period ──────────────────────────────────────────
  const graceTimer = setTimeout(() => {
    logger.warn(`[SHUTDOWN] Grace period (${SHUTDOWN_GRACE_MS}ms) exceeded — forcing close`);
    server.closeAllConnections?.();   // Node 18.2+
  }, SHUTDOWN_GRACE_MS);

  try {
    await closeServer;
    clearTimeout(graceTimer);
    logger.info('[SHUTDOWN] HTTP server closed — all connections drained');
  } catch (err) {
    clearTimeout(graceTimer);
    logger.error(`[SHUTDOWN] HTTP server close error — ${err.message}`);
  }

  // ── Step 3: Close Redis ────────────────────────────────────────────────────
  try {
    await disconnectRedis();
  } catch (err) {
    logger.error(`[SHUTDOWN] Redis disconnect error — ${err.message}`);
  }

  // ── Step 4: Close PostgreSQL ───────────────────────────────────────────────
  try {
    await disconnectDB();
  } catch (err) {
    logger.error(`[SHUTDOWN] DB disconnect error — ${err.message}`);
  }

  logger.info('[SHUTDOWN] Shutdown complete. Goodbye.');
  process.exit(0);
}

// ─── Signal Handlers ──────────────────────────────────────────────────────────

// SIGTERM — sent by Docker, Kubernetes, PM2, systemd on graceful stop
process.on('SIGTERM', () => shutdown('SIGTERM'));

// SIGINT — Ctrl+C in terminal
process.on('SIGINT',  () => shutdown('SIGINT'));

// SIGHUP — sent by PM2 on reload (restart without kill)
process.on('SIGHUP',  () => shutdown('SIGHUP'));

// ── Unhandled errors are caught in logger.js process-level listeners.
//    They log + call process.exit(1) automatically.
//    Added here as a safety net in case logger.js isn't loaded yet.

process.on('uncaughtException', (err) => {
  console.error('[FATAL] Uncaught Exception:', err.message, err.stack);
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  console.error('[FATAL] Unhandled Rejection:', reason);
  process.exit(1);
});

// ─── Start ────────────────────────────────────────────────────────────────────

boot();
