'use strict';

/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║               GHOSTY Auth — db.js                           ║
 * ║     Sequelize PostgreSQL connection, pool, and sync         ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * Exports:
 *   sequelize          — the Sequelize instance (default export)
 *   connectDB()        — connects, runs associations, syncs schema
 *   disconnectDB()     — gracefully closes pool
 *   healthCheck()      — tests connection, returns status object
 *
 * Usage:
 *   // In app.js / server.js:
 *   const { connectDB } = require('./config/db');
 *   await connectDB();
 *
 *   // In models:
 *   const sequelize = require('../config/db');
 *   class MyModel extends Model {}
 *   MyModel.init({ ... }, { sequelize });
 */

const { Sequelize } = require('sequelize');
const env    = require('./env');
const logger = require('../utils/logger');
const DB_URL = process.env.DATABASE_URL;

// ─── Constants ────────────────────────────────────────────────────────────────

const MAX_CONNECT_RETRIES  = 5;
const CONNECT_RETRY_DELAY  = 3000;   // ms between retries

// ─── Sequelize Instance ───────────────────────────────────────────────────────

const sequelize = DB_URL
  ? new Sequelize(DB_URL, {
      dialect: 'postgres',
      logging: env.DB.LOG_QUERIES ? (sql, timing) => logger.query(sql, timing) : false,
      benchmark: env.DB.LOG_QUERIES,
      dialectOptions: {
        ssl: { require: true, rejectUnauthorized: false },
      },
      pool: {
        min:     env.DB.POOL.MIN,
        max:     env.DB.POOL.MAX,
        acquire: env.DB.POOL.ACQUIRE_MS,
        idle:    env.DB.POOL.IDLE_MS,
      },
      define: {
        underscored:     false,
        timestamps:      true,
        freezeTableName: true,
      },
      timezone: '+00:00',
    })
  : new Sequelize(
      env.DB.NAME,
      env.DB.USER,
      env.DB.PASSWORD,
      {
        host:    env.DB.HOST,
        port:    env.DB.PORT,
        dialect: 'postgres',
        pool: {
          min:     env.DB.POOL.MIN,
          max:     env.DB.POOL.MAX,
          acquire: env.DB.POOL.ACQUIRE_MS,
          idle:    env.DB.POOL.IDLE_MS,
        },
        ...(env.DB.SSL && {
          dialectOptions: {
            ssl: { require: true, rejectUnauthorized: true },
          },
        }),
        logging: env.DB.LOG_QUERIES ? (sql, timing) => logger.query(sql, timing) : false,
        benchmark: env.DB.LOG_QUERIES,
        define: {
          underscored:     false,
          timestamps:      true,
          freezeTableName: true,
        },
        timezone: '+00:00',
      }
    );

// ─── connect (with retry) ─────────────────────────────────────────────────────

/**
 * Attempts to authenticate the Sequelize connection.
 * Retries up to MAX_CONNECT_RETRIES times on failure.
 *
 * @returns {Promise<void>}
 */
async function _authenticate() {
  for (let attempt = 1; attempt <= MAX_CONNECT_RETRIES; attempt++) {
    try {
      await sequelize.authenticate();
      return;   // Success
    } catch (err) {
      const isLast = attempt === MAX_CONNECT_RETRIES;

      logger[isLast ? 'fatal' : 'warn'](
        `[DB] Connection attempt ${attempt}/${MAX_CONNECT_RETRIES} failed — ${err.message}`,
        { host: env.DB.HOST, port: env.DB.PORT, db: env.DB.NAME }
      );

      if (isLast) throw err;

      // Wait before retrying
      await new Promise(resolve => setTimeout(resolve, CONNECT_RETRY_DELAY));
    }
  }
}

// ─── connectDB ────────────────────────────────────────────────────────────────

/**
 * Connects to PostgreSQL, loads all models and their associations,
 * and synchronises the schema.
 *
 * Call once at server startup — not on every request.
 *
 * @param {object}  [options]
 * @param {boolean} [options.sync=true]      — whether to sync schema
 * @param {boolean} [options.force=false]    — DROP and recreate tables (dev only)
 * @param {boolean} [options.alter=false]    — ALTER tables to match models (dev only)
 * @returns {Promise<void>}
 */
async function connectDB(options = {}) {
  const {
    sync  = true,
    force = false,
    alter = !env.IS_PROD && !env.IS_TEST,
  } = options;

  logger.info('[DB] Connecting to PostgreSQL...', {
    host: env.DB.HOST,
    port: env.DB.PORT,
    db:   env.DB.NAME,
    pool: `${env.DB.POOL.MIN}–${env.DB.POOL.MAX}`,
  });

  // ── 1. Authenticate ───────────────────────────────────────────────────────
  await _authenticate();
  logger.info('[DB] Connection authenticated successfully.');

  // ── 2. Load models + wire associations ────────────────────────────────────
  // Importing models/index.js triggers all model definitions and association
  // calls. This must happen AFTER authentication to ensure sequelize is ready.
  require('../models/index');
  logger.info('[DB] Models loaded and associations wired.');

  // ── 3. Schema sync ────────────────────────────────────────────────────────
  if (sync) {
    if (force && env.IS_PROD) {
      logger.fatal('[DB] sync { force: true } is not allowed in production. Refusing to start.');
      process.exit(1);
    }

    const syncOpts = force
      ? { force: true }
      : alter
        ? { alter: { drop: false } }   // alter but never DROP columns
        : {};

    const mode = force ? 'FORCE' : alter ? 'ALTER' : 'SAFE';
    logger.info(`[DB] Syncing schema (mode: ${mode})...`);

    await sequelize.sync(syncOpts);
    logger.info('[DB] Schema sync complete.');
  }
}

// ─── disconnectDB ─────────────────────────────────────────────────────────────

/**
 * Gracefully closes the connection pool.
 * Call during SIGTERM/SIGINT shutdown handlers.
 *
 * @returns {Promise<void>}
 */
async function disconnectDB() {
  try {
    await sequelize.close();
    logger.info('[DB] Connection pool closed.');
  } catch (err) {
    logger.error(`[DB] Error closing connection pool — ${err.message}`);
  }
}

// ─── healthCheck ─────────────────────────────────────────────────────────────

/**
 * Tests the database connection and returns a status object.
 * Used by the /health endpoint and monitoring systems.
 *
 * @returns {Promise<{ status: 'ok'|'error', latency_ms: number, error?: string }>}
 */
async function healthCheck() {
  const start = Date.now();
  try {
    await sequelize.authenticate();
    return {
      status:     'ok',
      latency_ms: Date.now() - start,
    };
  } catch (err) {
    return {
      status:     'error',
      latency_ms: Date.now() - start,
      error:      err.message,
    };
  }
}

// ─── Exports ──────────────────────────────────────────────────────────────────

module.exports = sequelize;

module.exports.connectDB    = connectDB;
module.exports.disconnectDB = disconnectDB;
module.exports.healthCheck  = healthCheck;
