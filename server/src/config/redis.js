'use strict';

/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║               GHOSTY Auth — redis.js                        ║
 * ║   Redis client with reconnect, health check, and helpers    ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * Uses the 'redis' v4 package (ioredis-compatible API).
 *
 * Exports:
 *   connectRedis()          — creates and connects the client
 *   disconnectRedis()       — graceful shutdown
 *   getClient()             — returns the live client (throws if not connected)
 *   healthCheck()           — PING test, returns status object
 *   isConnected()           — boolean connection state
 *
 * Internal Redis key namespacing:
 *   All keys are prefixed with env.REDIS.KEY_PREFIX (default: 'ghosty:')
 *   Sub-modules add their own prefix on top:
 *     Rate limiter:   ghosty:rl:<bucket>:<identity>
 *     Token blacklist: ghosty:bl:<token_hash>
 *     User revocation: ghosty:rv:<user_id>
 */

const redis  = require('redis');
const env    = require('./env');
const logger = require('../utils/logger');

// ─── State ────────────────────────────────────────────────────────────────────

/** @type {import('redis').RedisClientType | null} */
let client          = null;
let connectionState = 'disconnected';  // 'disconnected' | 'connecting' | 'connected' | 'error'
let reconnectCount  = 0;

const MAX_RECONNECT_ATTEMPTS = 10;
const RECONNECT_STRATEGY_CAP = 10000;   // ms — max delay between reconnects

// ─── connectRedis ─────────────────────────────────────────────────────────────

/**
 * Creates and connects the Redis client.
 * Sets up event listeners for connection lifecycle logging.
 * Call once at server startup.
 *
 * @returns {Promise<void>}
 */
async function connectRedis() {
  if (client && connectionState === 'connected') {
    logger.warn('[Redis] connectRedis() called but already connected. Skipping.');
    return;
  }

  logger.info('[Redis] Connecting...', {
    host: env.REDIS.HOST,
    port: env.REDIS.PORT,
    db:   env.REDIS.DB,
    tls:  env.REDIS.TLS,
  });

  // ── Build connection URL ───────────────────────────────────────────────────

  const protocol = env.REDIS.TLS ? 'rediss' : 'redis';
  const auth     = env.REDIS.PASSWORD ? `:${env.REDIS.PASSWORD}@` : '';
  const url      = `${protocol}://${auth}${env.REDIS.HOST}:${env.REDIS.PORT}/${env.REDIS.DB}`;

  // ── Create client ──────────────────────────────────────────────────────────

  connectionState = 'connecting';

  client = redis.createClient({
    url,

    // Key prefix applied to every command automatically
    // Note: redis v4 supports `legacyMode` and `commandOptions` but
    //       key prefix is best handled manually in sub-modules (more explicit)

    socket: {
      connectTimeout: env.REDIS.CONNECT_TIMEOUT_MS,
      reconnectStrategy: (retries) => {
        reconnectCount = retries;

        if (retries >= MAX_RECONNECT_ATTEMPTS) {
          logger.error(
            `[Redis] Max reconnect attempts (${MAX_RECONNECT_ATTEMPTS}) reached. ` +
            `Stopping reconnection.`
          );
          // Return an Error to stop reconnecting
          return new Error('Redis max reconnect attempts exceeded');
        }

        // Exponential back-off: 200ms, 400ms, 800ms … capped at 10s
        const delay = Math.min(200 * Math.pow(2, retries), RECONNECT_STRATEGY_CAP);
        logger.warn(`[Redis] Reconnecting in ${delay}ms (attempt ${retries + 1}/${MAX_RECONNECT_ATTEMPTS})`);
        return delay;
      },
    },

    commandsQueueMaxLength: 500,
  });

  // ── Event listeners ───────────────────────────────────────────────────────

  client.on('ready', () => {
    connectionState = 'connected';
    reconnectCount  = 0;
    logger.info('[Redis] Connected and ready.');
  });

  client.on('error', (err) => {
    connectionState = 'error';
    logger.error(`[Redis] Client error — ${err.message}`);
  });

  client.on('reconnecting', () => {
    connectionState = 'connecting';
    logger.warn(`[Redis] Reconnecting... (attempt ${reconnectCount + 1})`);
  });

  client.on('end', () => {
    connectionState = 'disconnected';
    logger.info('[Redis] Connection closed.');
  });

  // ── Connect ───────────────────────────────────────────────────────────────

  try {
    await client.connect();
  } catch (err) {
    connectionState = 'error';
    logger.fatal(`[Redis] Failed to connect — ${err.message}`, {
      host: env.REDIS.HOST,
      port: env.REDIS.PORT,
    });
    throw err;
  }
}

// ─── disconnectRedis ──────────────────────────────────────────────────────────

/**
 * Gracefully disconnects the Redis client.
 * Call during SIGTERM/SIGINT shutdown handlers.
 *
 * @returns {Promise<void>}
 */
async function disconnectRedis() {
  if (!client || connectionState === 'disconnected') {
    return;
  }

  try {
    await client.quit();
    client          = null;
    connectionState = 'disconnected';
    logger.info('[Redis] Disconnected gracefully.');
  } catch (err) {
    logger.error(`[Redis] Error during disconnect — ${err.message}`);
    try {
      // Force disconnect if quit fails
      await client.disconnect();
    } catch {
      // Ignore
    }
    client          = null;
    connectionState = 'disconnected';
  }
}

// ─── getClient ────────────────────────────────────────────────────────────────

/**
 * Returns the active Redis client.
 *
 * Throws if the client is not connected — callers should catch and
 * fail gracefully (most operations can proceed without Redis, with
 * logging, except rate limiting).
 *
 * @returns {import('redis').RedisClientType}
 */
function getClient() {
  if (!client) {
    throw new Error('[Redis] Client is not initialised. Call connectRedis() first.');
  }
  if (connectionState !== 'connected') {
    throw new Error(`[Redis] Client is not ready (state: ${connectionState}).`);
  }
  return client;
}

// ─── isConnected ─────────────────────────────────────────────────────────────

/**
 * Returns true if the Redis client is connected and ready.
 *
 * @returns {boolean}
 */
function isConnected() {
  return client !== null && connectionState === 'connected';
}

// ─── healthCheck ─────────────────────────────────────────────────────────────

/**
 * Tests the Redis connection with a PING command.
 * Returns a status object — used by the /health endpoint.
 *
 * @returns {Promise<{ status: 'ok'|'error', latency_ms: number, error?: string }>}
 */
async function healthCheck() {
  const start = Date.now();

  if (!client || connectionState !== 'connected') {
    return {
      status:     'error',
      latency_ms: 0,
      error:      `Redis not connected (state: ${connectionState})`,
    };
  }

  try {
    const pong = await client.ping();
    if (pong !== 'PONG') throw new Error(`Unexpected PING response: ${pong}`);

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

// ─── Key Helpers ──────────────────────────────────────────────────────────────

/**
 * Builds a namespaced Redis key using the configured prefix.
 *
 * @param {...string} parts
 * @returns {string}
 *
 * @example
 *   buildKey('rl', 'auth_init', '1.2.3.4')
 *   // → 'ghosty:rl:auth_init:1.2.3.4'
 */
function buildKey(...parts) {
  return `${env.REDIS.KEY_PREFIX}${parts.join(':')}`;
}

/**
 * Safely runs a Redis command, returning null on error instead of throwing.
 * Use for non-critical operations (e.g. logging, optional caching).
 *
 * @param {Function} fn   — async function that uses the client
 * @returns {Promise<*>}
 */
async function safeRun(fn) {
  try {
    const c = getClient();
    return await fn(c);
  } catch (err) {
    logger.error(`[Redis] safeRun failed — ${err.message}`);
    return null;
  }
}

/**
 * Sets a key with an expiry (seconds).
 * Shorthand wrapper used by token blacklist and rate limiter.
 *
 * @param {string} key
 * @param {string} value
 * @param {number} ttlSecs
 * @returns {Promise<boolean>}
 */
async function setEx(key, value, ttlSecs) {
  try {
    const c = getClient();
    await c.set(key, String(value), { EX: ttlSecs });
    return true;
  } catch (err) {
    logger.error(`[Redis] setEx failed — key=${key} ${err.message}`);
    return false;
  }
}

/**
 * Gets a key value. Returns null if not found or on error.
 *
 * @param {string} key
 * @returns {Promise<string|null>}
 */
async function get(key) {
  try {
    const c = getClient();
    return await c.get(key);
  } catch (err) {
    logger.error(`[Redis] get failed — key=${key} ${err.message}`);
    return null;
  }
}

/**
 * Deletes a key. Returns false on error.
 *
 * @param {string} key
 * @returns {Promise<boolean>}
 */
async function del(key) {
  try {
    const c = getClient();
    await c.del(key);
    return true;
  } catch (err) {
    logger.error(`[Redis] del failed — key=${key} ${err.message}`);
    return false;
  }
}

// ─── Exports ──────────────────────────────────────────────────────────────────

module.exports = {
  connectRedis,
  disconnectRedis,
  getClient,
  isConnected,
  healthCheck,
  buildKey,
  safeRun,
  setEx,
  get,
  del,
};
