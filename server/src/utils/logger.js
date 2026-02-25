'use strict';

/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║               GHOSTY Auth — logger.js                       ║
 * ║         Structured, levelled, production-ready logger       ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * Features:
 *   - Five log levels: debug | info | warn | error | fatal
 *   - Development: coloured, human-readable console output
 *   - Production:  structured JSON per line (stdout) — ready for
 *                  log aggregators (Datadog, Loki, CloudWatch, etc.)
 *   - Automatic PII scrubbing before any log is written
 *   - Sensitive field redaction (passwords, tokens, secrets, HWIDs)
 *   - Request context helpers (requestLogger middleware)
 *   - Synchronous fatal logging before process.exit
 *
 * Usage:
 *   const logger = require('../utils/logger');
 *
 *   logger.info('Server started on port 3000');
 *   logger.warn('[AUTH] suspicious request', { ip: '1.2.3.4' });
 *   logger.error('[DB] query failed', { stack: err.stack });
 *   logger.debug('[KEYS] generated batch', { qty: 50 });
 *   logger.fatal('[PROCESS] unhandled rejection — shutting down');
 */

const os   = require('os');
const path = require('path');

// ─── Config ───────────────────────────────────────────────────────────────────

const ENV         = process.env.NODE_ENV || 'development';
const IS_PROD     = ENV === 'production';
const IS_TEST     = ENV === 'test';
const LOG_LEVEL   = (process.env.LOG_LEVEL || (IS_PROD ? 'info' : 'debug')).toLowerCase();
const SERVICE     = process.env.npm_package_name || 'ghosty-auth';
const VERSION     = process.env.npm_package_version || '1.0.0';
const HOSTNAME    = os.hostname();

// ─── Log Levels ───────────────────────────────────────────────────────────────

const LEVELS = Object.freeze({
  debug: 10,
  info:  20,
  warn:  30,
  error: 40,
  fatal: 50,
});

const LEVEL_NAMES = Object.freeze(
  Object.fromEntries(Object.entries(LEVELS).map(([k, v]) => [v, k]))
);

const CONFIGURED_LEVEL = LEVELS[LOG_LEVEL] ?? LEVELS.info;

// ─── ANSI Colours (dev only) ──────────────────────────────────────────────────

const COLOURS = Object.freeze({
  reset:  '\x1b[0m',
  bold:   '\x1b[1m',
  dim:    '\x1b[2m',
  debug:  '\x1b[36m',   // cyan
  info:   '\x1b[32m',   // green
  warn:   '\x1b[33m',   // yellow
  error:  '\x1b[31m',   // red
  fatal:  '\x1b[35m',   // magenta
  grey:   '\x1b[90m',
  white:  '\x1b[97m',
});

// ─── PII / Sensitive Field Scrubbing ──────────────────────────────────────────

/**
 * Field names whose values are always redacted in log output.
 * Case-insensitive matching is applied.
 */
const SENSITIVE_FIELDS = new Set([
  'password',
  'password_hash',
  'new_password',
  'current_password',
  'secret',
  'app_secret',
  'token',
  'access_token',
  'refresh_token',
  'authorization',
  'request_signature',
  'hwid',              // HWID hashes are PII — mask in logs
  'ban_reason',        // May contain personal info
  'email',             // Scrub from deep log payloads
  'registration_key',
  'jwt_private_key',
  'jwt_public_key',
  'hmac_secret',
  'db_password',
  'redis_password',
]);

const REDACTED = '[REDACTED]';

/**
 * Recursively scrubs sensitive fields from an object before logging.
 * Handles nested objects and arrays.
 * Makes a shallow clone — does NOT mutate the original object.
 *
 * @param {*}      value
 * @param {number} [depth=0]   — prevents infinite recursion on circular refs
 * @returns {*}
 */
function scrub(value, depth = 0) {
  if (depth > 6) return '[DEEP_OBJECT]';
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return value;

  if (Array.isArray(value)) {
    return value.slice(0, 20).map(item => scrub(item, depth + 1));
  }

  if (value instanceof Error) {
    return {
      name:    value.name,
      message: value.message,
      code:    value.code,
      // Only include stack in non-prod or error level
      ...((!IS_PROD || depth === 0) && value.stack
        ? { stack: value.stack.split('\n').slice(0, 8).join('\n') }
        : {}),
    };
  }

  if (typeof value === 'object') {
    const result = {};
    for (const [key, val] of Object.entries(value)) {
      if (SENSITIVE_FIELDS.has(key.toLowerCase())) {
        result[key] = REDACTED;
      } else {
        result[key] = scrub(val, depth + 1);
      }
    }
    return result;
  }

  return String(value);
}

// ─── Timestamp ────────────────────────────────────────────────────────────────

function iso() {
  return new Date().toISOString();
}

// ─── Formatters ───────────────────────────────────────────────────────────────

/**
 * Development formatter — coloured, single-line, human-readable.
 */
function formatDev(level, message, meta) {
  const colour    = COLOURS[level] || COLOURS.white;
  const time      = `${COLOURS.grey}${iso()}${COLOURS.reset}`;
  const levelTag  = `${colour}${COLOURS.bold}[${level.toUpperCase().padEnd(5)}]${COLOURS.reset}`;
  const msg       = `${COLOURS.white}${message}${COLOURS.reset}`;

  let line = `${time} ${levelTag} ${msg}`;

  if (meta && typeof meta === 'object' && Object.keys(meta).length > 0) {
    const scrubbed = scrub(meta);
    const metaStr  = JSON.stringify(scrubbed, null, 0);

    // Keep meta inline if short, else on next line indented
    if (metaStr.length < 120) {
      line += `  ${COLOURS.dim}${metaStr}${COLOURS.reset}`;
    } else {
      line += `\n  ${COLOURS.dim}${JSON.stringify(scrubbed, null, 2).replace(/\n/g, '\n  ')}${COLOURS.reset}`;
    }
  }

  return line;
}

/**
 * Production formatter — newline-delimited JSON (NDJSON).
 * Each log entry is one complete JSON object per line.
 */
function formatProd(level, message, meta) {
  const entry = {
    ts:      iso(),
    level,
    service: SERVICE,
    version: VERSION,
    host:    HOSTNAME,
    pid:     process.pid,
    msg:     message,
  };

  if (meta && typeof meta === 'object' && Object.keys(meta).length > 0) {
    entry.meta = scrub(meta);
  }

  return JSON.stringify(entry);
}

// ─── Core Write ───────────────────────────────────────────────────────────────

/**
 * Writes a log entry to the appropriate stream.
 * error and fatal → stderr, everything else → stdout.
 *
 * @param {string} level
 * @param {string} message
 * @param {object} [meta]
 */
function write(level, message, meta) {
  // Suppress all logs in test mode (override with LOG_LEVEL=debug in tests)
  if (IS_TEST && CONFIGURED_LEVEL > LEVELS.warn) return;

  // Level filter
  if (LEVELS[level] < CONFIGURED_LEVEL) return;

  const line = IS_PROD
    ? formatProd(level, message, meta)
    : formatDev(level, message, meta);

  const stream = (level === 'error' || level === 'fatal')
    ? process.stderr
    : process.stdout;

  stream.write(line + '\n');
}

// ─── Public Logger Interface ──────────────────────────────────────────────────

const logger = {
  /**
   * Verbose debugging — only visible when LOG_LEVEL=debug.
   * Use for tracing internal logic during development.
   */
  debug(message, meta) {
    write('debug', message, meta);
  },

  /**
   * Normal operational events — server start, auth success, key generated.
   */
  info(message, meta) {
    write('info', message, meta);
  },

  /**
   * Recoverable anomalies — rate limit hit, invalid signature, stale timestamp.
   */
  warn(message, meta) {
    write('warn', message, meta);
  },

  /**
   * Errors that affect a single request but not the process.
   * DB query failures, unexpected exceptions.
   */
  error(message, meta) {
    write('error', message, meta);
  },

  /**
   * Critical failures — process is about to exit.
   * Synchronous write to stderr before shutdown.
   */
  fatal(message, meta) {
    // Fatal always writes regardless of configured level
    const line = IS_PROD
      ? formatProd('fatal', message, meta)
      : formatDev('fatal', message, meta);
    process.stderr.write(line + '\n');
  },

  // ── Structured helpers ─────────────────────────────────────────────────────

  /**
   * Logs an HTTP request completion.
   * Called by the routes/index.js request logger.
   */
  request(method, url, status, ms, ip) {
    const level = status >= 500 ? 'error'
                : status >= 400 ? 'warn'
                : 'info';

    write(level, `[HTTP] ${method} ${url} ${status} — ${ms}ms`, { ip, status, ms });
  },

  /**
   * Logs a database query (debug level, dev only).
   */
  query(sql, durationMs) {
    if (!IS_PROD) {
      write('debug', '[DB] query', {
        sql:    sql.slice(0, 200),
        dur_ms: durationMs,
      });
    }
  },

  /**
   * Logs an auth event (init, validate, logout).
   */
  auth(action, status, context = {}) {
    const level = status === 'success' ? 'info' : 'warn';
    write(level, `[AUTH] ${action} — ${status}`, context);
  },

  /**
   * Logs a security event (banned key attempt, invalid sig, etc.).
   * Always written at warn or higher — never filtered out.
   */
  security(event, context = {}) {
    write('warn', `[SECURITY] ${event}`, context);
  },

  // ── Express middleware ─────────────────────────────────────────────────────

  /**
   * Express middleware that logs every request on finish.
   * Attach via: app.use(logger.requestMiddleware)
   */
  requestMiddleware(req, res, next) {
    const start = Date.now();
    const ip    = (
      req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
      req.ip ||
      req.connection?.remoteAddress ||
      'unknown'
    );

    res.on('finish', () => {
      const ms     = Date.now() - start;
      const status = res.statusCode;
      const level  = status >= 500 ? 'error'
                   : status >= 400 ? 'warn'
                   : 'info';

      write(level, `[HTTP] ${req.method} ${req.originalUrl} ${status}`, {
        ms,
        ip,
        ua: req.headers['user-agent']?.slice(0, 100) || '',
      });
    });

    next();
  },

  // ── Child logger (namespaced) ──────────────────────────────────────────────

  /**
   * Creates a child logger that automatically prefixes every message.
   * Useful for isolating logs from a specific module.
   *
   * const log = logger.child('[keyService]');
   * log.info('Generated 50 keys');  →  "[keyService] Generated 50 keys"
   */
  child(namespace) {
    return {
      debug: (msg, meta) => write('debug', `${namespace} ${msg}`, meta),
      info:  (msg, meta) => write('info',  `${namespace} ${msg}`, meta),
      warn:  (msg, meta) => write('warn',  `${namespace} ${msg}`, meta),
      error: (msg, meta) => write('error', `${namespace} ${msg}`, meta),
      fatal: (msg, meta) => {
        const line = IS_PROD
          ? formatProd('fatal', `${namespace} ${msg}`, meta)
          : formatDev('fatal',  `${namespace} ${msg}`, meta);
        process.stderr.write(line + '\n');
      },
    };
  },
};

// ─── Process-Level Event Logging ──────────────────────────────────────────────
// Catch unhandled errors at the process level.
// These should never reach production but are critical to log if they do.

process.on('uncaughtException', (err) => {
  logger.fatal('[PROCESS] Uncaught exception — shutting down', {
    name:    err.name,
    message: err.message,
    stack:   err.stack,
  });
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  logger.fatal('[PROCESS] Unhandled promise rejection', {
    reason: reason instanceof Error
      ? { name: reason.name, message: reason.message, stack: reason.stack }
      : String(reason),
  });
  process.exit(1);
});

// ─── Export ───────────────────────────────────────────────────────────────────

module.exports = logger;
