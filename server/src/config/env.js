'use strict';

/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║               GHOSTY Auth — env.js                          ║
 * ║     Environment variable loader, validator, and parser      ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * This module MUST be the very first require() in server.js.
 * It loads .env, validates every required variable, and exports
 * a frozen config object used throughout the application.
 *
 * Fail-fast philosophy:
 *   If any required variable is missing or invalid, the process
 *   exits immediately with a clear error message rather than
 *   booting into a broken state.
 *
 * Usage:
 *   const env = require('./config/env');
 *   console.log(env.PORT);           // 3000
 *   console.log(env.DB.HOST);        // 'localhost'
 *   console.log(env.JWT.EXPIRES_IN); // '1h'
 */

const fs   = require('fs');
const path = require('path');

// ─── Load .env file ───────────────────────────────────────────────────────────

(function loadDotEnv() {
  const envPath = path.resolve(process.cwd(), '.env');

  if (!fs.existsSync(envPath)) {
    if (process.env.NODE_ENV === 'production') {
      // In production environment variables come from the host — .env is optional
      return;
    }
    console.warn('[env] Warning: .env file not found. Using process environment variables only.');
    return;
  }

  const raw     = fs.readFileSync(envPath, 'utf8');
  const lines   = raw.split('\n');
  let   loaded  = 0;

  for (const line of lines) {
    const trimmed = line.trim();

    // Skip empty lines and comments
    if (!trimmed || trimmed.startsWith('#')) continue;

    const eqIdx = trimmed.indexOf('=');
    if (eqIdx === -1) continue;

    const key   = trimmed.slice(0, eqIdx).trim();
    let   value = trimmed.slice(eqIdx + 1).trim();

    // Strip surrounding quotes (single or double)
    if ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }

    // Don't override existing process env vars
    // (allows docker/CI to override .env values)
    if (!(key in process.env)) {
      process.env[key] = value;
      loaded++;
    }
  }

  console.log(`[env] Loaded ${loaded} variable(s) from .env`);
})();

// ─── Validation Helpers ───────────────────────────────────────────────────────

const errors   = [];
const warnings = [];

/**
 * Reads a required string env var.
 * Registers an error if missing or empty.
 */
function required(key, description = '') {
  const value = process.env[key];
  if (!value || value.trim() === '') {
    errors.push(`  ✗ ${key} — required${description ? ` (${description})` : ''}`);
    return '';
  }
  return value.trim();
}

/**
 * Reads an optional string env var with a default fallback.
 */
function optional(key, defaultValue = '') {
  const value = process.env[key];
  return (value && value.trim()) ? value.trim() : defaultValue;
}

/**
 * Reads a required integer env var.
 */
function requiredInt(key, min = 0, max = Infinity) {
  const raw = process.env[key];
  if (!raw || raw.trim() === '') {
    errors.push(`  ✗ ${key} — required integer`);
    return 0;
  }
  const n = parseInt(raw.trim(), 10);
  if (isNaN(n)) {
    errors.push(`  ✗ ${key} — must be an integer (got: "${raw}")`);
    return 0;
  }
  if (n < min || n > max) {
    errors.push(`  ✗ ${key} — must be between ${min} and ${max} (got: ${n})`);
    return 0;
  }
  return n;
}

/**
 * Reads an optional integer env var with a default fallback.
 */
function optionalInt(key, defaultValue, min = 0, max = Infinity) {
  const raw = process.env[key];
  if (!raw || raw.trim() === '') return defaultValue;
  const n = parseInt(raw.trim(), 10);
  if (isNaN(n)) {
    warnings.push(`  ⚠ ${key} — invalid integer ("${raw}"), using default: ${defaultValue}`);
    return defaultValue;
  }
  if (n < min || n > max) {
    warnings.push(`  ⚠ ${key} — out of range [${min}–${max}] (got: ${n}), using default: ${defaultValue}`);
    return defaultValue;
  }
  return n;
}

/**
 * Reads an optional boolean env var.
 * Truthy values: 'true', '1', 'yes'
 */
function optionalBool(key, defaultValue = false) {
  const raw = process.env[key];
  if (!raw) return defaultValue;
  return ['true', '1', 'yes'].includes(raw.trim().toLowerCase());
}

/**
 * Reads a required env var and validates it against an allowed list.
 */
function requiredEnum(key, allowed, defaultValue) {
  const value = optional(key, defaultValue);
  if (!allowed.includes(value)) {
    errors.push(`  ✗ ${key} — must be one of [${allowed.join(', ')}] (got: "${value}")`);
    return defaultValue;
  }
  return value;
}

/**
 * Validates that a value looks like a PEM-encoded RSA key.
 */
function validatePEMKey(key, value, type = 'key') {
  if (!value || !value.includes('-----BEGIN')) {
    errors.push(`  ✗ ${key} — must be a valid PEM-encoded ${type}`);
    return false;
  }
  return true;
}

/**
 * Validates that a hex string has the expected byte length.
 */
function validateHexLen(key, value, expectedBytes) {
  const expectedLen = expectedBytes * 2;
  if (!value || value.length < expectedLen) {
    errors.push(
      `  ✗ ${key} — must be at least ${expectedLen} hex chars (${expectedBytes} bytes). ` +
      `Run: node -e "console.log(require('crypto').randomBytes(${expectedBytes}).toString('hex'))"`
    );
    return false;
  }
  if (!/^[0-9a-f]+$/i.test(value)) {
    errors.push(`  ✗ ${key} — must be a hexadecimal string`);
    return false;
  }
  return true;
}

// ─── Parse All Variables ──────────────────────────────────────────────────────

const NODE_ENV = requiredEnum(
  'NODE_ENV',
  ['development', 'production', 'test'],
  'development'
);

const IS_PROD = NODE_ENV === 'production';
const IS_TEST = NODE_ENV === 'test';
const IS_DEV  = NODE_ENV === 'development';

// ── Server ────────────────────────────────────────────────────────────────────

const PORT = optionalInt('PORT', 3000, 1, 65535);
const HOST = optional('HOST', '0.0.0.0');

// ── Database (PostgreSQL) ─────────────────────────────────────────────────────

const DB_HOST     = required('DB_HOST',     'PostgreSQL host');
const DB_PORT     = optionalInt('DB_PORT', 5432, 1, 65535);
const DB_NAME     = required('DB_NAME',     'PostgreSQL database name');
const DB_USER     = required('DB_USER',     'PostgreSQL username');
const DB_PASSWORD = required('DB_PASSWORD', 'PostgreSQL password');
const DB_SSL      = optionalBool('DB_SSL', IS_PROD);
const DB_POOL_MIN = optionalInt('DB_POOL_MIN', 2,  0, 20);
const DB_POOL_MAX = optionalInt('DB_POOL_MAX', 10, 1, 50);
const DB_POOL_ACQUIRE_MS = optionalInt('DB_POOL_ACQUIRE_MS', 30000, 1000, 120000);
const DB_POOL_IDLE_MS    = optionalInt('DB_POOL_IDLE_MS',    10000, 1000, 60000);
const DB_LOG_QUERIES     = optionalBool('DB_LOG_QUERIES', IS_DEV);

// ── Redis ─────────────────────────────────────────────────────────────────────

const REDIS_HOST     = required('REDIS_HOST',    'Redis host');
const REDIS_PORT     = optionalInt('REDIS_PORT', 6379, 1, 65535);
const REDIS_PASSWORD = optional('REDIS_PASSWORD', '');
const REDIS_DB       = optionalInt('REDIS_DB', 0, 0, 15);
const REDIS_TLS      = optionalBool('REDIS_TLS', IS_PROD);
const REDIS_KEY_PREFIX = optional('REDIS_KEY_PREFIX', 'ghosty:');
const REDIS_CONNECT_TIMEOUT_MS = optionalInt('REDIS_CONNECT_TIMEOUT_MS', 5000, 1000, 30000);
const REDIS_COMMAND_TIMEOUT_MS = optionalInt('REDIS_COMMAND_TIMEOUT_MS', 3000, 500,  15000);

// ── JWT (RS256) ───────────────────────────────────────────────────────────────

const JWT_PRIVATE_KEY_RAW = required('JWT_PRIVATE_KEY', 'RSA private key for JWT signing');
const JWT_PUBLIC_KEY_RAW  = required('JWT_PUBLIC_KEY',  'RSA public key for JWT verification');

// Unescape \n sequences stored in env vars
const JWT_PRIVATE_KEY = JWT_PRIVATE_KEY_RAW.replace(/\\n/g, '\n');
const JWT_PUBLIC_KEY  = JWT_PUBLIC_KEY_RAW.replace(/\\n/g, '\n');

// Validate PEM format
if (JWT_PRIVATE_KEY) validatePEMKey('JWT_PRIVATE_KEY', JWT_PRIVATE_KEY, 'RSA private key');
if (JWT_PUBLIC_KEY)  validatePEMKey('JWT_PUBLIC_KEY',  JWT_PUBLIC_KEY,  'RSA public key');

// TTL format: '1h' | '30m' | '7d' | '3600' (seconds)
const JWT_EXPIRES_IN = optional('JWT_EXPIRES_IN', '1h');
if (!/^\d+[smhd]?$/.test(JWT_EXPIRES_IN)) {
  errors.push(`  ✗ JWT_EXPIRES_IN — invalid format "${JWT_EXPIRES_IN}". Use: 1h, 30m, 7d, or seconds`);
}

// ── HMAC / Security ───────────────────────────────────────────────────────────

const HMAC_SECRET_RAW = required('HMAC_SECRET', 'HMAC signing secret (min 32 bytes hex)');
if (HMAC_SECRET_RAW) validateHexLen('HMAC_SECRET', HMAC_SECRET_RAW, 32);
const HMAC_SECRET = HMAC_SECRET_RAW;

const BCRYPT_ROUNDS = optionalInt('BCRYPT_ROUNDS', 12, 10, 20);

const REQUEST_TIMESTAMP_TOLERANCE_MS = optionalInt(
  'REQUEST_TIMESTAMP_TOLERANCE_MS',
  30000,    // 30 seconds
  5000,     // min 5 seconds
  300000    // max 5 minutes
);

// Warn if bcrypt rounds are too low for production
if (IS_PROD && BCRYPT_ROUNDS < 12) {
  warnings.push(`  ⚠ BCRYPT_ROUNDS=${BCRYPT_ROUNDS} — recommend ≥12 for production`);
}

// ── Rate Limiting ─────────────────────────────────────────────────────────────

const RATE_LIMIT_WINDOW_MS   = optionalInt('RATE_LIMIT_WINDOW_MS',   60000, 1000, 3600000);
const RATE_LIMIT_MAX_AUTH    = optionalInt('RATE_LIMIT_MAX_AUTH',    10,    1,    1000);
const RATE_LIMIT_MAX_KEYS    = optionalInt('RATE_LIMIT_MAX_KEYS',    30,    1,    1000);
const RATE_LIMIT_MAX_GENERAL = optionalInt('RATE_LIMIT_MAX_GENERAL', 100,   1,    5000);

// ── Admin ─────────────────────────────────────────────────────────────────────

const ADMIN_REGISTRATION_KEY = optional('ADMIN_REGISTRATION_KEY', '');
if (IS_PROD && !ADMIN_REGISTRATION_KEY) {
  warnings.push('  ⚠ ADMIN_REGISTRATION_KEY is not set — open registration is enabled in production');
}

// ── CORS ──────────────────────────────────────────────────────────────────────

const CORS_ORIGIN = optional('CORS_ORIGIN', IS_PROD ? '' : '*');
if (IS_PROD && (!CORS_ORIGIN || CORS_ORIGIN === '*')) {
  warnings.push('  ⚠ CORS_ORIGIN — using wildcard (*) in production is not recommended');
}

// ─── Print Warnings ───────────────────────────────────────────────────────────

if (warnings.length > 0) {
  console.warn('[env] Configuration warnings:');
  warnings.forEach(w => console.warn(w));
}

// ─── Fail Fast on Errors ──────────────────────────────────────────────────────

if (errors.length > 0) {
  console.error('\n╔══════════════════════════════════════════════════╗');
  console.error('║        GHOSTY Auth — Configuration Error         ║');
  console.error('╚══════════════════════════════════════════════════╝');
  console.error('\nThe following required environment variables are missing or invalid:\n');
  errors.forEach(e => console.error(e));
  console.error('\nCopy server/.env.example to server/.env and fill in all values.');
  console.error('See docs/setup.md for instructions.\n');
  process.exit(1);
}

// ─── Build Frozen Config Object ───────────────────────────────────────────────

const env = Object.freeze({
  // Runtime
  NODE_ENV,
  IS_PROD,
  IS_TEST,
  IS_DEV,

  // Server
  PORT,
  HOST,

  // PostgreSQL
  DB: Object.freeze({
    HOST:             DB_HOST,
    PORT:             DB_PORT,
    NAME:             DB_NAME,
    USER:             DB_USER,
    PASSWORD:         DB_PASSWORD,
    SSL:              DB_SSL,
    LOG_QUERIES:      DB_LOG_QUERIES,
    POOL: Object.freeze({
      MIN:        DB_POOL_MIN,
      MAX:        DB_POOL_MAX,
      ACQUIRE_MS: DB_POOL_ACQUIRE_MS,
      IDLE_MS:    DB_POOL_IDLE_MS,
    }),
  }),

  // Redis
  REDIS: Object.freeze({
    HOST:               REDIS_HOST,
    PORT:               REDIS_PORT,
    PASSWORD:           REDIS_PASSWORD,
    DB:                 REDIS_DB,
    TLS:                REDIS_TLS,
    KEY_PREFIX:         REDIS_KEY_PREFIX,
    CONNECT_TIMEOUT_MS: REDIS_CONNECT_TIMEOUT_MS,
    COMMAND_TIMEOUT_MS: REDIS_COMMAND_TIMEOUT_MS,
  }),

  // JWT
  JWT: Object.freeze({
    PRIVATE_KEY: JWT_PRIVATE_KEY,
    PUBLIC_KEY:  JWT_PUBLIC_KEY,
    EXPIRES_IN:  JWT_EXPIRES_IN,
  }),

  // Security
  SECURITY: Object.freeze({
    HMAC_SECRET:                  HMAC_SECRET,
    BCRYPT_ROUNDS:                BCRYPT_ROUNDS,
    REQUEST_TIMESTAMP_TOLERANCE:  REQUEST_TIMESTAMP_TOLERANCE_MS,
  }),

  // Rate limiting
  RATE_LIMIT: Object.freeze({
    WINDOW_MS:   RATE_LIMIT_WINDOW_MS,
    MAX_AUTH:    RATE_LIMIT_MAX_AUTH,
    MAX_KEYS:    RATE_LIMIT_MAX_KEYS,
    MAX_GENERAL: RATE_LIMIT_MAX_GENERAL,
  }),

  // Admin
  ADMIN: Object.freeze({
    REGISTRATION_KEY: ADMIN_REGISTRATION_KEY,
  }),

  // CORS
  CORS_ORIGIN,
});

module.exports = env;
