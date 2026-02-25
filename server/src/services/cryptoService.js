'use strict';

/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║             GHOSTY Auth — cryptoService.js                  ║
 * ║      HMAC signing, hashing, response signing, utilities     ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * All cryptographic primitives used across the system live here.
 * Nothing in this file does I/O — pure functions only.
 *
 * Exports:
 *   signResponse(success, message, data, secret)  → signed API response object
 *   verifyResponseSignature(sig, ts, data, secret) → boolean
 *   computeHMAC(secret, message)                  → hex string
 *   safeCompare(a, b)                             → boolean (constant-time)
 *   hashSHA256(input)                             → hex string
 *   hashSHA512(input)                             → hex string
 *   generateSecret(bytes)                         → hex string
 *   generateUUID()                                → UUID v4 string
 *   encryptAES(plaintext, key)                    → { iv, tag, ciphertext } hex strings
 *   decryptAES(iv, tag, ciphertext, key)          → plaintext string
 *   isValidHex(str, expectedLen)                  → boolean
 *   isValidUUID(str)                              → boolean
 */

const crypto = require('crypto');

// ─── Constants ────────────────────────────────────────────────────────────────

const HMAC_ALGO      = 'sha256';
const SHA256_HEX_LEN = 64;
const UUID_REGEX     = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX_REGEX      = /^[0-9a-f]+$/i;

// AES-256-GCM key must be exactly 32 bytes
const AES_KEY_LEN    = 32;
const AES_IV_LEN     = 16;
const AES_TAG_LEN    = 16;

// ─── Response Signing ─────────────────────────────────────────────────────────

/**
 * Builds and signs a standard API response object.
 *
 * The signature covers: `${timestamp}:${JSON.stringify(data)}`
 * Clients MUST verify this before trusting any field in `data`.
 *
 * @param {boolean} success
 * @param {string}  message
 * @param {*}       data       — any JSON-serialisable value
 * @param {string}  secret     — the application's HMAC secret (hex string)
 * @returns {object}           — full response body ready to send
 */
function signResponse(success, message, data, secret) {
  const timestamp = Date.now();
  const dataJson  = JSON.stringify(data ?? null);
  const sigInput  = `${timestamp}:${dataJson}`;
  const signature = computeHMAC(secret, sigInput);

  return {
    success,
    message,
    data,
    timestamp,
    signature,
  };
}

/**
 * Verifies the HMAC signature on an API response.
 * Used by controllers to verify their own outgoing data (self-test)
 * and by the request verifier for inbound responses in test contexts.
 *
 * @param {string} signature  — hex HMAC from the response
 * @param {number} timestamp  — Unix ms timestamp from the response
 * @param {*}      data       — the `data` field from the response
 * @param {string} secret     — the application's HMAC secret
 * @returns {boolean}
 */
function verifyResponseSignature(signature, timestamp, data, secret) {
  if (!signature || !timestamp || !secret) return false;

  const dataJson  = JSON.stringify(data ?? null);
  const sigInput  = `${timestamp}:${dataJson}`;
  const expected  = computeHMAC(secret, sigInput);

  return safeCompare(expected, signature);
}

// ─── HMAC ─────────────────────────────────────────────────────────────────────

/**
 * Computes HMAC-SHA256 of `message` using `secret`.
 *
 * @param {string|Buffer} secret
 * @param {string}        message
 * @returns {string}  lowercase hex
 */
function computeHMAC(secret, message) {
  if (!secret) throw new Error('[cryptoService] computeHMAC: secret is required.');
  if (typeof message !== 'string') throw new Error('[cryptoService] computeHMAC: message must be a string.');

  return crypto
    .createHmac(HMAC_ALGO, secret)
    .update(message, 'utf8')
    .digest('hex');
}

/**
 * Compute HMAC-SHA256 for a request signature.
 * Convention: HMAC(secret, appId:licenseKey:hwid:timestamp)
 *
 * @param {string} secret
 * @param {string} appId
 * @param {string} licenseKey   — should already be uppercased
 * @param {string} hwid         — SHA-256 hex
 * @param {number} timestamp    — Unix ms
 * @returns {string}  lowercase hex
 */
function computeRequestHMAC(secret, appId, licenseKey, hwid, timestamp) {
  const message = `${appId}:${licenseKey}:${hwid}:${timestamp}`;
  return computeHMAC(secret, message);
}

// ─── Constant-time Comparison ─────────────────────────────────────────────────

/**
 * Compares two strings in constant time.
 * Prevents timing oracle attacks against HMAC comparisons.
 *
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function safeCompare(a, b) {
  try {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    if (a.length !== b.length) return false;

    return crypto.timingSafeEqual(
      Buffer.from(a, 'hex'),
      Buffer.from(b, 'hex')
    );
  } catch {
    // Catches invalid hex or length mismatch inside Buffer.from
    return false;
  }
}

/**
 * String-safe constant-time compare for arbitrary strings (not just hex).
 * Uses Buffer.from with utf8 encoding.
 *
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function safeCompareStrings(a, b) {
  try {
    if (typeof a !== 'string' || typeof b !== 'string') return false;

    const bufA = Buffer.from(a, 'utf8');
    const bufB = Buffer.from(b, 'utf8');

    if (bufA.length !== bufB.length) return false;

    return crypto.timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
}

// ─── Hashing ──────────────────────────────────────────────────────────────────

/**
 * Computes SHA-256 hash of a string.
 *
 * @param {string|Buffer} input
 * @returns {string}  lowercase hex (64 chars)
 */
function hashSHA256(input) {
  return crypto
    .createHash('sha256')
    .update(input)
    .digest('hex');
}

/**
 * Computes SHA-512 hash of a string.
 *
 * @param {string|Buffer} input
 * @returns {string}  lowercase hex (128 chars)
 */
function hashSHA512(input) {
  return crypto
    .createHash('sha512')
    .update(input)
    .digest('hex');
}

/**
 * Computes a SHA-256 hash of a file buffer.
 * Used for executable integrity checks.
 *
 * @param {Buffer} buffer
 * @returns {string}  lowercase hex
 */
function hashBuffer(buffer) {
  if (!Buffer.isBuffer(buffer)) {
    throw new Error('[cryptoService] hashBuffer: input must be a Buffer.');
  }
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

// ─── Secure Random Generation ─────────────────────────────────────────────────

/**
 * Generates a cryptographically secure random hex string.
 *
 * @param {number} bytes  — number of random bytes (output is 2x this length)
 * @returns {string}  lowercase hex
 */
function generateSecret(bytes = 32) {
  if (bytes < 16) throw new Error('[cryptoService] generateSecret: minimum 16 bytes required.');
  return crypto.randomBytes(bytes).toString('hex');
}

/**
 * Generates a cryptographically secure random UUID v4.
 *
 * @returns {string}  UUID v4 string
 */
function generateUUID() {
  return crypto.randomUUID();
}

/**
 * Generates a secure random integer in [min, max] inclusive.
 * Uses crypto.randomInt — cryptographically secure, no modulo bias.
 *
 * @param {number} min
 * @param {number} max
 * @returns {number}
 */
function secureRandomInt(min, max) {
  if (min >= max) throw new Error('[cryptoService] secureRandomInt: min must be less than max.');
  return crypto.randomInt(min, max + 1);
}

// ─── AES-256-GCM Encryption ───────────────────────────────────────────────────

/**
 * Encrypts plaintext using AES-256-GCM.
 * Returns IV, auth tag, and ciphertext as hex strings.
 *
 * Use case: encrypting sensitive fields before storing in DB
 * (e.g. storing HWID in encrypted form for extra protection).
 *
 * @param {string} plaintext
 * @param {string} keyHex     — 32-byte key as 64-char hex string
 * @returns {{ iv: string, tag: string, ciphertext: string }}
 */
function encryptAES(plaintext, keyHex) {
  _validateAESKey(keyHex);

  const key    = Buffer.from(keyHex, 'hex');
  const iv     = crypto.randomBytes(AES_IV_LEN);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);

  const tag = cipher.getAuthTag();

  return {
    iv:         iv.toString('hex'),
    tag:        tag.toString('hex'),
    ciphertext: encrypted.toString('hex'),
  };
}

/**
 * Decrypts AES-256-GCM ciphertext.
 * Throws if the auth tag fails (tamper detection).
 *
 * @param {string} ivHex
 * @param {string} tagHex
 * @param {string} ciphertextHex
 * @param {string} keyHex         — 32-byte key as 64-char hex string
 * @returns {string}  plaintext
 */
function decryptAES(ivHex, tagHex, ciphertextHex, keyHex) {
  _validateAESKey(keyHex);

  const key      = Buffer.from(keyHex, 'hex');
  const iv       = Buffer.from(ivHex, 'hex');
  const tag      = Buffer.from(tagHex, 'hex');
  const data     = Buffer.from(ciphertextHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);

  decipher.setAuthTag(tag);

  try {
    return Buffer.concat([
      decipher.update(data),
      decipher.final(),
    ]).toString('utf8');
  } catch {
    throw new Error('[cryptoService] decryptAES: Decryption failed — data may be tampered.');
  }
}

// ─── Validators ───────────────────────────────────────────────────────────────

/**
 * Returns true if `str` is a valid lowercase hex string of `expectedLen` chars.
 *
 * @param {string} str
 * @param {number} [expectedLen]  — if omitted, only checks format
 * @returns {boolean}
 */
function isValidHex(str, expectedLen) {
  if (typeof str !== 'string') return false;
  if (!HEX_REGEX.test(str))   return false;
  if (expectedLen !== undefined && str.length !== expectedLen) return false;
  return true;
}

/**
 * Returns true if `str` is a valid UUID v4.
 *
 * @param {string} str
 * @returns {boolean}
 */
function isValidUUID(str) {
  return typeof str === 'string' && UUID_REGEX.test(str);
}

/**
 * Returns true if `str` is a valid HMAC-SHA256 hex string (64 chars).
 *
 * @param {string} str
 * @returns {boolean}
 */
function isValidHMACHex(str) {
  return isValidHex(str, SHA256_HEX_LEN);
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

function _validateAESKey(keyHex) {
  if (!isValidHex(keyHex, AES_KEY_LEN * 2)) {
    throw new Error(`[cryptoService] AES key must be a ${AES_KEY_LEN * 2}-char hex string (${AES_KEY_LEN} bytes).`);
  }
}

// ─── Exports ──────────────────────────────────────────────────────────────────

module.exports = {
  // Response signing
  signResponse,
  verifyResponseSignature,

  // HMAC
  computeHMAC,
  computeRequestHMAC,

  // Comparison
  safeCompare,
  safeCompareStrings,

  // Hashing
  hashSHA256,
  hashSHA512,
  hashBuffer,

  // Random generation
  generateSecret,
  generateUUID,
  secureRandomInt,

  // AES-256-GCM
  encryptAES,
  decryptAES,

  // Validators
  isValidHex,
  isValidUUID,
  isValidHMACHex,
};
