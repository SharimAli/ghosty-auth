'use strict';

/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║              GHOSTY Auth — keyController.js                 ║
 * ║    Handles key generation, listing, banning, HWID reset     ║
 * ╚══════════════════════════════════════════════════════════════╝
 */

const { Op }      = require('sequelize');
const License     = require('../models/License');
const Application = require('../models/Application');
const Log         = require('../models/Log');
const { generateLicenseKey } = require('../services/keyService');
const { ok, fail }           = require('../utils/response');
const logger                 = require('../utils/logger');

// ─── Constants ────────────────────────────────────────────────────────────────

const MAX_KEYS_PER_REQUEST  = 100;
const DEFAULT_PAGE_SIZE     = 50;
const MAX_PAGE_SIZE         = 100;

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Verifies the authenticated seller owns the requested application.
 */
async function assertAppOwnership(appId, sellerId) {
  const app = await Application.findOne({
    where: { id: appId, owner_id: sellerId },
  });
  return app || null;
}

/**
 * Parses and clamps pagination params from query string.
 */
function parsePagination(query) {
  const page  = Math.max(1, parseInt(query.page  || '1',  10));
  const limit = Math.min(MAX_PAGE_SIZE, Math.max(1, parseInt(query.limit || String(DEFAULT_PAGE_SIZE), 10)));
  const offset = (page - 1) * limit;
  return { page, limit, offset };
}

// ─────────────────────────────────────────────────────────────────────────────
//  POST /keys/generate
//  Generate one or more license keys for an application.
// ─────────────────────────────────────────────────────────────────────────────

exports.generate = async (req, res) => {
  const sellerId = req.user.id;
  const {
    app_id,
    quantity       = 1,
    expires_in_days,
    note           = '',
  } = req.body;

  // ── 1. Input validation ───────────────────────────────────────────────────
  if (!app_id) {
    return res.status(400).json(fail('MISSING_FIELDS', 'app_id is required.'));
  }

  const qty = parseInt(quantity, 10);
  if (isNaN(qty) || qty < 1 || qty > MAX_KEYS_PER_REQUEST) {
    return res.status(400).json(fail('INVALID_QUANTITY', `quantity must be between 1 and ${MAX_KEYS_PER_REQUEST}.`));
  }

  if (expires_in_days !== undefined) {
    const days = parseInt(expires_in_days, 10);
    if (isNaN(days) || days < 1 || days > 36500) {
      return res.status(400).json(fail('INVALID_EXPIRY', 'expires_in_days must be between 1 and 36500.'));
    }
  }

  try {
    // ── 2. Verify app ownership ───────────────────────────────────────────
    const app = await assertAppOwnership(app_id, sellerId);
    if (!app) {
      return res.status(403).json(fail('FORBIDDEN', 'Application not found or access denied.'));
    }

    // ── 3. Compute expiry date ────────────────────────────────────────────
    let expiresAt = null;
    if (expires_in_days) {
      const days = parseInt(expires_in_days, 10);
      expiresAt  = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
    }

    // ── 4. Generate keys ──────────────────────────────────────────────────
    const keys = [];
    for (let i = 0; i < qty; i++) {
      const keyStr = generateLicenseKey();

      const license = await License.create({
        key:        keyStr,
        app_id,
        created_by: sellerId,
        expires_at: expiresAt,
        note:       note.slice(0, 255),
      });

      keys.push({
        id:         license.id,
        key:        license.key,
        expires_at: license.expires_at ? license.expires_at.toISOString() : null,
        created_at: license.createdAt.toISOString(),
        note:       license.note,
      });
    }

    logger.info(`[KEYS] generated ${qty} key(s) — app=${app_id} seller=${sellerId}`);

    return res.status(201).json({
      success: true,
      message: `${qty} key${qty > 1 ? 's' : ''} generated successfully.`,
      data:    { keys },
    });

  } catch (err) {
    logger.error(`[KEYS] generate error — ${err.message}`, { stack: err.stack });
    return res.status(500).json(fail('SERVER_ERROR', 'An internal error occurred.'));
  }
};

// ─────────────────────────────────────────────────────────────────────────────
//  GET /keys
//  List all keys for an application with filtering and pagination.
// ─────────────────────────────────────────────────────────────────────────────

exports.list = async (req, res) => {
  const sellerId = req.user.id;
  const { app_id, status, search } = req.query;
  const { page, limit, offset } = parsePagination(req.query);

  if (!app_id) {
    return res.status(400).json(fail('MISSING_FIELDS', 'app_id query parameter is required.'));
  }

  try {
    // ── 1. Verify app ownership ───────────────────────────────────────────
    const app = await assertAppOwnership(app_id, sellerId);
    if (!app) {
      return res.status(403).json(fail('FORBIDDEN', 'Application not found or access denied.'));
    }

    // ── 2. Build filter ───────────────────────────────────────────────────
    const where = { app_id };
    const now   = new Date();

    if (status === 'active') {
      where.is_banned = false;
      where[Op.or] = [
        { expires_at: null },
        { expires_at: { [Op.gt]: now } },
      ];
    } else if (status === 'expired') {
      where.is_banned  = false;
      where.expires_at = { [Op.lte]: now };
    } else if (status === 'banned') {
      where.is_banned = true;
    }

    if (search) {
      // Safely filter by partial key match (sanitised — no raw SQL)
      where.key = { [Op.like]: `%${search.replace(/[%_]/g, '\\$&').toUpperCase()}%` };
    }

    // ── 3. Query ──────────────────────────────────────────────────────────
    const { count, rows } = await License.findAndCountAll({
      where,
      limit,
      offset,
      order: [['createdAt', 'DESC']],
      attributes: [
        'id', 'key', 'is_banned', 'ban_reason',
        'expires_at', 'hwid', 'username', 'email',
        'note', 'first_used_at', 'last_used_at',
        'last_used_ip', 'createdAt',
      ],
    });

    const totalPages = Math.ceil(count / limit);

    return res.status(200).json({
      success: true,
      data: {
        keys:        rows,
        pagination: {
          total:       count,
          page,
          limit,
          total_pages: totalPages,
          has_next:    page < totalPages,
          has_prev:    page > 1,
        },
      },
    });

  } catch (err) {
    logger.error(`[KEYS] list error — ${err.message}`, { stack: err.stack });
    return res.status(500).json(fail('SERVER_ERROR', 'An internal error occurred.'));
  }
};

// ─────────────────────────────────────────────────────────────────────────────
//  GET /keys/:id
//  Get a single key's full details.
// ─────────────────────────────────────────────────────────────────────────────

exports.getOne = async (req, res) => {
  const sellerId = req.user.id;
  const { id }   = req.params;

  try {
    const license = await License.findByPk(id);
    if (!license) {
      return res.status(404).json(fail('NOT_FOUND', 'License key not found.'));
    }

    // Verify seller owns the app this key belongs to
    const app = await assertAppOwnership(license.app_id, sellerId);
    if (!app) {
      return res.status(403).json(fail('FORBIDDEN', 'Access denied.'));
    }

    return res.status(200).json({ success: true, data: { key: license } });

  } catch (err) {
    logger.error(`[KEYS] getOne error — ${err.message}`, { stack: err.stack });
    return res.status(500).json(fail('SERVER_ERROR', 'An internal error occurred.'));
  }
};

// ─────────────────────────────────────────────────────────────────────────────
//  POST /keys/ban
//  Ban a license key.
// ─────────────────────────────────────────────────────────────────────────────

exports.ban = async (req, res) => {
  const sellerId = req.user.id;
  const { key_id, reason = '' } = req.body;

  if (!key_id) {
    return res.status(400).json(fail('MISSING_FIELDS', 'key_id is required.'));
  }

  try {
    const license = await License.findByPk(key_id);
    if (!license) {
      return res.status(404).json(fail('NOT_FOUND', 'License key not found.'));
    }

    const app = await assertAppOwnership(license.app_id, sellerId);
    if (!app) {
      return res.status(403).json(fail('FORBIDDEN', 'Access denied.'));
    }

    if (license.is_banned) {
      return res.status(400).json(fail('ALREADY_BANNED', 'This key is already banned.'));
    }

    await license.update({
      is_banned:  true,
      ban_reason: reason.slice(0, 255),
      banned_at:  new Date(),
      banned_by:  sellerId,
    });

    await Log.create({
      action:     'KEY_BANNED',
      status:     'success',
      app_id:     license.app_id,
      license_id: license.id,
      license_key: license.key,
      performed_by: sellerId,
      note:       reason,
    });

    logger.info(`[KEYS] banned key=${license.key} by seller=${sellerId}`);

    return res.status(200).json({
      success: true,
      message: 'License key has been banned.',
      data:    { key_id: license.id, is_banned: true },
    });

  } catch (err) {
    logger.error(`[KEYS] ban error — ${err.message}`, { stack: err.stack });
    return res.status(500).json(fail('SERVER_ERROR', 'An internal error occurred.'));
  }
};

// ─────────────────────────────────────────────────────────────────────────────
//  POST /keys/unban
//  Unban a license key.
// ─────────────────────────────────────────────────────────────────────────────

exports.unban = async (req, res) => {
  const sellerId = req.user.id;
  const { key_id } = req.body;

  if (!key_id) {
    return res.status(400).json(fail('MISSING_FIELDS', 'key_id is required.'));
  }

  try {
    const license = await License.findByPk(key_id);
    if (!license) {
      return res.status(404).json(fail('NOT_FOUND', 'License key not found.'));
    }

    const app = await assertAppOwnership(license.app_id, sellerId);
    if (!app) {
      return res.status(403).json(fail('FORBIDDEN', 'Access denied.'));
    }

    if (!license.is_banned) {
      return res.status(400).json(fail('NOT_BANNED', 'This key is not currently banned.'));
    }

    await license.update({
      is_banned:  false,
      ban_reason: null,
      banned_at:  null,
      banned_by:  null,
    });

    logger.info(`[KEYS] unbanned key=${license.key} by seller=${sellerId}`);

    return res.status(200).json({
      success: true,
      message: 'License key has been unbanned.',
      data:    { key_id: license.id, is_banned: false },
    });

  } catch (err) {
    logger.error(`[KEYS] unban error — ${err.message}`, { stack: err.stack });
    return res.status(500).json(fail('SERVER_ERROR', 'An internal error occurred.'));
  }
};

// ─────────────────────────────────────────────────────────────────────────────
//  POST /keys/reset-hwid
//  Reset the HWID binding for a key (allows use on a new machine).
// ─────────────────────────────────────────────────────────────────────────────

exports.resetHwid = async (req, res) => {
  const sellerId = req.user.id;
  const { key_id } = req.body;

  if (!key_id) {
    return res.status(400).json(fail('MISSING_FIELDS', 'key_id is required.'));
  }

  try {
    const license = await License.findByPk(key_id);
    if (!license) {
      return res.status(404).json(fail('NOT_FOUND', 'License key not found.'));
    }

    const app = await assertAppOwnership(license.app_id, sellerId);
    if (!app) {
      return res.status(403).json(fail('FORBIDDEN', 'Access denied.'));
    }

    const previousHwid = license.hwid;
    await license.update({ hwid: null });

    await Log.create({
      action:       'HWID_RESET',
      status:       'success',
      app_id:       license.app_id,
      license_id:   license.id,
      license_key:  license.key,
      performed_by: sellerId,
      note:         `Previous HWID: ${previousHwid || 'none'}`,
    });

    logger.info(`[KEYS] HWID reset — key=${license.key} by seller=${sellerId}`);

    return res.status(200).json({
      success: true,
      message: 'HWID binding has been reset. The key can now be used on a new device.',
      data:    { key_id: license.id },
    });

  } catch (err) {
    logger.error(`[KEYS] resetHwid error — ${err.message}`, { stack: err.stack });
    return res.status(500).json(fail('SERVER_ERROR', 'An internal error occurred.'));
  }
};

// ─────────────────────────────────────────────────────────────────────────────
//  POST /keys/extend
//  Extend the expiry date of a key by N days.
// ─────────────────────────────────────────────────────────────────────────────

exports.extend = async (req, res) => {
  const sellerId = req.user.id;
  const { key_id, days } = req.body;

  if (!key_id || !days) {
    return res.status(400).json(fail('MISSING_FIELDS', 'key_id and days are required.'));
  }

  const daysNum = parseInt(days, 10);
  if (isNaN(daysNum) || daysNum < 1 || daysNum > 36500) {
    return res.status(400).json(fail('INVALID_VALUE', 'days must be between 1 and 36500.'));
  }

  try {
    const license = await License.findByPk(key_id);
    if (!license) {
      return res.status(404).json(fail('NOT_FOUND', 'License key not found.'));
    }

    const app = await assertAppOwnership(license.app_id, sellerId);
    if (!app) {
      return res.status(403).json(fail('FORBIDDEN', 'Access denied.'));
    }

    // Extend from current expiry if not expired, or from now if already expired / no expiry
    const base       = license.expires_at && license.expires_at > new Date()
      ? new Date(license.expires_at)
      : new Date();
    const newExpiry  = new Date(base.getTime() + daysNum * 24 * 60 * 60 * 1000);

    await license.update({ expires_at: newExpiry });

    logger.info(`[KEYS] extended key=${license.key} by ${daysNum}d — seller=${sellerId}`);

    return res.status(200).json({
      success: true,
      message: `Key extended by ${daysNum} day${daysNum > 1 ? 's' : ''}.`,
      data: {
        key_id:     license.id,
        expires_at: newExpiry.toISOString(),
      },
    });

  } catch (err) {
    logger.error(`[KEYS] extend error — ${err.message}`, { stack: err.stack });
    return res.status(500).json(fail('SERVER_ERROR', 'An internal error occurred.'));
  }
};

// ─────────────────────────────────────────────────────────────────────────────
//  DELETE /keys/:id
//  Permanently delete a license key.
// ─────────────────────────────────────────────────────────────────────────────

exports.deleteKey = async (req, res) => {
  const sellerId = req.user.id;
  const { id }   = req.params;

  try {
    const license = await License.findByPk(id);
    if (!license) {
      return res.status(404).json(fail('NOT_FOUND', 'License key not found.'));
    }

    const app = await assertAppOwnership(license.app_id, sellerId);
    if (!app) {
      return res.status(403).json(fail('FORBIDDEN', 'Access denied.'));
    }

    await license.destroy();

    logger.info(`[KEYS] deleted key=${license.key} by seller=${sellerId}`);

    return res.status(200).json({
      success: true,
      message: 'License key permanently deleted.',
    });

  } catch (err) {
    logger.error(`[KEYS] delete error — ${err.message}`, { stack: err.stack });
    return res.status(500).json(fail('SERVER_ERROR', 'An internal error occurred.'));
  }
};
