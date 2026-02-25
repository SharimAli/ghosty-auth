'use strict';

/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║             GHOSTY Auth — adminController.js                ║
 * ║   Global admin actions: users, apps, keys, logs, stats      ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * All routes here require role === 'admin' (enforced in middleware).
 */

const bcrypt      = require('bcrypt');
const { Op }      = require('sequelize');
const sequelize   = require('../config/db');
const User        = require('../models/User');
const Application = require('../models/Application');
const License     = require('../models/License');
const Log         = require('../models/Log');
const { fail }    = require('../utils/response');
const logger      = require('../utils/logger');

// ─── Helpers ──────────────────────────────────────────────────────────────────

const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || '12', 10);

function parsePagination(query) {
  const page   = Math.max(1, parseInt(query.page  || '1',  10));
  const limit  = Math.min(100, Math.max(1, parseInt(query.limit || '50', 10)));
  const offset = (page - 1) * limit;
  return { page, limit, offset };
}

// ─────────────────────────────────────────────────────────────────────────────
//  GET /admin/stats
//  System-wide statistics dashboard data.
// ─────────────────────────────────────────────────────────────────────────────

exports.getStats = async (req, res) => {
  try {
    const [
      totalUsers,
      totalApps,
      totalKeys,
      activeKeys,
      bannedKeys,
      totalLogs,
      recentAuthCount,
    ] = await Promise.all([
      User.count(),
      Application.count(),
      License.count(),
      License.count({ where: { is_banned: false, [Op.or]: [{ expires_at: null }, { expires_at: { [Op.gt]: new Date() } }] } }),
      License.count({ where: { is_banned: true } }),
      Log.count(),
      // Auth attempts in the last 24 hours
      Log.count({
        where: {
          action:     'AUTH_INIT',
          createdAt: { [Op.gte]: new Date(Date.now() - 24 * 60 * 60 * 1000) },
        },
      }),
    ]);

    return res.status(200).json({
      success: true,
      data: {
        users: {
          total: totalUsers,
        },
        applications: {
          total: totalApps,
        },
        keys: {
          total:   totalKeys,
          active:  activeKeys,
          banned:  bannedKeys,
          expired: totalKeys - activeKeys - bannedKeys,
        },
        logs: {
          total:           totalLogs,
          auth_last_24h:   recentAuthCount,
        },
      },
    });

  } catch (err) {
    logger.error(`[ADMIN] getStats error — ${err.message}`, { stack: err.stack });
    return res.status(500).json(fail('SERVER_ERROR', 'An internal error occurred.'));
  }
};

// ─────────────────────────────────────────────────────────────────────────────
//  GET /admin/users
//  List all seller accounts.
// ─────────────────────────────────────────────────────────────────────────────

exports.listUsers = async (req, res) => {
  const { page, limit, offset } = parsePagination(req.query);
  const { search, role, is_banned } = req.query;

  try {
    const where = {};

    if (role) {
      where.role = role;
    }

    if (is_banned !== undefined) {
      where.is_banned = is_banned === 'true';
    }

    if (search) {
      where[Op.or] = [
        { username: { [Op.iLike]: `%${search}%` } },
        { email:    { [Op.iLike]: `%${search}%` } },
      ];
    }

    const { count, rows } = await User.findAndCountAll({
      where,
      limit,
      offset,
      order:      [['createdAt', 'DESC']],
      attributes: ['id', 'username', 'email', 'role', 'is_banned', 'ban_reason', 'createdAt', 'last_login_at'],
    });

    return res.status(200).json({
      success: true,
      data: {
        users:      rows,
        pagination: {
          total:       count,
          page,
          limit,
          total_pages: Math.ceil(count / limit),
        },
      },
    });

  } catch (err) {
    logger.error(`[ADMIN] listUsers error — ${err.message}`, { stack: err.stack });
    return res.status(500).json(fail('SERVER_ERROR', 'An internal error occurred.'));
  }
};

// ─────────────────────────────────────────────────────────────────────────────
//  GET /admin/users/:id
//  Get a single user with their apps and key counts.
// ─────────────────────────────────────────────────────────────────────────────

exports.getUser = async (req, res) => {
  const { id } = req.params;

  try {
    const user = await User.findByPk(id, {
      attributes: { exclude: ['password'] },
      include: [{
        model:      Application,
        as:         'applications',
        attributes: ['id', 'name', 'is_active', 'createdAt'],
      }],
    });

    if (!user) {
      return res.status(404).json(fail('NOT_FOUND', 'User not found.'));
    }

    // Count keys across all their apps
    const appIds   = user.applications.map(a => a.id);
    const keyCount = appIds.length
      ? await License.count({ where: { app_id: { [Op.in]: appIds } } })
      : 0;

    return res.status(200).json({
      success: true,
      data: { user, key_count: keyCount },
    });

  } catch (err) {
    logger.error(`[ADMIN] getUser error — ${err.message}`, { stack: err.stack });
    return res.status(500).json(fail('SERVER_ERROR', 'An internal error occurred.'));
  }
};

// ─────────────────────────────────────────────────────────────────────────────
//  POST /admin/users/ban
//  Ban a seller account.
// ─────────────────────────────────────────────────────────────────────────────

exports.banUser = async (req, res) => {
  const adminId = req.user.id;
  const { user_id, reason = '' } = req.body;

  if (!user_id) {
    return res.status(400).json(fail('MISSING_FIELDS', 'user_id is required.'));
  }

  // Prevent self-ban
  if (user_id === adminId) {
    return res.status(400).json(fail('FORBIDDEN', 'You cannot ban your own account.'));
  }

  try {
    const user = await User.findByPk(user_id);
    if (!user) {
      return res.status(404).json(fail('NOT_FOUND', 'User not found.'));
    }

    if (user.role === 'admin') {
      return res.status(403).json(fail('FORBIDDEN', 'Admin accounts cannot be banned via this endpoint.'));
    }

    if (user.is_banned) {
      return res.status(400).json(fail('ALREADY_BANNED', 'User is already banned.'));
    }

    await user.update({
      is_banned:  true,
      ban_reason: reason.slice(0, 255),
      banned_at:  new Date(),
      banned_by:  adminId,
    });

    await Log.create({
      action:       'USER_BANNED',
      status:       'success',
      performed_by: adminId,
      note:         `Banned user ${user_id}: ${reason}`,
    });

    logger.info(`[ADMIN] banned user=${user_id} by admin=${adminId} reason="${reason}"`);

    return res.status(200).json({
      success: true,
      message: 'User account has been banned.',
      data:    { user_id, is_banned: true },
    });

  } catch (err) {
    logger.error(`[ADMIN] banUser error — ${err.message}`, { stack: err.stack });
    return res.status(500).json(fail('SERVER_ERROR', 'An internal error occurred.'));
  }
};

// ─────────────────────────────────────────────────────────────────────────────
//  POST /admin/users/unban
//  Unban a seller account.
// ─────────────────────────────────────────────────────────────────────────────

exports.unbanUser = async (req, res) => {
  const adminId  = req.user.id;
  const { user_id } = req.body;

  if (!user_id) {
    return res.status(400).json(fail('MISSING_FIELDS', 'user_id is required.'));
  }

  try {
    const user = await User.findByPk(user_id);
    if (!user) {
      return res.status(404).json(fail('NOT_FOUND', 'User not found.'));
    }

    if (!user.is_banned) {
      return res.status(400).json(fail('NOT_BANNED', 'User is not currently banned.'));
    }

    await user.update({
      is_banned:  false,
      ban_reason: null,
      banned_at:  null,
      banned_by:  null,
    });

    logger.info(`[ADMIN] unbanned user=${user_id} by admin=${adminId}`);

    return res.status(200).json({
      success: true,
      message: 'User account has been unbanned.',
      data:    { user_id, is_banned: false },
    });

  } catch (err) {
    logger.error(`[ADMIN] unbanUser error — ${err.message}`, { stack: err.stack });
    return res.status(500).json(fail('SERVER_ERROR', 'An internal error occurred.'));
  }
};

// ─────────────────────────────────────────────────────────────────────────────
//  PATCH /admin/users/:id
//  Update a user's role or other admin-level fields.
// ─────────────────────────────────────────────────────────────────────────────

exports.updateUser = async (req, res) => {
  const adminId = req.user.id;
  const { id }  = req.params;
  const { role, new_password } = req.body;

  const VALID_ROLES = ['seller', 'admin'];

  try {
    const user = await User.findByPk(id);
    if (!user) {
      return res.status(404).json(fail('NOT_FOUND', 'User not found.'));
    }

    const updates = {};

    if (role) {
      if (!VALID_ROLES.includes(role)) {
        return res.status(400).json(fail('VALIDATION_ERROR', `Role must be one of: ${VALID_ROLES.join(', ')}.`));
      }
      updates.role = role;
    }

    // Admin can force-reset a user's password
    if (new_password) {
      if (new_password.length < 8) {
        return res.status(400).json(fail('VALIDATION_ERROR', 'Password must be at least 8 characters.'));
      }
      updates.password = await bcrypt.hash(new_password, BCRYPT_ROUNDS);
    }

    if (Object.keys(updates).length === 0) {
      return res.status(400).json(fail('NO_CHANGES', 'No valid fields to update.'));
    }

    await user.update(updates);

    logger.info(`[ADMIN] updated user=${id} by admin=${adminId} fields=${Object.keys(updates).join(',')}`);

    return res.status(200).json({ success: true, message: 'User updated successfully.' });

  } catch (err) {
    logger.error(`[ADMIN] updateUser error — ${err.message}`, { stack: err.stack });
    return res.status(500).json(fail('SERVER_ERROR', 'An internal error occurred.'));
  }
};

// ─────────────────────────────────────────────────────────────────────────────
//  DELETE /admin/users/:id
//  Permanently delete a seller account and all their data.
// ─────────────────────────────────────────────────────────────────────────────

exports.deleteUser = async (req, res) => {
  const adminId = req.user.id;
  const { id }  = req.params;

  if (id === adminId) {
    return res.status(400).json(fail('FORBIDDEN', 'You cannot delete your own account.'));
  }

  try {
    const user = await User.findByPk(id);
    if (!user) {
      return res.status(404).json(fail('NOT_FOUND', 'User not found.'));
    }

    // Cascade delete is handled at DB level (see models)
    await user.destroy();

    logger.info(`[ADMIN] deleted user=${id} by admin=${adminId}`);

    return res.status(200).json({ success: true, message: 'User and all associated data deleted.' });

  } catch (err) {
    logger.error(`[ADMIN] deleteUser error — ${err.message}`, { stack: err.stack });
    return res.status(500).json(fail('SERVER_ERROR', 'An internal error occurred.'));
  }
};

// ─────────────────────────────────────────────────────────────────────────────
//  GET /admin/logs
//  System-wide auth and action logs with filtering.
// ─────────────────────────────────────────────────────────────────────────────

exports.getLogs = async (req, res) => {
  const { page, limit, offset } = parsePagination(req.query);
  const {
    app_id,
    license_id,
    action,
    status,
    ip,
    from,
    to,
  } = req.query;

  try {
    const where = {};

    if (app_id)     where.app_id     = app_id;
    if (license_id) where.license_id = license_id;
    if (action)     where.action     = action.toUpperCase();
    if (status)     where.status     = status.toLowerCase();
    if (ip)         where.ip         = ip;

    if (from || to) {
      where.createdAt = {};
      if (from) where.createdAt[Op.gte] = new Date(from);
      if (to)   where.createdAt[Op.lte] = new Date(to);
    }

    const { count, rows } = await Log.findAndCountAll({
      where,
      limit,
      offset,
      order: [['createdAt', 'DESC']],
    });

    return res.status(200).json({
      success: true,
      data: {
        logs:       rows,
        pagination: {
          total:       count,
          page,
          limit,
          total_pages: Math.ceil(count / limit),
        },
      },
    });

  } catch (err) {
    logger.error(`[ADMIN] getLogs error — ${err.message}`, { stack: err.stack });
    return res.status(500).json(fail('SERVER_ERROR', 'An internal error occurred.'));
  }
};

// ─────────────────────────────────────────────────────────────────────────────
//  DELETE /admin/logs
//  Purge logs older than N days.
// ─────────────────────────────────────────────────────────────────────────────

exports.purgeLogs = async (req, res) => {
  const adminId      = req.user.id;
  const { older_than_days = 90 } = req.body;

  const days = parseInt(older_than_days, 10);
  if (isNaN(days) || days < 1) {
    return res.status(400).json(fail('VALIDATION_ERROR', 'older_than_days must be a positive integer.'));
  }

  try {
    const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
    const deleted = await Log.destroy({
      where: { createdAt: { [Op.lt]: cutoff } },
    });

    logger.info(`[ADMIN] purged ${deleted} logs older than ${days}d — by admin=${adminId}`);

    return res.status(200).json({
      success: true,
      message: `${deleted} log entries deleted.`,
      data:    { deleted_count: deleted },
    });

  } catch (err) {
    logger.error(`[ADMIN] purgeLogs error — ${err.message}`, { stack: err.stack });
    return res.status(500).json(fail('SERVER_ERROR', 'An internal error occurred.'));
  }
};

// ─────────────────────────────────────────────────────────────────────────────
//  GET /admin/applications
//  List all applications across all sellers.
// ─────────────────────────────────────────────────────────────────────────────

exports.listApps = async (req, res) => {
  const { page, limit, offset } = parsePagination(req.query);
  const { search, owner_id }    = req.query;

  try {
    const where = {};
    if (owner_id) where.owner_id = owner_id;
    if (search) {
      where.name = { [Op.iLike]: `%${search}%` };
    }

    const { count, rows } = await Application.findAndCountAll({
      where,
      limit,
      offset,
      order:   [['createdAt', 'DESC']],
      include: [{
        model:      User,
        as:         'owner',
        attributes: ['id', 'username', 'email'],
      }],
      attributes: { exclude: ['secret'] }, // Never expose app secrets in admin list
    });

    return res.status(200).json({
      success: true,
      data: {
        applications: rows,
        pagination: {
          total:       count,
          page,
          limit,
          total_pages: Math.ceil(count / limit),
        },
      },
    });

  } catch (err) {
    logger.error(`[ADMIN] listApps error — ${err.message}`, { stack: err.stack });
    return res.status(500).json(fail('SERVER_ERROR', 'An internal error occurred.'));
  }
};

// ─────────────────────────────────────────────────────────────────────────────
//  POST /admin/applications/:id/toggle
//  Enable or disable an application globally.
// ─────────────────────────────────────────────────────────────────────────────

exports.toggleApp = async (req, res) => {
  const adminId = req.user.id;
  const { id }  = req.params;

  try {
    const app = await Application.findByPk(id);
    if (!app) {
      return res.status(404).json(fail('NOT_FOUND', 'Application not found.'));
    }

    const newState = !app.is_active;
    await app.update({ is_active: newState });

    logger.info(`[ADMIN] app=${id} is_active=${newState} by admin=${adminId}`);

    return res.status(200).json({
      success: true,
      message: `Application ${newState ? 'enabled' : 'disabled'}.`,
      data:    { app_id: id, is_active: newState },
    });

  } catch (err) {
    logger.error(`[ADMIN] toggleApp error — ${err.message}`, { stack: err.stack });
    return res.status(500).json(fail('SERVER_ERROR', 'An internal error occurred.'));
  }
};
