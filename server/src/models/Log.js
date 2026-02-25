'use strict';

/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║                GHOSTY Auth — Log.js                         ║
 * ║   Immutable audit / auth event log schema (Sequelize)       ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * Table: logs
 *
 * Records every notable event in the system:
 *   - Auth attempts (init, validate)
 *   - Key actions (ban, unban, HWID reset)
 *   - User actions (login, register, ban)
 *   - Admin actions (toggle app, purge logs)
 *
 * Design principles:
 *   - Immutable: logs are NEVER updated after creation
 *   - Append-only: no UPDATE or soft-delete
 *   - All FK columns are nullable — logs survive even if related records
 *     are deleted (SET NULL on delete)
 *
 * Associations (defined at bottom):
 *   Log belongsTo Application  (as 'application',  optional)
 *   Log belongsTo License      (as 'license',       optional)
 *   Log belongsTo User         (as 'actor',         via performed_by, optional)
 */

const { DataTypes, Model } = require('sequelize');
const sequelize = require('../config/db');

// ─── Valid action types ───────────────────────────────────────────────────────

const ACTIONS = [
  // Auth flow
  'AUTH_INIT',
  'AUTH_VALIDATE',
  'AUTH_VERIFY',
  'AUTH_LOGOUT',

  // Key management
  'KEY_CREATED',
  'KEY_BANNED',
  'KEY_UNBANNED',
  'KEY_DELETED',
  'KEY_EXTENDED',
  'HWID_RESET',

  // User management
  'USER_REGISTERED',
  'USER_LOGIN',
  'USER_LOGIN_FAILED',
  'USER_BANNED',
  'USER_UNBANNED',
  'USER_UPDATED',
  'USER_DELETED',

  // App management
  'APP_CREATED',
  'APP_TOGGLED',
  'APP_DELETED',
  'APP_SECRET_ROTATED',

  // Admin
  'LOGS_PURGED',
];

const STATUSES = ['success', 'failed', 'blocked'];

// ─────────────────────────────────────────────────────────────────────────────

class Log extends Model {
  /**
   * Returns a safe public representation with only the fields
   * needed for a dashboard log viewer.
   */
  toPublic() {
    return {
      id:           this.id,
      action:       this.action,
      status:       this.status,
      reason:       this.reason,
      ip:           this.ip,
      app_id:       this.app_id,
      license_id:   this.license_id,
      license_key:  this.license_key,
      hwid:         this.hwid ? `${this.hwid.slice(0, 8)}...` : null,  // Partially mask HWID in logs
      performed_by: this.performed_by,
      note:         this.note,
      created_at:   this.createdAt,
    };
  }
}

// ─────────────────────────────────────────────────────────────────────────────

Log.init(
  {
    // ── Primary Key ─────────────────────────────────────────────────────────
    id: {
      type:         DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey:   true,
      allowNull:    false,
      comment:      'UUID primary key',
    },

    // ── Event Classification ──────────────────────────────────────────────────
    action: {
      type:      DataTypes.STRING(32),
      allowNull: false,
      validate: {
        notNull: { msg: 'Log action is required.' },
        isIn: {
          args: [ACTIONS],
          msg:  `Action must be one of: ${ACTIONS.join(', ')}`,
        },
      },
      comment: 'The type of event that occurred',
    },

    status: {
      type:         DataTypes.ENUM(...STATUSES),
      allowNull:    false,
      defaultValue: 'success',
      validate: {
        isIn: {
          args: [STATUSES],
          msg:  `Status must be one of: ${STATUSES.join(', ')}`,
        },
      },
      comment: 'Outcome of the action',
    },

    // ── Failure Reason ────────────────────────────────────────────────────────
    reason: {
      type:      DataTypes.STRING(64),
      allowNull: true,
      comment:   'Machine-readable failure code (e.g. HWID_MISMATCH, KEY_EXPIRED)',
    },

    // ── Network Context ───────────────────────────────────────────────────────
    ip: {
      type:      DataTypes.STRING(45),     // IPv6 max = 39, IPv4-mapped = 45
      allowNull: true,
      comment:   'Client IP address',
    },

    // ── Related Records (all nullable — survive deletions) ────────────────────
    app_id: {
      type:       DataTypes.UUID,
      allowNull:  true,
      references: { model: 'applications', key: 'id' },
      onDelete:   'SET NULL',
      onUpdate:   'CASCADE',
      comment:    'FK → applications.id (nullable)',
    },

    license_id: {
      type:       DataTypes.UUID,
      allowNull:  true,
      references: { model: 'licenses', key: 'id' },
      onDelete:   'SET NULL',
      onUpdate:   'CASCADE',
      comment:    'FK → licenses.id (nullable)',
    },

    // ── Denormalised fields ────────────────────────────────────────────────────
    // Stored directly on the log so the record remains useful even if the
    // license key or application is later deleted.
    license_key: {
      type:      DataTypes.STRING(64),
      allowNull: true,
      comment:   'Snapshot of the license key string at log time',
    },

    hwid: {
      type:      DataTypes.STRING(64),
      allowNull: true,
      comment:   'HWID hash presented in the request (if applicable)',
    },

    // ── Actor ─────────────────────────────────────────────────────────────────
    performed_by: {
      type:       DataTypes.UUID,
      allowNull:  true,
      references: { model: 'users', key: 'id' },
      onDelete:   'SET NULL',
      onUpdate:   'CASCADE',
      comment:    'FK → users.id — the seller/admin who triggered this event (nullable)',
    },

    // ── Free-text Note ────────────────────────────────────────────────────────
    note: {
      type:      DataTypes.STRING(512),
      allowNull: true,
      comment:   'Additional context or description for this log entry',
    },
  },
  {
    sequelize,
    modelName:   'Log',
    tableName:   'logs',
    timestamps:  true,
    paranoid:    false,
    underscored: false,

    indexes: [
      // Most common query: all logs for an app, newest first
      { fields: ['app_id', 'createdAt'],            name: 'logs_app_created_idx' },
      // Filter by license
      { fields: ['license_id'],                      name: 'logs_license_id_idx' },
      // Filter by action type
      { fields: ['action'],                          name: 'logs_action_idx' },
      // Filter by status (success vs failed)
      { fields: ['status'],                          name: 'logs_status_idx' },
      // Filter by IP (security/abuse queries)
      { fields: ['ip'],                              name: 'logs_ip_idx' },
      // Actor queries (what did this admin do?)
      { fields: ['performed_by'],                    name: 'logs_performed_by_idx' },
      // Time-based queries (log purge, recent activity)
      { fields: ['createdAt'],                       name: 'logs_created_at_idx' },
      // Compound: auth failures for an app within a time range
      { fields: ['app_id', 'action', 'status'],      name: 'logs_app_action_status_idx' },
    ],

    hooks: {
      // ── Enforce immutability ──────────────────────────────────────────────
      // Logs must never be updated after creation
      beforeUpdate() {
        throw new Error('[Log] Logs are immutable and cannot be updated.');
      },

      // ── Sanitise fields before insert ──────────────────────────────────────
      beforeCreate(log) {
        // Uppercase action for consistency
        if (log.action) {
          log.action = log.action.toUpperCase().trim();
        }
        // Lowercase status
        if (log.status) {
          log.status = log.status.toLowerCase().trim();
        }
        // Lowercase HWID
        if (log.hwid) {
          log.hwid = log.hwid.toLowerCase().trim();
        }
        // Truncate note if too long (safety net)
        if (log.note && log.note.length > 512) {
          log.note = log.note.slice(0, 512);
        }
      },
    },
  }
);

// ─── Static helpers ──────────────────────────────────────────────────────────

/**
 * Creates a log entry without throwing.
 * Wraps Log.create in a try/catch — logging should never break a request.
 *
 * @param {object} data  Log fields
 * @returns {Promise<Log|null>}
 */
Log.safeCreate = async function (data) {
  try {
    return await Log.create(data);
  } catch (err) {
    require('../utils/logger').error(`[Log] safeCreate failed — ${err.message}`);
    return null;
  }
};

/**
 * Returns a summary count of events for a given app in a time window.
 * Useful for dashboard sparklines / activity graphs.
 *
 * @param {string} appId
 * @param {number} windowHours
 * @returns {Promise<{ action: string, count: number }[]>}
 */
Log.getActivitySummary = async function (appId, windowHours = 24) {
  const { Op, fn, col, literal } = require('sequelize');
  const since = new Date(Date.now() - windowHours * 60 * 60 * 1000);

  return Log.findAll({
    where: {
      app_id:    appId,
      createdAt: { [Op.gte]: since },
    },
    attributes: [
      'action',
      'status',
      [fn('COUNT', col('id')), 'count'],
    ],
    group: ['action', 'status'],
    order: [[literal('count'), 'DESC']],
    raw:   true,
  });
};

// ─── Associations ─────────────────────────────────────────────────────────────

Log.associate = (models) => {
  Log.belongsTo(models.Application, {
    foreignKey: 'app_id',
    as:         'application',
  });

  Log.belongsTo(models.License, {
    foreignKey: 'license_id',
    as:         'license',
  });

  Log.belongsTo(models.User, {
    foreignKey: 'performed_by',
    as:         'actor',
  });
};

// ─── Expose valid action constants ───────────────────────────────────────────

Log.ACTIONS  = Object.freeze(ACTIONS);
Log.STATUSES = Object.freeze(STATUSES);

module.exports = Log;
