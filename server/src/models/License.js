'use strict';

/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║               GHOSTY Auth — License.js                      ║
 * ║          License key schema (Sequelize model)               ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * Table: licenses
 *
 * A License key:
 *   - Belongs to one Application
 *   - Was created by one User (seller)
 *   - Has an optional HWID binding (set on first use)
 *   - Has an optional expiry date
 *   - Can be banned with a reason
 *   - Has optional user identity fields (username, email)
 *     that the end-user can be associated with
 *
 * Associations (defined at bottom):
 *   License belongsTo Application  (as 'application')
 *   License belongsTo User         (as 'creator',  via created_by)
 *   License hasMany  Log           (as 'logs')
 */

const { DataTypes, Model, Op } = require('sequelize');
const sequelize = require('../config/db');

// ─── Key format regex: GHOST-XXXX-XXXX-XXXX (uppercase hex segments) ──────────
const KEY_FORMAT_REGEX = /^[A-Z0-9]{4,8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/;

// ─────────────────────────────────────────────────────────────────────────────

class License extends Model {

  // ── Status helpers ───────────────────────────────────────────────────────

  /** Returns true if the key is currently usable. */
  isActive() {
    if (this.is_banned) return false;
    if (this.expires_at && new Date(this.expires_at) < new Date()) return false;
    return true;
  }

  /** Returns the computed status string for API responses. */
  getStatus() {
    if (this.is_banned)  return 'banned';
    if (this.expires_at && new Date(this.expires_at) < new Date()) return 'expired';
    return 'active';
  }

  /** Returns true if the key has been bound to a hardware ID. */
  isHwidBound() {
    return !!this.hwid;
  }

  /**
   * Safe representation for API responses.
   * Includes computed fields.
   */
  toPublic() {
    return {
      id:            this.id,
      key:           this.key,
      status:        this.getStatus(),
      is_banned:     this.is_banned,
      ban_reason:    this.ban_reason,
      expires_at:    this.expires_at,
      hwid_bound:    this.isHwidBound(),
      username:      this.username,
      email:         this.email,
      note:          this.note,
      first_used_at: this.first_used_at,
      last_used_at:  this.last_used_at,
      last_used_ip:  this.last_used_ip,
      created_at:    this.createdAt,
    };
  }
}

// ─────────────────────────────────────────────────────────────────────────────

License.init(
  {
    // ── Primary Key ─────────────────────────────────────────────────────────
    id: {
      type:         DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey:   true,
      allowNull:    false,
      comment:      'UUID primary key',
    },

    // ── Ownership / Scope ────────────────────────────────────────────────────
    app_id: {
      type:       DataTypes.UUID,
      allowNull:  false,
      references: { model: 'applications', key: 'id' },
      onDelete:   'CASCADE',
      onUpdate:   'CASCADE',
      comment:    'FK → applications.id',
    },

    created_by: {
      type:       DataTypes.UUID,
      allowNull:  false,
      references: { model: 'users', key: 'id' },
      onDelete:   'CASCADE',
      onUpdate:   'CASCADE',
      comment:    'FK → users.id (seller who generated this key)',
    },

    // ── The Key ───────────────────────────────────────────────────────────────
    key: {
      type:      DataTypes.STRING(64),
      allowNull: false,
      unique:    true,
      validate: {
        notNull:  { msg: 'License key is required.' },
        notEmpty: { msg: 'License key cannot be empty.' },
        isValidFormat(value) {
          if (!KEY_FORMAT_REGEX.test(value)) {
            throw new Error('License key must match format: PREFIX-XXXX-XXXX-XXXX');
          }
        },
      },
      set(value) {
        // Always uppercase
        this.setDataValue('key', value?.trim().toUpperCase());
      },
      comment: 'The license key string (e.g. GHOST-AB12-CD34-EF56)',
    },

    // ── Expiry ────────────────────────────────────────────────────────────────
    expires_at: {
      type:      DataTypes.DATE,
      allowNull: true,
      comment:   'When this key expires. NULL = never expires.',
    },

    // ── HWID Binding ─────────────────────────────────────────────────────────
    hwid: {
      type:      DataTypes.STRING(64),     // SHA-256 hex = 64 chars
      allowNull: true,
      validate: {
        isValidHWID(value) {
          if (value !== null && value !== undefined) {
            if (!/^[0-9a-f]{64}$/.test(value)) {
              throw new Error('HWID must be a 64-character lowercase hex SHA-256 hash.');
            }
          }
        },
      },
      comment: 'SHA-256 HWID hash bound on first use. NULL = not yet bound.',
    },

    // ── Ban Management ───────────────────────────────────────────────────────
    is_banned: {
      type:         DataTypes.BOOLEAN,
      allowNull:    false,
      defaultValue: false,
      comment:      'Whether this key is banned from authenticating',
    },

    ban_reason: {
      type:      DataTypes.STRING(255),
      allowNull: true,
      comment:   'Reason for the ban (seller/admin-supplied)',
    },

    banned_at: {
      type:      DataTypes.DATE,
      allowNull: true,
      comment:   'Timestamp when the ban was applied',
    },

    banned_by: {
      type:      DataTypes.UUID,
      allowNull: true,
      comment:   'ID of the user (seller/admin) who banned this key',
    },

    // ── End-User Identity (Optional) ──────────────────────────────────────────
    // Sellers can optionally attach a customer name/email to a key
    // for their own record-keeping.
    username: {
      type:      DataTypes.STRING(64),
      allowNull: true,
      comment:   'Optional: end-user username associated with this key',
    },

    email: {
      type:      DataTypes.STRING(254),
      allowNull: true,
      validate: {
        isEmailOrNull(value) {
          if (value !== null && value !== undefined && value !== '') {
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(value)) {
              throw new Error('Email must be a valid email address.');
            }
          }
        },
      },
      comment: 'Optional: end-user email associated with this key',
    },

    // ── Metadata ─────────────────────────────────────────────────────────────
    note: {
      type:      DataTypes.STRING(255),
      allowNull: true,
      comment:   'Seller-supplied note (e.g. reseller batch, customer name)',
    },

    // ── Usage Tracking ────────────────────────────────────────────────────────
    first_used_at: {
      type:      DataTypes.DATE,
      allowNull: true,
      comment:   'Timestamp of first successful authentication (HWID bind event)',
    },

    last_used_at: {
      type:      DataTypes.DATE,
      allowNull: true,
      comment:   'Timestamp of the most recent successful authentication',
    },

    last_used_ip: {
      type:      DataTypes.STRING(45),
      allowNull: true,
      comment:   'IP address of the most recent successful authentication',
    },
  },
  {
    sequelize,
    modelName:   'License',
    tableName:   'licenses',
    timestamps:  true,
    paranoid:    false,
    underscored: false,

    indexes: [
      // Primary lookup: by key string (auth flow)
      { unique: true, fields: ['key'],        name: 'licenses_key_unique' },
      // List keys for an app (dashboard)
      { fields: ['app_id'],                   name: 'licenses_app_id_idx' },
      // Creator lookup
      { fields: ['created_by'],               name: 'licenses_created_by_idx' },
      // Status filtering (active/banned)
      { fields: ['is_banned'],                name: 'licenses_is_banned_idx' },
      // Expiry queries (find expired keys)
      { fields: ['expires_at'],               name: 'licenses_expires_at_idx' },
      // HWID lookup (future: multi-device support)
      { fields: ['hwid'],                     name: 'licenses_hwid_idx' },
      // Compound: common dashboard query (app + status)
      { fields: ['app_id', 'is_banned'],      name: 'licenses_app_status_idx' },
    ],

    scopes: {
      // Commonly used query scopes

      /** Only active (not banned, not expired) keys. */
      active: {
        where: {
          is_banned: false,
          [Op.or]: [
            { expires_at: null },
            { expires_at: { [Op.gt]: new Date() } },
          ],
        },
      },

      /** Only banned keys. */
      banned: {
        where: { is_banned: true },
      },

      /** Only expired (but not banned) keys. */
      expired: {
        where: {
          is_banned:  false,
          expires_at: { [Op.lte]: new Date() },
        },
      },

      /** Keys that have been used at least once. */
      used: {
        where: {
          first_used_at: { [Op.ne]: null },
        },
      },

      /** Keys that have never been used. */
      unused: {
        where: {
          first_used_at: null,
        },
      },
    },

    hooks: {
      // Normalise key to uppercase before any save
      beforeValidate(license) {
        if (license.key) {
          license.key = license.key.trim().toUpperCase();
        }
        // Normalise HWID to lowercase
        if (license.hwid) {
          license.hwid = license.hwid.toLowerCase();
        }
      },

      // Enforce: can't un-expire a key by setting expires_at in the past
      beforeUpdate(license) {
        if (license.changed('expires_at') && license.expires_at) {
          // Silently allow — admins can set past dates (to force-expire a key)
          // Just log it
          if (new Date(license.expires_at) < new Date()) {
            require('../utils/logger').warn(
              `[License] expires_at set to past date — id=${license.id}`
            );
          }
        }
      },
    },
  }
);

// ─── Static helpers ──────────────────────────────────────────────────────────

/**
 * Finds a license by its key string and app.
 * Uses the unique index for O(1) lookup.
 *
 * @param {string} key    The license key string
 * @param {string} appId  The application UUID
 */
License.findByKeyAndApp = function (key, appId) {
  return License.findOne({
    where: {
      key:    key.trim().toUpperCase(),
      app_id: appId,
    },
  });
};

// ─── Associations ─────────────────────────────────────────────────────────────

License.associate = (models) => {
  License.belongsTo(models.Application, {
    foreignKey: 'app_id',
    as:         'application',
  });

  License.belongsTo(models.User, {
    foreignKey: 'created_by',
    as:         'creator',
  });

  License.hasMany(models.Log, {
    foreignKey: 'license_id',
    as:         'logs',
    onDelete:   'SET NULL',
    onUpdate:   'CASCADE',
  });
};

module.exports = License;
