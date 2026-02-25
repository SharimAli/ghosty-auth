'use strict';

/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║             GHOSTY Auth — Application.js                    ║
 * ║      Seller application (software product) schema           ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * Table: applications
 *
 * Each Application:
 *   - Is owned by one User (seller)
 *   - Has a unique cryptographic secret used to sign/verify requests
 *   - Can have many License keys
 *   - Can have many Logs
 *
 * Associations (defined at bottom):
 *   Application belongsTo User          (as 'owner')
 *   Application hasMany  License        (as 'licenses')
 *   Application hasMany  Log            (as 'logs')
 */

const crypto                   = require('crypto');
const { DataTypes, Model }     = require('sequelize');
const sequelize                = require('../config/db');

// ─────────────────────────────────────────────────────────────────────────────

class Application extends Model {
  /**
   * Regenerates the application secret.
   * Returns the new plaintext secret — store it, it won't be shown again.
   */
  async rotateSecret() {
    const newSecret = crypto.randomBytes(32).toString('hex');
    await this.update({ secret: newSecret });
    return newSecret;
  }

  /**
   * Safe public representation — NEVER exposes the secret.
   */
  toPublic() {
    return {
      id:          this.id,
      name:        this.name,
      description: this.description,
      is_active:   this.is_active,
      version:     this.version,
      created_at:  this.createdAt,
      updated_at:  this.updatedAt,
    };
  }
}

// ─────────────────────────────────────────────────────────────────────────────

Application.init(
  {
    // ── Primary Key ─────────────────────────────────────────────────────────
    id: {
      type:         DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey:   true,
      allowNull:    false,
      comment:      'UUID primary key',
    },

    // ── Ownership ────────────────────────────────────────────────────────────
    owner_id: {
      type:       DataTypes.UUID,
      allowNull:  false,
      references: { model: 'users', key: 'id' },
      onDelete:   'CASCADE',
      onUpdate:   'CASCADE',
      comment:    'FK → users.id (seller who owns this app)',
    },

    // ── Identity ─────────────────────────────────────────────────────────────
    name: {
      type:      DataTypes.STRING(64),
      allowNull: false,
      validate: {
        len:     [1, 64],
        notNull: { msg: 'Application name is required.' },
        notEmpty:{ msg: 'Application name cannot be empty.' },
      },
      set(value) {
        this.setDataValue('name', value?.trim());
      },
      comment: 'Human-readable application name (1–64 chars)',
    },

    description: {
      type:         DataTypes.STRING(512),
      allowNull:    true,
      defaultValue: null,
      validate:     { len: [0, 512] },
      comment:      'Optional description of the application',
    },

    version: {
      type:         DataTypes.STRING(32),
      allowNull:    true,
      defaultValue: '1.0.0',
      validate:     { len: [0, 32] },
      comment:      'Application version string (displayed to SDK on auth)',
    },

    // ── Cryptographic Secret ──────────────────────────────────────────────────
    // Used to sign/verify request_signature in /auth/init
    // Generated as crypto.randomBytes(32).toString('hex') = 64-char hex string
    // NEVER returned in list responses — only on creation and explicit rotation
    secret: {
      type:      DataTypes.STRING(128),
      allowNull: false,
      validate: {
        len:     [64, 128],
        notNull: { msg: 'Application secret is required.' },
        // Ensure it looks like a hex string
        is: {
          args: /^[0-9a-f]+$/i,
          msg:  'Secret must be a hexadecimal string.',
        },
      },
      comment: 'HMAC secret (64-char hex, from crypto.randomBytes(32)) — never expose in list APIs',
    },

    // ── Status ────────────────────────────────────────────────────────────────
    is_active: {
      type:         DataTypes.BOOLEAN,
      allowNull:    false,
      defaultValue: true,
      comment:      'When false, all auth requests for this app are rejected',
    },

    // ── Settings ─────────────────────────────────────────────────────────────
    // These allow per-app customisation of auth behaviour
    hwid_lock_enabled: {
      type:         DataTypes.BOOLEAN,
      allowNull:    false,
      defaultValue: true,
      comment:      'Whether HWID binding is enforced for this application',
    },

    max_devices: {
      type:         DataTypes.INTEGER,
      allowNull:    false,
      defaultValue: 1,
      validate: {
        min: 1,
        max: 10,
      },
      comment: 'Max simultaneous devices per license key (future use)',
    },

    session_ttl_hours: {
      type:         DataTypes.INTEGER,
      allowNull:    false,
      defaultValue: 1,
      validate: {
        min: 1,
        max: 720,   // 30 days
      },
      comment: 'Session token TTL in hours for this specific app',
    },
  },
  {
    sequelize,
    modelName:   'Application',
    tableName:   'applications',
    timestamps:  true,
    paranoid:    false,
    underscored: false,

    indexes: [
      // Owner lookup (list apps for a seller)
      { fields: ['owner_id'],  name: 'applications_owner_id_idx' },
      // Status filter
      { fields: ['is_active'], name: 'applications_is_active_idx' },
    ],

    hooks: {
      // Ensure secret is always stored in lowercase hex
      beforeCreate(app) {
        if (app.secret) {
          app.secret = app.secret.toLowerCase();
        }
      },
      beforeUpdate(app) {
        if (app.changed('secret') && app.secret) {
          app.secret = app.secret.toLowerCase();
        }
      },
    },
  }
);

// ─── Associations ─────────────────────────────────────────────────────────────

Application.associate = (models) => {
  // Belongs to a seller
  Application.belongsTo(models.User, {
    foreignKey: 'owner_id',
    as:         'owner',
  });

  // Has many license keys
  Application.hasMany(models.License, {
    foreignKey: 'app_id',
    as:         'licenses',
    onDelete:   'CASCADE',
    onUpdate:   'CASCADE',
  });

  // Has many log entries
  Application.hasMany(models.Log, {
    foreignKey: 'app_id',
    as:         'logs',
    onDelete:   'SET NULL',
    onUpdate:   'CASCADE',
  });
};

module.exports = Application;
