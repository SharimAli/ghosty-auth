'use strict';

/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║               GHOSTY Auth — User.js                         ║
 * ║      Seller / Admin accounts schema (Sequelize model)       ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * Table: users
 *
 * Associations (defined at bottom):
 *   User hasMany Application  (as 'applications')
 *   User hasMany Log          (as 'logs', via performed_by)
 */

const { DataTypes, Model } = require('sequelize');
const sequelize = require('../config/db');

// ─────────────────────────────────────────────────────────────────────────────

class User extends Model {
  // ── Instance helpers ────────────────────────────────────────────────────

  /** Returns true if this user has the given role. */
  hasRole(role) {
    return this.role === role;
  }

  /** Returns true if this is an admin account. */
  isAdmin() {
    return this.role === 'admin';
  }

  /**
   * Safe serialisation — strips password and sensitive ban metadata.
   * Use this when returning user data in API responses.
   */
  toPublic() {
    return {
      id:            this.id,
      username:      this.username,
      email:         this.email,
      role:          this.role,
      is_banned:     this.is_banned,
      created_at:    this.createdAt,
      last_login_at: this.last_login_at,
    };
  }
}

// ─────────────────────────────────────────────────────────────────────────────

User.init(
  {
    // ── Primary Key ─────────────────────────────────────────────────────────
    id: {
      type:         DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey:   true,
      allowNull:    false,
      comment:      'UUID primary key',
    },

    // ── Identity ────────────────────────────────────────────────────────────
    username: {
      type:      DataTypes.STRING(32),
      allowNull: false,
      unique:    true,
      validate: {
        len:     [3, 32],
        is:      /^[a-zA-Z0-9_]+$/i,
        notNull: { msg: 'Username is required.' },
      },
      set(value) {
        // Always store lowercase for case-insensitive uniqueness
        this.setDataValue('username', value?.trim().toLowerCase());
      },
      comment: 'Unique seller username (3–32 chars, alphanumeric + underscore)',
    },

    email: {
      type:      DataTypes.STRING(254),
      allowNull: false,
      unique:    true,
      validate: {
        isEmail: { msg: 'Must be a valid email address.' },
        notNull: { msg: 'Email is required.' },
        len:     [5, 254],
      },
      set(value) {
        this.setDataValue('email', value?.trim().toLowerCase());
      },
      comment: 'Unique email address (normalised to lowercase)',
    },

    // ── Authentication ───────────────────────────────────────────────────────
    password: {
      type:      DataTypes.STRING(255),
      allowNull: false,
      validate: {
        notNull: { msg: 'Password hash is required.' },
        len:     [60, 255],          // bcrypt hashes are always 60 chars
      },
      comment: 'bcrypt hash (minimum 12 rounds) — never store plaintext',
    },

    // ── Authorisation ────────────────────────────────────────────────────────
    role: {
      type:         DataTypes.ENUM('seller', 'admin'),
      allowNull:    false,
      defaultValue: 'seller',
      validate: {
        isIn: {
          args:  [['seller', 'admin']],
          msg:   'Role must be seller or admin.',
        },
      },
      comment: 'seller = normal user; admin = full platform access',
    },

    // ── Ban Management ───────────────────────────────────────────────────────
    is_banned: {
      type:         DataTypes.BOOLEAN,
      allowNull:    false,
      defaultValue: false,
      comment:      'Whether this account is banned from logging in',
    },

    ban_reason: {
      type:      DataTypes.STRING(255),
      allowNull: true,
      comment:   'Admin-supplied reason for the ban',
    },

    banned_at: {
      type:      DataTypes.DATE,
      allowNull: true,
      comment:   'Timestamp when the ban was applied',
    },

    banned_by: {
      type:      DataTypes.UUID,
      allowNull: true,
      comment:   'ID of the admin who applied the ban',
    },

    // ── Activity Tracking ────────────────────────────────────────────────────
    last_login_at: {
      type:      DataTypes.DATE,
      allowNull: true,
      comment:   'Timestamp of the most recent successful login',
    },

    last_login_ip: {
      type:         DataTypes.STRING(45),   // IPv6 max = 39, IPv4-mapped = 45
      allowNull:    true,
      comment:      'IP address of the most recent successful login',
    },
  },
  {
    sequelize,
    modelName:  'User',
    tableName:  'users',
    timestamps: true,                       // createdAt, updatedAt
    paranoid:   false,                      // Hard delete only (no soft-delete for users)
    underscored: false,

    indexes: [
      // Fast lookup by email (login flow)
      { unique: true, fields: ['email'],    name: 'users_email_unique' },
      // Fast lookup by username
      { unique: true, fields: ['username'], name: 'users_username_unique' },
      // Admin queries: filter by role
      { fields: ['role'],                   name: 'users_role_idx' },
      // Admin queries: filter banned accounts
      { fields: ['is_banned'],              name: 'users_is_banned_idx' },
    ],

    hooks: {
      // Prevent accidental plaintext password storage
      beforeCreate(user) {
        if (user.password && !user.password.startsWith('$2')) {
          throw new Error('[User] Attempted to store an unhashed password. Abort.');
        }
      },
      beforeUpdate(user) {
        if (user.changed('password') && !user.password.startsWith('$2')) {
          throw new Error('[User] Attempted to store an unhashed password. Abort.');
        }
      },
    },
  }
);

// ─── Associations ─────────────────────────────────────────────────────────────
// Defined here to avoid circular-require issues.
// Called once after all models are loaded (see config/db.js or app.js).

User.associate = (models) => {
  // A seller owns many Applications
  User.hasMany(models.Application, {
    foreignKey: 'owner_id',
    as:         'applications',
    onDelete:   'CASCADE',    // Deleting a user removes their apps and keys
    onUpdate:   'CASCADE',
  });

  // A user can have many Log entries (as the actor)
  User.hasMany(models.Log, {
    foreignKey: 'performed_by',
    as:         'actioned_logs',
    onDelete:   'SET NULL',
    onUpdate:   'CASCADE',
  });
};

module.exports = User;
