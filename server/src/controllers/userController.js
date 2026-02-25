'use strict';

/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║              GHOSTY Auth — userController.js                ║
 * ║     Handles seller registration, login, profile, apps       ║
 * ╚══════════════════════════════════════════════════════════════╝
 */

const bcrypt      = require('bcrypt');
const crypto      = require('crypto');
const { Op }      = require('sequelize');
const User        = require('../models/User');
const Application = require('../models/Application');
const { signToken }  = require('../services/tokenService');
const { fail }       = require('../utils/response');
const logger         = require('../utils/logger');

// ─── Constants ────────────────────────────────────────────────────────────────

const BCRYPT_ROUNDS       = parseInt(process.env.BCRYPT_ROUNDS || '12', 10);
const MAX_APPS_PER_SELLER = 20;

// ─── Validators ───────────────────────────────────────────────────────────────

const USERNAME_REGEX = /^[a-zA-Z0-9_]{3,32}$/;
const EMAIL_REGEX    = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,128}$/;

function validateRegistrationInput({ username, email, password }) {
  const errors = [];

  if (!username || !USERNAME_REGEX.test(username))
    errors.push('Username must be 3–32 characters (letters, numbers, underscores only).');

  if (!email || !EMAIL_REGEX.test(email))
    errors.push('A valid email address is required.');

  if (!password || !PASSWORD_REGEX.test(password))
    errors.push('Password must be 8–128 characters and include uppercase, lowercase, and a number.');

  return errors;
}

// ─────────────────────────────────────────────────────────────────────────────
//  POST /users/register
//  Register a new seller account.
// ─────────────────────────────────────────────────────────────────────────────

exports.register = async (req, res) => {
  const { username, email, password, registration_key } = req.body;

  // ── 1. Optional registration key gate ────────────────────────────────────
  // Prevents open registration — only those with the key can sign up.
  const requiredRegKey = process.env.ADMIN_REGISTRATION_KEY;
  if (requiredRegKey) {
    if (!registration_key) {
      return res.status(403).json(fail('FORBIDDEN', 'A registration key is required to create an account.'));
    }
    // Constant-time comparison
    try {
      const valid = crypto.timingSafeEqual(
        Buffer.from(requiredRegKey),
        Buffer.from(registration_key)
      );
      if (!valid) {
        return res.status(403).json(fail('FORBIDDEN', 'Invalid registration key.'));
      }
    } catch {
      return res.status(403).json(fail('FORBIDDEN', 'Invalid registration key.'));
    }
  }

  // ── 2. Input validation ───────────────────────────────────────────────────
  const errors = validateRegistrationInput({ username, email, password });
  if (errors.length) {
    return res.status(400).json({
      success: false,
      code:    'VALIDATION_ERROR',
      message: errors[0],
      errors,
    });
  }

  try {
    // ── 3. Check for duplicates ───────────────────────────────────────────
    const existing = await User.findOne({
      where: {
        [Op.or]: [
          { email:    email.toLowerCase() },
          { username: username.toLowerCase() },
        ],
      },
    });

    if (existing) {
      // Don't reveal which field is taken — security through obscurity here
      return res.status(409).json(fail('CONFLICT', 'Username or email is already in use.'));
    }

    // ── 4. Hash password ──────────────────────────────────────────────────
    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

    // ── 5. Create user ────────────────────────────────────────────────────
    const user = await User.create({
      username: username.trim(),
      email:    email.toLowerCase().trim(),
      password: passwordHash,
      role:     'seller',
    });

    logger.info(`[USERS] registered — user=${user.id} (${user.username})`);

    return res.status(201).json({
      success: true,
      message: 'Account created successfully.',
      data: {
        id:         user.id,
        username:   user.username,
        email:      user.email,
        role:       user.role,
        created_at: user.createdAt.toISOString(),
      },
    });

  } catch (err) {
    logger.error(`[USERS] register error — ${err.message}`, { stack: err.stack });
    return res.status(500).json(fail('SERVER_ERROR', 'An internal error occurred.'));
  }
};

// ─────────────────────────────────────────────────────────────────────────────
//  POST /users/login
//  Authenticate a seller and issue a JWT.
// ─────────────────────────────────────────────────────────────────────────────

exports.login = async (req, res) => {
  const ip = req.ip || req.connection.remoteAddress;
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json(fail('MISSING_FIELDS', 'email and password are required.'));
  }

  try {
    // ── 1. Load user ──────────────────────────────────────────────────────
    const user = await User.findOne({
      where: { email: email.toLowerCase().trim() },
    });

    // ── 2. Verify password — always run bcrypt even if user not found
    //       to prevent user-enumeration via timing differences.
    const dummyHash = '$2b$12$invalidhashfortimingnormalization.......................';
    const passwordMatch = await bcrypt.compare(
      password,
      user ? user.password : dummyHash
    );

    if (!user || !passwordMatch) {
      logger.warn(`[USERS] login failed — email=${email} ip=${ip}`);
      return res.status(401).json(fail('INVALID_CREDENTIALS', 'Invalid email or password.'));
    }

    // ── 3. Check if account is banned ─────────────────────────────────────
    if (user.is_banned) {
      logger.warn(`[USERS] login attempt on banned account — user=${user.id} ip=${ip}`);
      return res.status(401).json(fail('ACCOUNT_BANNED', 'This account has been suspended.'));
    }

    // ── 4. Issue JWT ──────────────────────────────────────────────────────
    const { token, expiresAt } = await signToken({
      user_id:  user.id,
      username: user.username,
      role:     user.role,
    });

    // ── 5. Update last login ──────────────────────────────────────────────
    await user.update({ last_login_at: new Date(), last_login_ip: ip });

    logger.info(`[USERS] login success — user=${user.id} (${user.username}) ip=${ip}`);

    return res.status(200).json({
      success: true,
      message: 'Login successful.',
      data: {
        token,
        expires_in: Math.floor((expiresAt - Date.now()) / 1000),
        user: {
          id:       user.id,
          username: user.username,
          email:    user.email,
          role:     user.role,
        },
      },
    });

  } catch (err) {
    logger.error(`[USERS] login error — ${err.message}`, { stack: err.stack });
    return res.status(500).json(fail('SERVER_ERROR', 'An internal error occurred.'));
  }
};

// ─────────────────────────────────────────────────────────────────────────────
//  GET /users/me
//  Return the current authenticated user's profile.
// ─────────────────────────────────────────────────────────────────────────────

exports.me = async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id, {
      attributes: ['id', 'username', 'email', 'role', 'createdAt', 'last_login_at'],
    });

    if (!user) {
      return res.status(404).json(fail('NOT_FOUND', 'User not found.'));
    }

    return res.status(200).json({ success: true, data: { user } });

  } catch (err) {
    logger.error(`[USERS] me error — ${err.message}`, { stack: err.stack });
    return res.status(500).json(fail('SERVER_ERROR', 'An internal error occurred.'));
  }
};

// ─────────────────────────────────────────────────────────────────────────────
//  PATCH /users/me
//  Update profile — username or password.
// ─────────────────────────────────────────────────────────────────────────────

exports.updateMe = async (req, res) => {
  const userId = req.user.id;
  const { username, current_password, new_password } = req.body;

  try {
    const user = await User.findByPk(userId);
    if (!user) {
      return res.status(404).json(fail('NOT_FOUND', 'User not found.'));
    }

    const updates = {};

    // ── Username change ───────────────────────────────────────────────────
    if (username) {
      if (!USERNAME_REGEX.test(username)) {
        return res.status(400).json(fail('VALIDATION_ERROR', 'Invalid username format.'));
      }
      const taken = await User.findOne({
        where: { username: username.toLowerCase(), id: { [Op.ne]: userId } },
      });
      if (taken) {
        return res.status(409).json(fail('CONFLICT', 'Username is already taken.'));
      }
      updates.username = username.trim();
    }

    // ── Password change ───────────────────────────────────────────────────
    if (new_password) {
      if (!current_password) {
        return res.status(400).json(fail('MISSING_FIELDS', 'current_password is required to set a new password.'));
      }
      const match = await bcrypt.compare(current_password, user.password);
      if (!match) {
        return res.status(401).json(fail('INVALID_CREDENTIALS', 'Current password is incorrect.'));
      }
      if (!PASSWORD_REGEX.test(new_password)) {
        return res.status(400).json(fail('VALIDATION_ERROR', 'New password does not meet requirements.'));
      }
      updates.password = await bcrypt.hash(new_password, BCRYPT_ROUNDS);
    }

    if (Object.keys(updates).length === 0) {
      return res.status(400).json(fail('NO_CHANGES', 'No valid fields to update.'));
    }

    await user.update(updates);

    logger.info(`[USERS] profile updated — user=${userId}`);

    return res.status(200).json({ success: true, message: 'Profile updated successfully.' });

  } catch (err) {
    logger.error(`[USERS] updateMe error — ${err.message}`, { stack: err.stack });
    return res.status(500).json(fail('SERVER_ERROR', 'An internal error occurred.'));
  }
};

// ─────────────────────────────────────────────────────────────────────────────
//  POST /users/applications
//  Create a new application under the authenticated seller.
// ─────────────────────────────────────────────────────────────────────────────

exports.createApp = async (req, res) => {
  const sellerId  = req.user.id;
  const { name, description = '' } = req.body;

  if (!name || !name.trim()) {
    return res.status(400).json(fail('MISSING_FIELDS', 'Application name is required.'));
  }

  if (name.trim().length > 64) {
    return res.status(400).json(fail('VALIDATION_ERROR', 'Application name must be 64 characters or less.'));
  }

  try {
    // ── Enforce per-seller app limit ──────────────────────────────────────
    const appCount = await Application.count({ where: { owner_id: sellerId } });
    if (appCount >= MAX_APPS_PER_SELLER) {
      return res.status(400).json(fail('LIMIT_REACHED', `You can have a maximum of ${MAX_APPS_PER_SELLER} applications.`));
    }

    // ── Generate a unique app secret ──────────────────────────────────────
    const secret = crypto.randomBytes(32).toString('hex');

    const app = await Application.create({
      name:        name.trim(),
      description: description.slice(0, 512),
      owner_id:    sellerId,
      secret,
    });

    logger.info(`[USERS] app created — app=${app.id} seller=${sellerId}`);

    return res.status(201).json({
      success: true,
      message: 'Application created successfully.',
      data: {
        id:          app.id,
        name:        app.name,
        description: app.description,
        secret,         // Only returned on creation — never shown again
        created_at:  app.createdAt.toISOString(),
      },
    });

  } catch (err) {
    logger.error(`[USERS] createApp error — ${err.message}`, { stack: err.stack });
    return res.status(500).json(fail('SERVER_ERROR', 'An internal error occurred.'));
  }
};

// ─────────────────────────────────────────────────────────────────────────────
//  GET /users/applications
//  List all applications for the authenticated seller.
// ─────────────────────────────────────────────────────────────────────────────

exports.listApps = async (req, res) => {
  const sellerId = req.user.id;

  try {
    const apps = await Application.findAll({
      where:      { owner_id: sellerId },
      attributes: ['id', 'name', 'description', 'is_active', 'createdAt'],
      order:      [['createdAt', 'DESC']],
    });

    return res.status(200).json({ success: true, data: { applications: apps } });

  } catch (err) {
    logger.error(`[USERS] listApps error — ${err.message}`, { stack: err.stack });
    return res.status(500).json(fail('SERVER_ERROR', 'An internal error occurred.'));
  }
};

// ─────────────────────────────────────────────────────────────────────────────
//  DELETE /users/applications/:id
//  Delete an application (and all its keys via cascade).
// ─────────────────────────────────────────────────────────────────────────────

exports.deleteApp = async (req, res) => {
  const sellerId = req.user.id;
  const { id }   = req.params;

  try {
    const app = await Application.findOne({ where: { id, owner_id: sellerId } });
    if (!app) {
      return res.status(404).json(fail('NOT_FOUND', 'Application not found or access denied.'));
    }

    await app.destroy();

    logger.info(`[USERS] app deleted — app=${id} seller=${sellerId}`);

    return res.status(200).json({ success: true, message: 'Application and all its keys have been deleted.' });

  } catch (err) {
    logger.error(`[USERS] deleteApp error — ${err.message}`, { stack: err.stack });
    return res.status(500).json(fail('SERVER_ERROR', 'An internal error occurred.'));
  }
};
