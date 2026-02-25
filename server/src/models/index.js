'use strict';

/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║             GHOSTY Auth — models/index.js                   ║
 * ║   Loads all Sequelize models and wires their associations    ║
 * ╚══════════════════════════════════════════════════════════════╝
 *
 * Import models from here, never directly from individual files:
 *   const { User, License, Application, Log } = require('../models');
 *
 * Association graph:
 *
 *   User ─────────────────── hasMany ──► Application  (owner_id)
 *   User ─────────────────── hasMany ──► Log           (performed_by)
 *
 *   Application ─────────── belongsTo ─► User          (owner_id)
 *   Application ─────────── hasMany ───► License        (app_id)
 *   Application ─────────── hasMany ───► Log            (app_id)
 *
 *   License ─────────────── belongsTo ─► Application   (app_id)
 *   License ─────────────── belongsTo ─► User           (created_by)
 *   License ─────────────── hasMany ───► Log            (license_id)
 *
 *   Log ─────────────────── belongsTo ─► Application   (app_id)
 *   Log ─────────────────── belongsTo ─► License        (license_id)
 *   Log ─────────────────── belongsTo ─► User           (performed_by)
 */

const User        = require('./User');
const Application = require('./Application');
const License     = require('./License');
const Log         = require('./Log');

// ─── Bundle all models for association wiring ─────────────────────────────────

const models = { User, Application, License, Log };

// ─── Run each model's associate() function if it exists ───────────────────────

Object.values(models).forEach((model) => {
  if (typeof model.associate === 'function') {
    model.associate(models);
  }
});

// ─────────────────────────────────────────────────────────────────────────────

module.exports = models;
