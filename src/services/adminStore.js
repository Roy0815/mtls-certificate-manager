'use strict';

const yamlStore = require('./yamlStore');
const cryptoSvc = require('./crypto');
const env = require('../config/env');

const MAX_ATTEMPTS = env.MAX_LOGIN_ATTEMPTS;

async function isSetupComplete() {
  return yamlStore.exists(env.ADMIN_FILE);
}

async function getAdmin() {
  return yamlStore.readYaml(env.ADMIN_FILE, null);
}

/** Called once, during the setup wizard. Fails if an admin already exists. */
async function createAdmin(username, password) {
  const existing = await getAdmin();
  if (existing) {
    throw new Error('Admin account already exists');
  }
  const passwordHash = await cryptoSvc.hashPassword(password);
  const kdfSalt = cryptoSvc.generateKdfSalt();
  const admin = {
    username,
    passwordHash,
    kdfSalt,
    failedAttempts: 0,
    locked: false,
    createdAt: new Date().toISOString(),
  };
  await yamlStore.writeYaml(env.ADMIN_FILE, admin);
  return admin;
}

/**
 * Verifies username+password against the stored admin, enforcing the
 * permanent lockout after MAX_ATTEMPTS failures. Returns one of:
 *   { ok: true }
 *   { ok: false, reason: 'locked' | 'invalid' }
 */
async function verifyLogin(username, password) {
  return yamlStore.updateYaml(env.ADMIN_FILE, null, async (admin) => {
    if (!admin) {
      return { ok: false, reason: 'invalid' };
    }
    if (admin.locked) {
      return admin; // no-op write, just report locked below
    }
    if (admin.username !== username) {
      admin.failedAttempts = (admin.failedAttempts || 0) + 1;
      if (admin.failedAttempts >= MAX_ATTEMPTS) admin.locked = true;
      return admin;
    }
    const valid = await cryptoSvc.verifyPassword(admin.passwordHash, password);
    if (!valid) {
      admin.failedAttempts = (admin.failedAttempts || 0) + 1;
      if (admin.failedAttempts >= MAX_ATTEMPTS) admin.locked = true;
      return admin;
    }
    admin.failedAttempts = 0;
    return admin;
  }).then(async () => {
    // Re-read the (now updated) state to build the caller-facing verdict.
    const admin = await getAdmin();
    if (!admin) return { ok: false, reason: 'invalid' };
    if (admin.locked) return { ok: false, reason: 'locked' };
    if (admin.username === username && admin.failedAttempts === 0) {
      return { ok: true };
    }
    return { ok: false, reason: 'invalid' };
  });
}

/** Re-verifies just the password for an already-authenticated session (re-auth prompts). */
async function verifyPasswordOnly(password) {
  const admin = await getAdmin();
  if (!admin || admin.locked) return false;
  return cryptoSvc.verifyPassword(admin.passwordHash, password);
}

/** node cli.js unlock-admin */
async function unlockAdmin() {
  return yamlStore.updateYaml(env.ADMIN_FILE, null, (admin) => {
    if (!admin) throw new Error('No admin account found');
    admin.locked = false;
    admin.failedAttempts = 0;
    return admin;
  });
}

module.exports = {
  isSetupComplete,
  getAdmin,
  createAdmin,
  verifyLogin,
  verifyPasswordOnly,
  unlockAdmin,
};
