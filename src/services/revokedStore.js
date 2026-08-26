'use strict';

const yamlStore = require('./yamlStore');
const env = require('../config/env');

async function listRevoked() {
  const data = await yamlStore.readYaml(env.REVOKED_FILE, { revoked: [] });
  return data.revoked || [];
}

/**
 * @param {object} entry
 * @param {string} entry.serial
 * @param {string} entry.userId
 * @param {string} entry.expiresAt - the revoked cert's own expiry, kept here
 *   (not looked up from users.yml) because the user record gets overwritten
 *   on reissue/deactivate and would otherwise lose this.
 * @param {'reissued'|'manually_deactivated'} entry.reason
 */
async function addRevoked({ serial, userId, expiresAt, reason }) {
  return yamlStore.updateYaml(env.REVOKED_FILE, { revoked: [] }, (data) => {
    data.revoked = data.revoked || [];
    data.revoked.push({
      serial,
      userId,
      expiresAt,
      reason,
      revokedAt: new Date().toISOString(),
    });
    return data;
  });
}

/** Entries that still matter for a CRL: revoked, and not yet naturally expired. */
async function listActiveForCrl() {
  const all = await listRevoked();
  const now = Date.now();
  return all.filter((r) => new Date(r.expiresAt).getTime() > now);
}

module.exports = { listRevoked, addRevoked, listActiveForCrl };
