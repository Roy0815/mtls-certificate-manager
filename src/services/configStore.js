'use strict';

const crypto = require('crypto');
const yamlStore = require('./yamlStore');
const env = require('../config/env');

async function getConfig() {
  return yamlStore.readYaml(env.CONFIG_FILE, {});
}

async function getCertValidityDays() {
  const config = await getConfig();
  return config.certValidityDaysOverride || env.CERT_VALIDITY_DAYS;
}

async function setCertValidityOverride(days) {
  return yamlStore.updateYaml(env.CONFIG_FILE, {}, (data) => {
    data.certValidityDaysOverride = days;
    return data;
  });
}

/**
 * express-session needs a stable signing secret across restarts, but the
 * spec's env var list has no slot for one. Generate it once on first boot
 * and persist it in config.yml rather than inventing a new required env var.
 */
async function getOrCreateSessionSecret() {
  return yamlStore.updateYaml(env.CONFIG_FILE, {}, (data) => {
    if (!data.sessionSecret) {
      data.sessionSecret = crypto.randomBytes(48).toString('hex');
    }
    return data;
  }).then((data) => data.sessionSecret);
}

/** RFC 5280 §5.2.3 requires CRL Number to increase monotonically across exports. */
async function getNextCrlNumber() {
  return yamlStore.updateYaml(env.CONFIG_FILE, {}, (data) => {
    data.crlNumber = (data.crlNumber || 0) + 1;
    return data;
  }).then((data) => data.crlNumber);
}

module.exports = {
  getConfig,
  getCertValidityDays,
  setCertValidityOverride,
  getOrCreateSessionSecret,
  getNextCrlNumber,
};
