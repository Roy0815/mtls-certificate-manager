'use strict';

const path = require('path');

function parseIntEnv(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const n = parseInt(raw, 10);
  return Number.isFinite(n) ? n : fallback;
}

const DATA_DIR = process.env.DATA_DIR || path.join(process.cwd(), 'data');
const PKI_DIR = process.env.PKI_DIR || path.join(process.cwd(), 'pki');

module.exports = {
  PORT: parseIntEnv('PORT', 3000),
  DATA_DIR,
  PKI_DIR,
  CERTS_DIR: path.join(PKI_DIR, 'certs'),
  CA_CERT_PATH: path.join(PKI_DIR, 'ca.crt'),
  CA_KEY_ENC_PATH: path.join(PKI_DIR, 'ca.key.enc'),
  ADMIN_FILE: path.join(DATA_DIR, 'admin.yml'),
  USERS_FILE: path.join(DATA_DIR, 'users.yml'),
  REVOKED_FILE: path.join(DATA_DIR, 'revoked.yml'),
  CONFIG_FILE: path.join(DATA_DIR, 'config.yml'),
  CRL_FILE: path.join(PKI_DIR, 'crl.pem'),

  CERT_VALIDITY_DAYS: parseIntEnv('CERT_VALIDITY_DAYS', 365),
  CRL_VALIDITY_DAYS: parseIntEnv('CRL_VALIDITY_DAYS', 7),
  CA_VALIDITY_DAYS: parseIntEnv('CA_VALIDITY_DAYS', 3650),

  SESSION_SECRET: process.env.SESSION_SECRET || null,
  MAX_LOGIN_ATTEMPTS: 3,

  GOKAPI_API_URL: process.env.GOKAPI_API_URL || '',
  GOKAPI_API_KEY: process.env.GOKAPI_API_KEY || '',
  GOKAPI_SHARE_EXPIRY_HOURS: parseIntEnv('GOKAPI_SHARE_EXPIRY_HOURS', 48),
  GOKAPI_SHARE_MAX_DOWNLOADS: parseIntEnv('GOKAPI_SHARE_MAX_DOWNLOADS', 1),

  NODE_ENV: process.env.NODE_ENV || 'production',
};
