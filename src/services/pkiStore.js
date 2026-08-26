'use strict';

const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const env = require('../config/env');
const pki = require('./pki');
const cryptoSvc = require('./crypto');
const adminStore = require('./adminStore');
const yamlStore = require('./yamlStore');

async function isCaInitialized() {
  return (await yamlStore.exists(env.CA_CERT_PATH)) && (await yamlStore.exists(env.CA_KEY_ENC_PATH));
}

/** Derives the AES key from the admin's login password + stored KDF salt. Caller must zero it after use. */
async function deriveKeyFromPassword(password) {
  const admin = await adminStore.getAdmin();
  if (!admin) throw new Error('Admin account not set up yet');
  return cryptoSvc.deriveEncryptionKey(password, admin.kdfSalt);
}

async function initializeCa(password, orgName) {
  const { certPem, privateKeyPem } = await pki.generateCA(orgName);
  const key = await deriveKeyFromPassword(password);
  try {
    const encrypted = cryptoSvc.encryptBuffer(key, Buffer.from(privateKeyPem, 'utf8'));
    await fsp.mkdir(env.PKI_DIR, { recursive: true });
    await fsp.writeFile(env.CA_CERT_PATH, certPem, { mode: 0o644 });
    await fsp.writeFile(env.CA_KEY_ENC_PATH, encrypted, { mode: 0o600 });
  } finally {
    key.fill(0);
  }
}

async function loadCaCertPem() {
  return fsp.readFile(env.CA_CERT_PATH, 'utf8');
}

/** Decrypts and returns the CA private key PEM. Caller must not cache this beyond the current operation. */
async function loadCaPrivateKeyPem(password) {
  const key = await deriveKeyFromPassword(password);
  try {
    const blob = await fsp.readFile(env.CA_KEY_ENC_PATH);
    const plaintext = cryptoSvc.decryptBuffer(key, blob);
    return plaintext.toString('utf8');
  } finally {
    key.fill(0);
  }
}

function certDir(userId) {
  return path.join(env.CERTS_DIR, userId);
}

/**
 * Issues a new certificate for a user, encrypting the private key at rest.
 * Returns everything userStore/revokedStore need to update their records —
 * it does NOT touch users.yml/revoked.yml itself (caller's responsibility,
 * so this module stays purely about PKI material on disk).
 */
async function issueCertificateForUser(password, user, validityDays) {
  const caCertPem = await loadCaCertPem();
  const caPrivateKeyPem = await loadCaPrivateKeyPem(password);
  const result = await pki.issueCertificate(
    caCertPem,
    caPrivateKeyPem,
    { commonName: user.name, email: user.email },
    validityDays
  );

  const key = await deriveKeyFromPassword(password);
  try {
    const dir = certDir(user.id);
    await fsp.mkdir(dir, { recursive: true });
    const encryptedKey = cryptoSvc.encryptBuffer(key, Buffer.from(result.privateKeyPem, 'utf8'));
    await fsp.writeFile(path.join(dir, `${result.serial}.crt.pem`), result.certPem, { mode: 0o644 });
    await fsp.writeFile(path.join(dir, `${result.serial}.key.enc`), encryptedKey, { mode: 0o600 });
  } finally {
    key.fill(0);
  }

  return {
    serial: result.serial,
    issuedAt: result.issuedAt,
    expiresAt: result.expiresAt,
  };
}

/** Reads back a previously issued cert + decrypted key, e.g. to build a PKCS#12. */
async function readCertAndKey(userId, serial, password) {
  const dir = certDir(userId);
  const certPem = await fsp.readFile(path.join(dir, `${serial}.crt.pem`), 'utf8');
  const key = await deriveKeyFromPassword(password);
  try {
    const blob = await fsp.readFile(path.join(dir, `${serial}.key.enc`));
    const plaintext = cryptoSvc.decryptBuffer(key, blob);
    return { certPem, privateKeyPem: plaintext.toString('utf8') };
  } finally {
    key.fill(0);
  }
}

async function exportCrl(password, entries, crlNumber, validityDays) {
  const caCertPem = await loadCaCertPem();
  const caPrivateKeyPem = await loadCaPrivateKeyPem(password);
  const crlPem = pki.buildCrl(caCertPem, caPrivateKeyPem, entries, crlNumber, validityDays);
  await fsp.writeFile(env.CRL_FILE, crlPem, { mode: 0o644 });
  return crlPem;
}

module.exports = {
  isCaInitialized,
  initializeCa,
  loadCaCertPem,
  issueCertificateForUser,
  readCertAndKey,
  exportCrl,
};
