'use strict';

const argon2 = require('argon2');
const crypto = require('crypto');

// Fixed Argon2id cost parameters for the *key derivation* path (ca.key.enc /
// user key.enc encryption key). These MUST NOT change once any data has been
// encrypted with a key derived under them — changing memoryCost/timeCost/
// parallelism/hashLength changes the derived key for the same password+salt,
// permanently locking out every already-encrypted private key on disk.
const KDF_PARAMS = Object.freeze({
  type: argon2.argon2id,
  memoryCost: 65536, // 64 MiB
  timeCost: 3,
  parallelism: 1,
  hashLength: 32, // bytes -> AES-256 key
});

const AES_ALGO = 'aes-256-gcm';
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

/** Login password hash — argon2id with its own random salt, fully self-describing. */
async function hashPassword(password) {
  return argon2.hash(password, { type: argon2.argon2id });
}

async function verifyPassword(hash, password) {
  try {
    return await argon2.verify(hash, password);
  } catch {
    return false;
  }
}

function generateKdfSalt() {
  return crypto.randomBytes(16).toString('base64');
}

/**
 * Derives the AES-256-GCM key used to encrypt/decrypt ca.key and user keys,
 * from the admin login password and the salt stored in admin.yml.
 * Returned Buffer must be discarded by the caller as soon as the operation
 * that needed it is done — never cached on the session.
 */
async function deriveEncryptionKey(password, saltBase64) {
  const salt = Buffer.from(saltBase64, 'base64');
  return argon2.hash(password, { ...KDF_PARAMS, salt, raw: true });
}

/** Encrypts a Buffer, returning a single Buffer: [iv(12)][authTag(16)][ciphertext]. */
function encryptBuffer(key, plaintext) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(AES_ALGO, key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, ciphertext]);
}

/** Reverses encryptBuffer(). Throws if the key is wrong or data was tampered with. */
function decryptBuffer(key, blob) {
  const iv = blob.subarray(0, IV_LENGTH);
  const authTag = blob.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
  const ciphertext = blob.subarray(IV_LENGTH + AUTH_TAG_LENGTH);
  const decipher = crypto.createDecipheriv(AES_ALGO, key, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/** Cryptographically random passphrase for one-time PKCS#12 export passwords. */
function generateExportPassword(length = 20) {
  const alphabet =
    'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#%^&*-_=+';
  const bytes = crypto.randomBytes(length);
  let out = '';
  for (let i = 0; i < length; i++) {
    out += alphabet[bytes[i] % alphabet.length];
  }
  return out;
}

module.exports = {
  KDF_PARAMS,
  hashPassword,
  verifyPassword,
  generateKdfSalt,
  deriveEncryptionKey,
  encryptBuffer,
  decryptBuffer,
  generateExportPassword,
};
