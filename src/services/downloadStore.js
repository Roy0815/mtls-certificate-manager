'use strict';

const crypto = require('crypto');

// Ephemeral, in-memory, single-use handoff for a freshly built .p12 buffer
// between the password-confirmation POST and the actual file download GET.
// Same "no cross-process state" assumption as express-session's in-memory
// store (see app.js) — fine for a single-container app, lost on restart.
const TTL_MS = 5 * 60 * 1000;
const pending = new Map();

function cleanupExpired() {
  const now = Date.now();
  for (const [token, entry] of pending) {
    if (entry.expiresAt <= now) pending.delete(token);
  }
}

function stash(buffer, filename) {
  cleanupExpired();
  const token = crypto.randomBytes(24).toString('hex');
  pending.set(token, { buffer, filename, expiresAt: Date.now() + TTL_MS });
  return token;
}

function take(token) {
  cleanupExpired();
  const entry = pending.get(token);
  if (!entry) return null;
  pending.delete(token);
  return entry;
}

module.exports = { stash, take };
