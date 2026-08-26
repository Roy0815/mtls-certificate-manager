'use strict';

const crypto = require('crypto');

/** Synchronizer-token CSRF pattern: a per-session secret, echoed back in every form. */
function csrfToken(req, res, next) {
  if (!req.session.csrfSecret) {
    req.session.csrfSecret = crypto.randomBytes(32).toString('hex');
  }
  res.locals.csrfToken = req.session.csrfSecret;
  next();
}

function timingSafeStringEqual(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function verifyCsrf(req, res, next) {
  const token = req.body && req.body._csrf;
  const secret = req.session && req.session.csrfSecret;
  if (!secret || !token || !timingSafeStringEqual(token, secret)) {
    return res.status(403).render('error', {
      message: 'Sicherheitsprüfung fehlgeschlagen (ungültiges CSRF-Token). Bitte Seite neu laden und erneut versuchen.',
    });
  }
  next();
}

module.exports = { csrfToken, verifyCsrf };
