'use strict';

const express = require('express');
const router = express.Router();
const adminStore = require('../services/adminStore');
const pkiStore = require('../services/pkiStore');
const { verifyCsrf } = require('../middleware/csrf');

// Same floor as most modern password-manager defaults. This password isn't
// just a login check — it's also fed into the Argon2id KDF that protects
// ca.key/user.key on disk, so it deserves a stronger minimum than a typical
// "just logging into a website" password.
const MIN_PASSWORD_LENGTH = 12;

router.get('/setup', async (req, res) => {
  const adminExists = await adminStore.isSetupComplete();
  const caReady = adminExists && (await pkiStore.isCaInitialized());
  if (caReady) return res.redirect('/login');
  res.render('setup', { step: adminExists ? 2 : 1, error: null });
});

router.post('/setup/admin', verifyCsrf, async (req, res) => {
  if (await adminStore.isSetupComplete()) return res.redirect('/setup');

  const username = (req.body.username || '').trim();
  const { password, confirmPassword } = req.body;

  if (!username || !password) {
    return res.render('setup', { step: 1, error: 'Benutzername und Passwort sind erforderlich.' });
  }
  if (password.length < MIN_PASSWORD_LENGTH) {
    return res.render('setup', {
      step: 1,
      error: `Das Passwort muss mindestens ${MIN_PASSWORD_LENGTH} Zeichen lang sein (es wird auch zur Verschlüsselung der privaten Schlüssel verwendet).`,
    });
  }
  if (password !== confirmPassword) {
    return res.render('setup', { step: 1, error: 'Die Passwörter stimmen nicht überein.' });
  }

  await adminStore.createAdmin(username, password);
  res.redirect('/setup');
});

router.post('/setup/ca', verifyCsrf, async (req, res) => {
  const adminExists = await adminStore.isSetupComplete();
  if (!adminExists) return res.redirect('/setup');
  if (await pkiStore.isCaInitialized()) return res.redirect('/login');

  const { password } = req.body;
  const orgName = (req.body.orgName || '').trim() || 'mTLS Certificate Manager';

  const valid = await adminStore.verifyPasswordOnly(password || '');
  if (!valid) {
    return res.render('setup', { step: 2, error: 'Falsches Passwort.' });
  }

  try {
    await pkiStore.initializeCa(password, orgName);
  } catch (err) {
    return res.render('setup', { step: 2, error: `CA-Erstellung fehlgeschlagen: ${err.message}` });
  }
  res.redirect('/login');
});

module.exports = router;
