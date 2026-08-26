'use strict';

const express = require('express');
const router = express.Router();
const adminStore = require('../services/adminStore');
const { isFullySetUp } = require('../middleware/auth');
const { verifyCsrf } = require('../middleware/csrf');
const { loginLimiter } = require('../middleware/rateLimiter');

router.get('/login', async (req, res) => {
  if (req.session.isAuthenticated) return res.redirect('/');
  if (!(await isFullySetUp())) return res.redirect('/setup');
  res.render('login', { error: null });
});

router.post('/login', loginLimiter, verifyCsrf, async (req, res) => {
  const username = (req.body.username || '').trim();
  const password = req.body.password || '';

  const result = await adminStore.verifyLogin(username, password);
  if (!result.ok) {
    const message =
      result.reason === 'locked'
        ? 'Dieses Konto ist gesperrt (zu viele Fehlversuche). Entsperren nur manuell möglich, siehe README (node cli.js unlock-admin).'
        : 'Benutzername oder Passwort ist falsch.';
    return res.render('login', { error: message });
  }

  // Regenerate the session id on privilege change to prevent session fixation.
  req.session.regenerate((err) => {
    if (err) {
      return res.status(500).render('error', { message: 'Login fehlgeschlagen. Bitte erneut versuchen.' });
    }
    req.session.isAuthenticated = true;
    req.session.username = username;
    res.redirect('/');
  });
});

router.post('/logout', verifyCsrf, (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

module.exports = router;
