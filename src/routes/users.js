'use strict';

const express = require('express');
const router = express.Router();
const userStore = require('../services/userStore');
const revokedStore = require('../services/revokedStore');
const adminStore = require('../services/adminStore');
const pkiStore = require('../services/pkiStore');
const configStore = require('../services/configStore');
const { requireLogin } = require('../middleware/auth');
const { verifyCsrf } = require('../middleware/csrf');

router.post('/users', requireLogin, verifyCsrf, async (req, res) => {
  const name = (req.body.name || '').trim();
  const email = (req.body.email || '').trim();
  if (!name || !email) {
    req.flash('error', 'Name und E-Mail sind erforderlich.');
    return res.redirect('/');
  }
  await userStore.createUser(name, email);
  req.flash('success', `Nutzer "${name}" angelegt.`);
  res.redirect('/');
});

router.get('/users/:id/issue', requireLogin, async (req, res) => {
  const user = await userStore.getUser(req.params.id);
  if (!user) return res.status(404).render('error', { message: 'Nutzer nicht gefunden.' });
  res.render('confirm-password', {
    title: 'Neues Zertifikat ausstellen',
    description: `Für ${user.name} (${user.email}) wird ein neues Zertifikat erzeugt. Ein eventuell vorhandenes aktuelles Zertifikat wird auf die Sperrliste gesetzt.`,
    action: `/users/${user.id}/issue`,
    submitLabel: 'Zertifikat ausstellen',
    icon: 'file-badge',
    error: null,
  });
});

router.post('/users/:id/issue', requireLogin, verifyCsrf, async (req, res) => {
  const user = await userStore.getUser(req.params.id);
  if (!user) return res.status(404).render('error', { message: 'Nutzer nicht gefunden.' });

  const password = req.body.password || '';
  const renderForm = (error) =>
    res.render('confirm-password', {
      title: 'Neues Zertifikat ausstellen',
      description: `Für ${user.name} (${user.email}) wird ein neues Zertifikat erzeugt.`,
      action: `/users/${user.id}/issue`,
      submitLabel: 'Zertifikat ausstellen',
      icon: 'file-badge',
      error,
    });

  const valid = await adminStore.verifyPasswordOnly(password);
  if (!valid) return renderForm('Falsches Passwort.');

  try {
    if (user.currentSerial && user.certStatus === 'active') {
      await revokedStore.addRevoked({
        serial: user.currentSerial,
        userId: user.id,
        expiresAt: user.expiresAt,
        reason: 'reissued',
      });
    }
    const validityDays = await configStore.getCertValidityDays();
    const issued = await pkiStore.issueCertificateForUser(password, user, validityDays);
    await userStore.setCertIssued(user.id, issued);
    req.flash(
      'success',
      `Neues Zertifikat für ${user.name} ausgestellt (gültig bis ${new Date(issued.expiresAt).toLocaleDateString('de-DE')}).`
    );
    res.redirect('/');
  } catch (err) {
    renderForm(`Zertifikatserstellung fehlgeschlagen: ${err.message}`);
  }
});

router.post('/users/:id/deactivate', requireLogin, verifyCsrf, async (req, res) => {
  const user = await userStore.getUser(req.params.id);
  if (!user) return res.status(404).render('error', { message: 'Nutzer nicht gefunden.' });

  if (user.currentSerial && user.certStatus === 'active') {
    await revokedStore.addRevoked({
      serial: user.currentSerial,
      userId: user.id,
      expiresAt: user.expiresAt,
      reason: 'manually_deactivated',
    });
    await userStore.deactivateCert(user.id);
    req.flash('success', `Zertifikat für ${user.name} deaktiviert.`);
  } else {
    req.flash('error', `${user.name} hat kein aktives Zertifikat.`);
  }
  res.redirect('/');
});

module.exports = router;
