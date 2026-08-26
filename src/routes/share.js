'use strict';

const express = require('express');
const router = express.Router();
const userStore = require('../services/userStore');
const adminStore = require('../services/adminStore');
const pkiStore = require('../services/pkiStore');
const pki = require('../services/pki');
const cryptoSvc = require('../services/crypto');
const gokapi = require('../services/gokapi');
const downloadStore = require('../services/downloadStore');
const env = require('../config/env');
const { requireLogin } = require('../middleware/auth');
const { verifyCsrf } = require('../middleware/csrf');

function description(user) {
  return `Erstellt eine passwortgeschützte .p12-Datei für ${user.name} und lädt sie zu GoKapi hoch ` +
    `(max. ${env.GOKAPI_SHARE_MAX_DOWNLOADS} Download(s), Ablauf nach ca. ${env.GOKAPI_SHARE_EXPIRY_HOURS}h).`;
}

function downloadDescription(user) {
  return `Erstellt eine passwortgeschützte .p12-Datei für ${user.name} und lädt sie direkt herunter ` +
    `(kein GoKapi-Upload, die Datei bleibt lokal).`;
}

router.get('/users/:id/share', requireLogin, async (req, res) => {
  const user = await userStore.getUser(req.params.id);
  if (!user) return res.status(404).render('error', { message: 'Nutzer nicht gefunden.' });
  if (!user.currentSerial || user.certStatus !== 'active') {
    req.flash('error', `${user.name} hat kein aktives Zertifikat zum Versenden.`);
    return res.redirect('/');
  }
  res.render('confirm-password', {
    title: 'Zertifikat per Einmal-Link versenden',
    description: description(user),
    action: `/users/${user.id}/share`,
    submitLabel: 'Versenden',
    icon: 'send',
    error: null,
  });
});

router.post('/users/:id/share', requireLogin, verifyCsrf, async (req, res) => {
  const user = await userStore.getUser(req.params.id);
  if (!user) return res.status(404).render('error', { message: 'Nutzer nicht gefunden.' });

  const password = req.body.password || '';
  const renderForm = (error) =>
    res.render('confirm-password', {
      title: 'Zertifikat per Einmal-Link versenden',
      description: description(user),
      action: `/users/${user.id}/share`,
      submitLabel: 'Versenden',
      icon: 'send',
      error,
    });

  if (!user.currentSerial || user.certStatus !== 'active') {
    return renderForm('Kein aktives Zertifikat vorhanden.');
  }

  const valid = await adminStore.verifyPasswordOnly(password);
  if (!valid) return renderForm('Falsches Passwort.');

  try {
    const { certPem, privateKeyPem } = await pkiStore.readCertAndKey(user.id, user.currentSerial, password);
    const caCertPem = await pkiStore.loadCaCertPem();
    const exportPassword = cryptoSvc.generateExportPassword();
    const p12Buffer = pki.buildPkcs12(certPem, privateKeyPem, caCertPem, exportPassword);
    const safeName = user.name.replace(/[^a-z0-9_-]+/gi, '_');
    const filename = `${safeName}-${user.currentSerial.slice(0, 8)}.p12`;

    const upload = await gokapi.uploadFile(p12Buffer, filename, {
      allowedDownloads: env.GOKAPI_SHARE_MAX_DOWNLOADS,
      expiryHours: env.GOKAPI_SHARE_EXPIRY_HOURS,
    });

    res.render('share-result', {
      user,
      downloadUrl: upload.downloadUrl,
      exportPassword,
      expireAtString: upload.expireAtString,
    });
  } catch (err) {
    renderForm(`Versand fehlgeschlagen: ${err.message}`);
  }
});

router.get('/users/:id/download', requireLogin, async (req, res) => {
  const user = await userStore.getUser(req.params.id);
  if (!user) return res.status(404).render('error', { message: 'Nutzer nicht gefunden.' });
  if (!user.currentSerial || user.certStatus !== 'active') {
    req.flash('error', `${user.name} hat kein aktives Zertifikat zum Herunterladen.`);
    return res.redirect('/');
  }
  res.render('confirm-password', {
    title: 'Zertifikat herunterladen',
    description: downloadDescription(user),
    action: `/users/${user.id}/download`,
    submitLabel: 'Herunterladen',
    icon: 'download',
    error: null,
  });
});

router.post('/users/:id/download', requireLogin, verifyCsrf, async (req, res) => {
  const user = await userStore.getUser(req.params.id);
  if (!user) return res.status(404).render('error', { message: 'Nutzer nicht gefunden.' });

  const password = req.body.password || '';
  const renderForm = (error) =>
    res.render('confirm-password', {
      title: 'Zertifikat herunterladen',
      description: downloadDescription(user),
      action: `/users/${user.id}/download`,
      submitLabel: 'Herunterladen',
      icon: 'download',
      error,
    });

  if (!user.currentSerial || user.certStatus !== 'active') {
    return renderForm('Kein aktives Zertifikat vorhanden.');
  }

  const valid = await adminStore.verifyPasswordOnly(password);
  if (!valid) return renderForm('Falsches Passwort.');

  try {
    const { certPem, privateKeyPem } = await pkiStore.readCertAndKey(user.id, user.currentSerial, password);
    const caCertPem = await pkiStore.loadCaCertPem();
    const exportPassword = cryptoSvc.generateExportPassword();
    const p12Buffer = pki.buildPkcs12(certPem, privateKeyPem, caCertPem, exportPassword);
    const safeName = user.name.replace(/[^a-z0-9_-]+/gi, '_');
    const filename = `${safeName}-${user.currentSerial.slice(0, 8)}.p12`;

    const token = downloadStore.stash(p12Buffer, filename);

    res.render('download-result', {
      user,
      exportPassword,
      downloadPath: `/downloads/${token}`,
    });
  } catch (err) {
    renderForm(`Download fehlgeschlagen: ${err.message}`);
  }
});

router.get('/downloads/:token', requireLogin, (req, res) => {
  const entry = downloadStore.take(req.params.token);
  if (!entry) {
    req.flash('error', 'Download-Link abgelaufen oder bereits verwendet.');
    return res.redirect('/');
  }
  res.set('Content-Type', 'application/x-pkcs12');
  res.set('Content-Disposition', `attachment; filename="${entry.filename}"`);
  res.send(entry.buffer);
});

module.exports = router;
