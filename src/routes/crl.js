'use strict';

const express = require('express');
const router = express.Router();
const adminStore = require('../services/adminStore');
const revokedStore = require('../services/revokedStore');
const pkiStore = require('../services/pkiStore');
const configStore = require('../services/configStore');
const env = require('../config/env');
const { requireLogin } = require('../middleware/auth');
const { verifyCsrf } = require('../middleware/csrf');

const DESCRIPTION =
  'Erzeugt eine aktuelle Sperrliste (CRL) im PEM-Format, signiert mit dem CA-Schlüssel. ' +
  `Enthält alle widerrufenen, aber noch nicht regulär abgelaufenen Zertifikate. Gültig für ${env.CRL_VALIDITY_DAYS} Tage.`;

// ca.crt is stored unencrypted on disk (see pkiStore.initializeCa) — it's the
// public half of the CA, meant for distribution to whatever terminates mTLS
// (e.g. Nginx Proxy Manager), so this is a plain download with no password
// step, unlike every other export in this file.
router.get('/ca/export', requireLogin, async (req, res) => {
  const caCertPem = await pkiStore.loadCaCertPem();
  res.setHeader('Content-Type', 'application/x-x509-ca-cert');
  res.setHeader('Content-Disposition', 'attachment; filename="ca.crt"');
  res.send(caCertPem);
});

router.get('/crl/export', requireLogin, async (req, res) => {
  res.render('confirm-password', {
    title: 'CRL exportieren',
    description: DESCRIPTION,
    action: '/crl/export',
    submitLabel: 'CRL exportieren',
    icon: 'file-down',
    error: null,
  });
});

router.post('/crl/export', requireLogin, verifyCsrf, async (req, res) => {
  const password = req.body.password || '';
  const renderForm = (error) =>
    res.render('confirm-password', {
      title: 'CRL exportieren',
      description: DESCRIPTION,
      action: '/crl/export',
      submitLabel: 'CRL exportieren',
      icon: 'file-down',
      error,
    });

  const valid = await adminStore.verifyPasswordOnly(password);
  if (!valid) return renderForm('Falsches Passwort.');

  try {
    const entries = await revokedStore.listActiveForCrl();
    const crlNumber = await configStore.getNextCrlNumber();
    const crlPem = await pkiStore.exportCrl(password, entries, crlNumber, env.CRL_VALIDITY_DAYS);
    res.setHeader('Content-Type', 'application/pkix-crl');
    res.setHeader('Content-Disposition', 'attachment; filename="crl.pem"');
    res.send(crlPem);
  } catch (err) {
    renderForm(`CRL-Export fehlgeschlagen: ${err.message}`);
  }
});

module.exports = router;
