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

router.get('/crl/export', requireLogin, async (req, res) => {
  res.render('confirm-password', {
    title: 'CRL exportieren',
    description: DESCRIPTION,
    action: '/crl/export',
    submitLabel: 'CRL exportieren',
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
