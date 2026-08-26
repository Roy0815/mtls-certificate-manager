'use strict';

const express = require('express');
const router = express.Router();
const userStore = require('../services/userStore');
const pkiStore = require('../services/pkiStore');
const pki = require('../services/pki');
const { requireLogin } = require('../middleware/auth');

const DAY_MS = 24 * 60 * 60 * 1000;
// Cert is flagged "läuft ab" (amber) instead of plain "aktiv" (green) inside
// this window — a presentation-only tier layered on top of the three
// documented displayStatus values (active/expired/none), not a stored field.
const EXPIRING_SOON_DAYS = 30;

router.get('/', requireLogin, async (req, res) => {
  const users = await userStore.listUsers();
  const now = Date.now();
  const rows = users
    .map((u) => {
      const displayStatus = userStore.getDisplayStatus(u);
      let daysRemaining = null;
      let percentRemaining = null;
      let expiringSoon = false;
      if (displayStatus === 'active') {
        const expiresAt = new Date(u.expiresAt).getTime();
        const issuedAt = new Date(u.issuedAt).getTime();
        daysRemaining = Math.max(0, Math.ceil((expiresAt - now) / DAY_MS));
        percentRemaining = Math.max(
          0,
          Math.min(100, Math.round(((expiresAt - now) / (expiresAt - issuedAt)) * 100))
        );
        expiringSoon = daysRemaining <= EXPIRING_SOON_DAYS;
      }
      return { ...u, displayStatus, daysRemaining, percentRemaining, expiringSoon };
    })
    .sort((a, b) => a.name.localeCompare(b.name));

  const caCertPem = await pkiStore.loadCaCertPem();
  const caExpiresAt = pki.getCertExpiry(caCertPem);
  const activeCount = rows.filter((u) => u.displayStatus === 'active').length;

  res.render('dashboard', {
    users: rows,
    username: req.session.username,
    activeCount,
    caExpiresAt,
  });
});

module.exports = router;
