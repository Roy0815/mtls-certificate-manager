'use strict';

const express = require('express');
const router = express.Router();
const userStore = require('../services/userStore');
const { requireLogin } = require('../middleware/auth');

router.get('/', requireLogin, async (req, res) => {
  const users = await userStore.listUsers();
  const rows = users
    .map((u) => ({ ...u, displayStatus: userStore.getDisplayStatus(u) }))
    .sort((a, b) => a.name.localeCompare(b.name));
  res.render('dashboard', { users: rows, username: req.session.username });
});

module.exports = router;
