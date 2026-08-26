'use strict';

const adminStore = require('../services/adminStore');
const pkiStore = require('../services/pkiStore');

async function isFullySetUp() {
  return (await adminStore.isSetupComplete()) && (await pkiStore.isCaInitialized());
}

async function requireSetupComplete(req, res, next) {
  if (!(await isFullySetUp())) {
    return res.redirect('/setup');
  }
  next();
}

function requireLogin(req, res, next) {
  if (!req.session || !req.session.isAuthenticated) {
    return res.redirect('/login');
  }
  next();
}

module.exports = { isFullySetUp, requireSetupComplete, requireLogin };
