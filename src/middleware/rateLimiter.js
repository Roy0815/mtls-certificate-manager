'use strict';

const rateLimit = require('express-rate-limit');

// Defense in depth alongside the permanent 3-attempt account lock: this caps
// request *rate* (per source IP) independent of which username is targeted,
// so it also slows down username enumeration / distributed guessing across
// many accounts before the per-account lock would ever trigger.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Zu viele Login-Versuche. Bitte später erneut versuchen.',
});

module.exports = { loginLimiter };
