'use strict';

const express = require('express');
const path = require('path');
const session = require('express-session');
const flash = require('connect-flash');
const helmet = require('helmet');

const env = require('./config/env');
const configStore = require('./services/configStore');
const { csrfToken } = require('./middleware/csrf');
const icons = require('./config/icons');

async function createApp() {
  const app = express();
  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, 'views'));
  app.locals.icons = icons;
  // Needed so express-session's cookie.secure:'auto' and rate-limiter IP
  // detection work correctly behind a reverse proxy (e.g. Nginx Proxy Manager)
  // terminating TLS.
  app.set('trust proxy', 1);

  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", 'https://fonts.googleapis.com'],
          fontSrc: ["'self'", 'https://fonts.gstatic.com'],
          scriptSrc: ["'self'"],
          imgSrc: ["'self'", 'data:'],
        },
      },
    })
  );
  app.use(express.urlencoded({ extended: false }));
  app.use(express.static(path.join(__dirname, 'public')));

  // No DBMS means no Redis/SQL-backed session store either; express-session's
  // in-memory store is fine for a single-container internal admin tool — the
  // only cost is that everyone is logged out on container restart.
  const sessionSecret = env.SESSION_SECRET || (await configStore.getOrCreateSessionSecret());
  app.use(
    session({
      secret: sessionSecret,
      name: 'mtls_admin_sid',
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        secure: 'auto', // requires 'trust proxy' above to detect HTTPS behind a reverse proxy
        sameSite: 'strict',
        maxAge: 1000 * 60 * 60 * 8,
      },
    })
  );
  app.use(flash());
  app.use(csrfToken);
  app.use((req, res, next) => {
    res.locals.successMessages = req.flash('success');
    res.locals.errorMessages = req.flash('error');
    res.locals.username = req.session && req.session.username;
    next();
  });

  app.use('/', require('./routes/setup'));
  app.use('/', require('./routes/auth'));
  app.use('/', require('./routes/dashboard'));
  app.use('/', require('./routes/users'));
  app.use('/', require('./routes/crl'));
  app.use('/', require('./routes/share'));

  app.use((req, res) => {
    res.status(404).render('error', { message: 'Seite nicht gefunden.' });
  });

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).render('error', { message: 'Ein unerwarteter Fehler ist aufgetreten.' });
  });

  return app;
}

module.exports = createApp;
