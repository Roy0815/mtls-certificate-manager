'use strict';

const createApp = require('./app');
const env = require('./config/env');

createApp()
  .then((app) => {
    app.listen(env.PORT, () => {
      console.log(`mTLS certificate manager listening on port ${env.PORT}`);
    });
  })
  .catch((err) => {
    console.error('Failed to start application:', err);
    process.exit(1);
  });
