#!/usr/bin/env node
'use strict';

const adminStore = require('./src/services/adminStore');

async function main() {
  const [, , command] = process.argv;

  if (command === 'unlock-admin') {
    try {
      await adminStore.unlockAdmin();
      console.log('Admin-Konto wurde entsperrt (failed_attempts zurückgesetzt, locked=false).');
    } catch (err) {
      console.error(`Fehlgeschlagen: ${err.message}`);
      process.exit(1);
    }
    return;
  }

  console.log('Verwendung: node cli.js unlock-admin');
  process.exit(command ? 1 : 0);
}

main();
