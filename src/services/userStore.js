'use strict';

const crypto = require('crypto');
const yamlStore = require('./yamlStore');
const env = require('../config/env');

async function listUsers() {
  const data = await yamlStore.readYaml(env.USERS_FILE, { users: [] });
  return data.users || [];
}

async function getUser(id) {
  const users = await listUsers();
  return users.find((u) => u.id === id) || null;
}

async function createUser(name, email) {
  return yamlStore.updateYaml(env.USERS_FILE, { users: [] }, (data) => {
    data.users = data.users || [];
    const user = {
      id: crypto.randomUUID(),
      name,
      email,
      currentSerial: null,
      issuedAt: null,
      expiresAt: null,
      certStatus: null, // null = never issued, 'active', 'deactivated'
      createdAt: new Date().toISOString(),
    };
    data.users.push(user);
    return data;
  }).then((data) => data.users[data.users.length - 1]);
}

async function setCertIssued(id, { serial, issuedAt, expiresAt }) {
  return yamlStore.updateYaml(env.USERS_FILE, { users: [] }, (data) => {
    const user = (data.users || []).find((u) => u.id === id);
    if (!user) throw new Error(`Unknown user id ${id}`);
    user.currentSerial = serial;
    user.issuedAt = issuedAt;
    user.expiresAt = expiresAt;
    user.certStatus = 'active';
    return data;
  });
}

async function deactivateCert(id) {
  return yamlStore.updateYaml(env.USERS_FILE, { users: [] }, (data) => {
    const user = (data.users || []).find((u) => u.id === id);
    if (!user) throw new Error(`Unknown user id ${id}`);
    user.currentSerial = null;
    user.issuedAt = null;
    user.expiresAt = null;
    user.certStatus = 'deactivated';
    return data;
  });
}

/** active | expired | none — what the dashboard shows in the "Zertifikat-Status" column. */
function getDisplayStatus(user) {
  if (!user.currentSerial || user.certStatus !== 'active') return 'none';
  if (user.expiresAt && new Date(user.expiresAt).getTime() < Date.now()) {
    return 'expired';
  }
  return 'active';
}

module.exports = {
  listUsers,
  getUser,
  createUser,
  setCertIssued,
  deactivateCert,
  getDisplayStatus,
};
