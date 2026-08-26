'use strict';

const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const yaml = require('js-yaml');

// Single-process app, single YAML "database" per file — an in-memory
// per-path queue is enough to stop concurrent request handlers from
// interleaving reads/writes and corrupting a file. No cross-process
// locking is attempted because this app only ever runs as one container.
const queues = new Map();

function enqueue(filePath, task) {
  const prev = queues.get(filePath) || Promise.resolve();
  const next = prev.then(task, task);
  queues.set(
    filePath,
    next.catch(() => {})
  );
  return next;
}

async function readYaml(filePath, fallback) {
  return enqueue(filePath, async () => {
    try {
      const raw = await fsp.readFile(filePath, 'utf8');
      const data = yaml.load(raw);
      return data === undefined || data === null ? fallback : data;
    } catch (err) {
      if (err.code === 'ENOENT') return fallback;
      throw err;
    }
  });
}

async function writeYaml(filePath, data) {
  return enqueue(filePath, async () => {
    await fsp.mkdir(path.dirname(filePath), { recursive: true });
    const raw = yaml.dump(data, { noRefs: true, lineWidth: 120 });
    const tmpPath = `${filePath}.${process.pid}.${Date.now()}.tmp`;
    await fsp.writeFile(tmpPath, raw, { mode: 0o600 });
    await fsp.rename(tmpPath, filePath);
  });
}

/** Read-modify-write a YAML file atomically with respect to other calls on the same path. */
async function updateYaml(filePath, fallback, mutator) {
  return enqueue(filePath, async () => {
    let data;
    try {
      const raw = await fsp.readFile(filePath, 'utf8');
      const loaded = yaml.load(raw);
      data = loaded === undefined || loaded === null ? fallback : loaded;
    } catch (err) {
      if (err.code === 'ENOENT') data = fallback;
      else throw err;
    }
    const result = await mutator(data);
    const toWrite = result === undefined ? data : result;
    await fsp.mkdir(path.dirname(filePath), { recursive: true });
    const raw = yaml.dump(toWrite, { noRefs: true, lineWidth: 120 });
    const tmpPath = `${filePath}.${process.pid}.${Date.now()}.tmp`;
    await fsp.writeFile(tmpPath, raw, { mode: 0o600 });
    await fsp.rename(tmpPath, filePath);
    return toWrite;
  });
}

async function exists(filePath) {
  try {
    await fsp.access(filePath, fs.constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

module.exports = { readYaml, writeYaml, updateYaml, exists };
