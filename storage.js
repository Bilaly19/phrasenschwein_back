const fs = require('fs/promises');
const path = require('path');
const { logWarn, logError } = require('./logger');

const defaultData = {
  valuePerClick: 0.5
};

const defaultUsers = {
  users: {},
  sessions: {}
};

async function ensureDir(filePath) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
}

async function atomicWriteJson(filePath, data) {
  await ensureDir(filePath);
  const tmpPath = `${filePath}.tmp`;
  const json = JSON.stringify(data, null, 2);

  await fs.writeFile(tmpPath, json, 'utf-8');
  await fs.rename(tmpPath, filePath);
}

async function readJsonWithDefault(filePath, fallback, label) {
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    const parsed = JSON.parse(content);
    return { ...fallback, ...parsed };
  } catch (error) {
    if (error.code === 'ENOENT') {
      logWarn(`${label} file fehlt, initialisiere neu.`, { filePath });
      await atomicWriteJson(filePath, fallback);
      return { ...fallback };
    }

    if (error.name === 'SyntaxError') {
      logError(`${label} Datei enthält ungültiges JSON, setze auf Default zurück.`, { filePath });
      await atomicWriteJson(filePath, fallback);
      return { ...fallback };
    }

    throw error;
  }
}

function normalizeData(data) {
  const normalized = { ...defaultData, ...(data || {}) };
  if (typeof normalized.valuePerClick !== 'number') {
    normalized.valuePerClick = defaultData.valuePerClick;
  }
  return normalized;
}

function normalizeUsers(data) {
  const normalized = { ...defaultUsers, ...(data || {}) };
  if (!normalized.users || typeof normalized.users !== 'object') {
    normalized.users = {};
  }
  if (!normalized.sessions || typeof normalized.sessions !== 'object') {
    normalized.sessions = {};
  }
  return normalized;
}

async function readData(dataPath) {
  const data = await readJsonWithDefault(dataPath, defaultData, 'data.json');
  return normalizeData(data);
}

async function writeData(dataPath, data) {
  return atomicWriteJson(dataPath, normalizeData(data));
}

async function readUsers(usersPath) {
  const users = await readJsonWithDefault(usersPath, defaultUsers, 'users.json');
  return normalizeUsers(users);
}

async function writeUsers(usersPath, users) {
  return atomicWriteJson(usersPath, normalizeUsers(users));
}

module.exports = {
  readData,
  writeData,
  readUsers,
  writeUsers
};
