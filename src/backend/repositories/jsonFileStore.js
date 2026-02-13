const fs = require('node:fs/promises');
const path = require('node:path');
const writeLocks = new Map();

async function ensureDir(filePath) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
}

async function writeJsonAtomic(filePath, data) {
  await ensureDir(filePath);
  const tmpPath = `${filePath}.tmp`;
  await fs.writeFile(tmpPath, JSON.stringify(data, null, 2), 'utf-8');
  await fs.rename(tmpPath, filePath);
}

async function readJsonOrDefault(filePath, fallback) {
  try {
    const raw = await fs.readFile(filePath, 'utf-8');
    const parsed = JSON.parse(raw);
    return { ...fallback, ...parsed };
  } catch (error) {
    if (error.code === 'ENOENT' || error.name === 'SyntaxError') {
      await writeJsonAtomic(filePath, fallback);
      return { ...fallback };
    }

    throw error;
  }
}

function withFileLock(filePath, work) {
  const previous = writeLocks.get(filePath) || Promise.resolve();
  const run = previous
    .catch(() => {})
    .then(work);

  writeLocks.set(filePath, run.finally(() => {
    if (writeLocks.get(filePath) === run) {
      writeLocks.delete(filePath);
    }
  }));

  return run;
}

module.exports = {
  readJsonOrDefault,
  writeJsonAtomic,
  withFileLock
};
