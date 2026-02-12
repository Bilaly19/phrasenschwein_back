const fs = require('fs/promises');
const path = require('path');

async function ensureDir(filePath) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
}

async function atomicWriteJson(filePath, data) {
  await ensureDir(filePath);
  const tempFile = `${filePath}.tmp`;
  await fs.writeFile(tempFile, JSON.stringify(data, null, 2), 'utf-8');
  await fs.rename(tempFile, filePath);
}

async function readJsonWithFallback(filePath, fallback) {
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    return JSON.parse(content);
  } catch (error) {
    if (error.code === 'ENOENT' || error.name === 'SyntaxError') {
      await atomicWriteJson(filePath, fallback);
      return structuredClone(fallback);
    }
    throw error;
  }
}

module.exports = { atomicWriteJson, readJsonWithFallback };
