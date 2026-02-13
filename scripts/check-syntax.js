const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = process.cwd();
const includeDirs = ['src/backend', 'test', 'tests/contract'];
const includeFiles = ['server.js'];

function collectJsFiles(dirPath, acc) {
  if (!fs.existsSync(dirPath)) return;

  for (const entry of fs.readdirSync(dirPath, { withFileTypes: true })) {
    const fullPath = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      collectJsFiles(fullPath, acc);
      continue;
    }

    if (entry.isFile() && fullPath.endsWith('.js')) {
      acc.push(fullPath);
    }
  }
}

function runNodeCheck(filePath) {
  const source = fs.readFileSync(filePath, 'utf8');
  try {
    new vm.Script(source, { filename: filePath });
  } catch (error) {
    throw new Error(`Syntax check failed for ${filePath}\n${error.message}`);
  }
}

function main() {
  const files = includeFiles
    .map((file) => path.join(root, file))
    .filter((file) => fs.existsSync(file));

  for (const dir of includeDirs) {
    collectJsFiles(path.join(root, dir), files);
  }

  for (const file of files) {
    runNodeCheck(file);
  }

  console.log(`Syntax check passed for ${files.length} files.`);
}

main();
