async function getNames(readData, dataPath) {
  const { valuePerClick, ...names } = await readData(dataPath);
  return names;
}

async function getConfig(readData, dataPath) {
  const data = await readData(dataPath);
  return { valuePerClick: data.valuePerClick };
}

async function updateConfig(readData, writeData, dataPath, valuePerClick) {
  const data = await readData(dataPath);
  data.valuePerClick = valuePerClick;
  await writeData(dataPath, data);
}

async function addName(readData, writeData, dataPath, name) {
  const data = await readData(dataPath);

  if (data[name]) {
    return false;
  }

  data[name] = { count: 0, lastClickedAt: null };
  await writeData(dataPath, data);
  return true;
}

async function incrementName(readData, writeData, dataPath, name) {
  const data = await readData(dataPath);

  if (!data[name]) {
    return false;
  }

  data[name].count += 1;
  data[name].lastClickedAt = new Date().toISOString();
  await writeData(dataPath, data);
  return true;
}

async function resetNames(readData, writeData, dataPath) {
  const data = await readData(dataPath);

  for (const name in data) {
    if (name !== 'valuePerClick') {
      data[name].count = 0;
      data[name].lastClickedAt = null;
    }
  }

  await writeData(dataPath, data);
}

async function deleteName(readData, writeData, dataPath, name) {
  const data = await readData(dataPath);

  if (!data[name]) {
    return false;
  }

  delete data[name];
  await writeData(dataPath, data);
  return true;
}

module.exports = {
  getNames,
  getConfig,
  updateConfig,
  addName,
  incrementName,
  resetNames,
  deleteName
};
