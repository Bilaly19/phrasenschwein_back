const { NamesService } = require('../src/backend/services/namesService');

module.exports = {
  getNames: (readData, dataPath) => {
    const repo = {
      getNames: () => readData(dataPath).then(({ valuePerClick, ...names }) => names)
    };
    return new NamesService({ namesRepository: repo }).getNames();
  },
  getConfig: (readData, dataPath) => {
    const repo = {
      getConfig: () => readData(dataPath).then((data) => ({ valuePerClick: data.valuePerClick }))
    };
    return new NamesService({ namesRepository: repo }).getConfig();
  },
  updateConfig: async (readData, writeData, dataPath, valuePerClick) => {
    const repo = {
      setValuePerClick: async (value) => {
        const data = await readData(dataPath);
        data.valuePerClick = value;
        await writeData(dataPath, data);
      }
    };
    return new NamesService({ namesRepository: repo }).updateConfig(valuePerClick);
  },
  addName: async (readData, writeData, dataPath, name) => {
    const repo = {
      addName: async (n) => {
        const data = await readData(dataPath);
        if (data[n]) return false;
        data[n] = { count: 0, lastClickedAt: null };
        await writeData(dataPath, data);
        return true;
      }
    };
    try {
      await new NamesService({ namesRepository: repo }).addName(name);
      return true;
    } catch {
      return false;
    }
  },
  incrementName: async (readData, writeData, dataPath, name) => {
    const repo = {
      incrementName: async (n) => {
        const data = await readData(dataPath);
        if (!data[n]) return false;
        data[n].count += 1;
        data[n].lastClickedAt = new Date().toISOString();
        await writeData(dataPath, data);
        return true;
      }
    };
    try {
      await new NamesService({ namesRepository: repo }).incrementName(name);
      return true;
    } catch {
      return false;
    }
  },
  resetNames: async (readData, writeData, dataPath) => {
    const data = await readData(dataPath);
    for (const key of Object.keys(data)) {
      if (key !== 'valuePerClick') {
        data[key].count = 0;
        data[key].lastClickedAt = null;
      }
    }
    await writeData(dataPath, data);
  },
  deleteName: async (readData, writeData, dataPath, name) => {
    const data = await readData(dataPath);
    if (!data[name]) return false;
    delete data[name];
    await writeData(dataPath, data);
    return true;
  }
};
