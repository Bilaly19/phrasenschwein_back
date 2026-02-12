const test = require('node:test');
const assert = require('node:assert/strict');

const namesService = require('../services/namesService');

function createDataStore(initial) {
  let state = structuredClone(initial);
  return {
    readData: async () => structuredClone(state),
    writeData: async (_path, next) => {
      state = structuredClone(next);
    },
    getState: () => structuredClone(state)
  };
}

test('addName legt neuen Namen mit count=0 an', async () => {
  const store = createDataStore({ valuePerClick: 0.5 });
  const created = await namesService.addName(store.readData, store.writeData, 'unused', 'Anna');

  assert.equal(created, true);
  assert.deepEqual(store.getState().Anna, { count: 0, lastClickedAt: null });
});

test('incrementName erhöht count und setzt Timestamp', async () => {
  const store = createDataStore({
    valuePerClick: 0.5,
    Anna: { count: 1, lastClickedAt: null }
  });

  const found = await namesService.incrementName(store.readData, store.writeData, 'unused', 'Anna');
  const state = store.getState();

  assert.equal(found, true);
  assert.equal(state.Anna.count, 2);
  assert.match(state.Anna.lastClickedAt, /^\d{4}-\d{2}-\d{2}T/);
});

test('resetNames setzt alle Namen zurück und lässt valuePerClick unverändert', async () => {
  const store = createDataStore({
    valuePerClick: 0.75,
    Anna: { count: 2, lastClickedAt: '2024-01-01T00:00:00.000Z' },
    Ben: { count: 5, lastClickedAt: '2024-01-01T00:00:00.000Z' }
  });

  await namesService.resetNames(store.readData, store.writeData, 'unused');
  const state = store.getState();

  assert.equal(state.valuePerClick, 0.75);
  assert.deepEqual(state.Anna, { count: 0, lastClickedAt: null });
  assert.deepEqual(state.Ben, { count: 0, lastClickedAt: null });
});
