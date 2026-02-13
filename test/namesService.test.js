const test = require('node:test');
const assert = require('node:assert/strict');

const { NamesService } = require('../src/backend/services/namesService');

function createNamesRepositoryMock(initial) {
  let state = structuredClone(initial);
  return {
    async addName(name) {
      if (state[name]) return false;
      state[name] = { count: 0, lastClickedAt: null };
      return true;
    },
    async incrementName(name) {
      if (!state[name]) return false;
      state[name].count += 1;
      state[name].lastClickedAt = new Date().toISOString();
      return true;
    },
    async resetNames() {
      for (const [key, value] of Object.entries(state)) {
        if (key === 'valuePerClick' || typeof value !== 'object') continue;
        state[key] = { ...value, count: 0, lastClickedAt: null };
      }
    },
    getState() {
      return structuredClone(state);
    }
  };
}

test('addName creates a new name with count=0', async () => {
  const repo = createNamesRepositoryMock({ valuePerClick: 0.5 });
  const service = new NamesService({ namesRepository: repo });

  await service.addName('Anna');
  assert.deepEqual(repo.getState().Anna, { count: 0, lastClickedAt: null });
});

test('incrementName increases count and sets timestamp', async () => {
  const repo = createNamesRepositoryMock({
    valuePerClick: 0.5,
    Anna: { count: 1, lastClickedAt: null }
  });
  const service = new NamesService({ namesRepository: repo });

  await service.incrementName('Anna');
  const state = repo.getState();

  assert.equal(state.Anna.count, 2);
  assert.match(state.Anna.lastClickedAt, /^\d{4}-\d{2}-\d{2}T/);
});

test('resetNames resets counters and keeps valuePerClick', async () => {
  const repo = createNamesRepositoryMock({
    valuePerClick: 0.75,
    Anna: { count: 2, lastClickedAt: '2024-01-01T00:00:00.000Z' },
    Ben: { count: 5, lastClickedAt: '2024-01-01T00:00:00.000Z' }
  });
  const service = new NamesService({ namesRepository: repo });

  await service.resetNames();
  const state = repo.getState();

  assert.equal(state.valuePerClick, 0.75);
  assert.deepEqual(state.Anna, { count: 0, lastClickedAt: null });
  assert.deepEqual(state.Ben, { count: 0, lastClickedAt: null });
});
