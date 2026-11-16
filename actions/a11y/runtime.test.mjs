import test from 'node:test';
import assert from 'node:assert/strict';
import { verifyRuntime } from './runtime.mjs';

function engine(title = 'ZZ runtime') {
  const state = { launches: 0, closes: 0, pages: 0 };
  return { state, async launch() {
    state.launches++;
    return { async newPage() {
      state.pages++;
      return { async setContent() {}, async title() { return title; } };
    }, async close() { state.closes++; } };
  } };
}
test('preflight launches and closes every engine and checks rendered content', async () => {
  const chromium = engine(), webkit = engine();
  assert.deepEqual(await verifyRuntime({ chromium, webkit }), { schema_version: 1, status: 'pass', engines: 2 });
  for (const type of [chromium, webkit]) assert.deepEqual(type.state, { launches: 1, closes: 1, pages: 1 });
});
test('missing browser or dependency fails closed', async () => {
  await assert.rejects(verifyRuntime({ chromium: { async launch() { throw new Error('ZZ missing'); } } }));
});
test('bad render fails closed and still closes the browser', async () => {
  const chromium = engine('ZZ broken');
  await assert.rejects(verifyRuntime({ chromium }));
  assert.equal(chromium.state.closes, 1);
});
