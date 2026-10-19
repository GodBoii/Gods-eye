import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeNaturalEvents } from './records.js';
import { createNaturalEventsSource } from './source.js';
import { createNaturalEventsLayer } from './index.js';

const event = {
  id: 'EONET_fixture',
  title: 'Test volcano',
  closed: null,
  categories: [{ title: 'Volcanoes' }],
  sources: [{ url: 'https://example.org/event' }],
  geometry: [
    { type: 'Point', date: '2026-10-17T00:00:00Z', coordinates: [20, 30] },
    { type: 'Point', date: '2026-10-16T00:00:00Z', coordinates: [10, 15] },
    { type: 'Point', date: '2026-10-18T00:00:00Z', coordinates: [999, 15] },
  ],
};
const rows = normalizeNaturalEvents({ events: [event] });
const snapshot = {
  rows,
  fetchedAt: 1000,
  expiresAt: 601000,
  status: 'fresh',
  error: null,
};

test('latest valid point preserves category, observation time and safe source links', () => {
  assert.deepEqual(rows[0], {
    id: event.id,
    title: event.title,
    categories: 'Volcanoes',
    lon: 20,
    lat: 30,
    observedAt: '2026-10-17T00:00:00.000Z',
    url: 'https://example.org/event',
  });
  assert.deepEqual(
    normalizeNaturalEvents({ events: [{ ...event, closed: '2026-10-18' }] }),
    [],
  );
  assert.deepEqual(
    normalizeNaturalEvents({
      events: [{ ...event, geometry: [{ type: 'Polygon', coordinates: [] }] }],
    }),
    [],
  );
  for (const url of [
    'javascript:alert(1)',
    'data:text/html,hi',
    'https://user:password@example.org',
  ])
    assert.equal(
      normalizeNaturalEvents({ events: [{ ...event, sources: [{ url }] }] })[0]
        .url,
      null,
    );
  assert.throws(
    () => normalizeNaturalEvents({ events: [event, event] }),
    /Malformed/,
  );
  assert.throws(() => normalizeNaturalEvents({ events: null }), /Malformed/);
  assert.throws(
    () => normalizeNaturalEvents({ events: Array(101).fill(event) }),
    /Malformed/,
  );
});

test('source rejects HTTP failures, malformed snapshots and cancellation after body completion', async () => {
  assert.deepEqual(
    await createNaturalEventsSource({
      fetchImpl: async () => Response.json(snapshot),
    }).getSnapshot(),
    snapshot,
  );
  for (const body of [
    { ...snapshot, rows: [{ ...rows[0], lat: 100 }] },
    { ...snapshot, rows: [{ ...rows[0], url: 'javascript:alert(1)' }] },
    { rows: [] },
  ])
    await assert.rejects(
      createNaturalEventsSource({
        fetchImpl: async () => Response.json(body),
      }).getSnapshot(),
      /Malformed/,
    );
  await assert.rejects(
    createNaturalEventsSource({
      fetchImpl: async () => new Response('', { status: 503 }),
    }).getSnapshot(),
    /HTTP 503/,
  );
  const controller = new AbortController();
  await assert.rejects(
    createNaturalEventsSource({
      fetchImpl: async () => {
        controller.abort();
        return Response.json(snapshot);
      },
    }).getSnapshot({ signal: controller.signal }),
    { name: 'AbortError' },
  );
});

function display(source) {
  const sources = [];
  const viewer = {
    dataSources: {
      add: (value) => sources.push(value),
      remove: (value) => sources.splice(sources.indexOf(value), 1),
    },
    scene: { requestRender() {} },
  };
  const layer = createNaturalEventsLayer({ source });
  layer.init(viewer);
  layer.enable();
  return { layer, viewer, sources };
}

test('real Cesium entities and dated records survive failed refresh, then clear on valid empty snapshot', async () => {
  let result = snapshot;
  const h = display({
    getSnapshot: async () => {
      if (result instanceof Error) throw result;
      return result;
    },
  });
  assert.equal(await h.layer.update(h.viewer), true);
  assert.equal(h.sources[0].entities.values[0].name, event.title);
  assert.deepEqual(h.layer.getRecords(), rows);
  result = new Error('offline');
  assert.equal(await h.layer.update(h.viewer), false);
  assert.equal(h.layer.getStats().status, 'stale');
  assert.equal(h.layer.getStats().lastUpdate, 1000);
  assert.equal(h.layer.getRecords().length, 1);
  result = { ...snapshot, rows: [], fetchedAt: 2000 };
  assert.equal(await h.layer.update(h.viewer), true);
  assert.deepEqual(h.layer.getRecords(), []);
  assert.equal(h.sources[0].entities.values.length, 0);
  h.layer.destroy(h.viewer);
  assert.equal(h.sources.length, 0);
});

test('disable, re-enable and destroy reject late uncancellable provider responses', async () => {
  for (const action of ['disable', 'destroy']) {
    let resolve, signal;
    const h = display({
      getSnapshot(options) {
        signal = options.signal;
        return new Promise((done) => {
          resolve = done;
        });
      },
    });
    const pending = h.layer.update(h.viewer);
    h.layer[action](h.viewer);
    assert.equal(signal.aborted, true);
    if (action === 'disable') h.layer.enable();
    resolve(snapshot);
    assert.equal(await pending, false);
    assert.deepEqual(h.layer.getRecords(), []);
    h.layer.destroy(h.viewer);
  }
});
