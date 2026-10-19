import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { naturalEventsProxy } from './naturalEvents.js';
import { EONET_URL } from '../../src/layers/naturalEvents/records.js';

async function serve(t, plugin, preview = false) {
  let middleware;
  plugin[preview ? 'configurePreviewServer' : 'configureServer']({
    middlewares: {
      use(handler) {
        middleware = handler;
      },
    },
  });
  const server = http.createServer(
    (req, res) =>
      void middleware(req, res, () => {
        res.writeHead(404);
        res.end();
      }),
  );
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(
    () =>
      new Promise((resolve) => {
        server.closeAllConnections();
        server.close(resolve);
      }),
  );
  return `http://127.0.0.1:${server.address().port}`;
}

test('Vite hooks return no post-install callback even when Connect returns its app', () => {
  const server = {
    middlewares: {
      use() {
        return () => {
          throw new Error('Unexpected Vite post-hook');
        };
      },
    },
  };
  const plugin = naturalEventsProxy();
  assert.equal(plugin.configureServer(server), undefined);
  assert.equal(plugin.configurePreviewServer(server), undefined);
});

test('dev and production preview expose only the fixed NASA endpoint', async (t) => {
  for (const preview of [false, true]) {
    let calls = 0;
    const base = await serve(
      t,
      naturalEventsProxy({
        fetchImpl: async (url, options) => {
          calls++;
          assert.equal(url, EONET_URL);
          assert.equal(options.redirect, 'error');
          assert.ok(options.signal);
          return Response.json({ events: [] });
        },
      }),
      preview,
    );
    assert.equal(
      (await fetch(base + '/api/natural-events?url=https://example.org'))
        .status,
      400,
    );
    assert.equal(
      (await fetch(base + '/api/natural-events', { method: 'POST' })).status,
      405,
    );
    assert.equal((await fetch(base + '/unknown')).status, 404);
    assert.equal(calls, 0);
    const responses = await Promise.all(
      Array.from({ length: 5 }, () =>
        fetch(base + '/api/natural-events').then((response) => response.json()),
      ),
    );
    assert.equal(calls, 1);
    assert.ok(
      responses.every(
        (value) => value.status === 'fresh' && value.rows.length === 0,
      ),
    );
  }
});

test('malformed and oversized responses preserve dated last-good data and respect cooldown', async (t) => {
  let time = 1000000,
    calls = 0;
  let result = { events: [] };
  const base = await serve(
    t,
    naturalEventsProxy({
      now: () => time,
      fetchImpl: async () => {
        calls++;
        return result instanceof Response ? result : Response.json(result);
      },
    }),
  );
  const read = () =>
    fetch(base + '/api/natural-events').then((response) => response.json());
  const initial = await read();
  time += 600001;
  result = { nope: [] };
  const stale = await read();
  assert.equal(stale.status, 'stale');
  assert.equal(stale.fetchedAt, initial.fetchedAt);
  assert.match(stale.error, /unavailable/);
  await read();
  assert.equal(calls, 2);
  time += 60001;
  result = new Response('oversized', {
    headers: { 'content-length': String(3 * 1024 * 1024) },
  });
  assert.equal((await read()).status, 'stale');
  time += 60001;
  result = { events: [] };
  assert.equal((await read()).status, 'fresh');
  assert.equal(calls, 4);
});

test('a provider failure without a snapshot is unavailable rather than an empty success', async (t) => {
  const base = await serve(
    t,
    naturalEventsProxy({
      fetchImpl: async () => {
        throw new Error('network down');
      },
    }),
  );
  const response = await fetch(base + '/api/natural-events');
  assert.equal(response.status, 502);
  assert.match((await response.json()).error, /unavailable/);
});
