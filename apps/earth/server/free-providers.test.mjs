import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { freeEditionGateway } from './free-providers.js';

test('real HTTP gateway rejects billing/setup and invalid flight coordinates before provider I/O', async (t) => {
  let middleware;
  freeEditionGateway().configureServer({ middlewares: { use(handler) { middleware = handler; } } });
  const server = http.createServer((req, res) => void middleware(req, res, () => { res.writeHead(404); res.end(); }));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => { server.closeAllConnections(); server.close(resolve); }));
  const base = `http://127.0.0.1:${server.address().port}`;
  for (const path of ['/api/openai/hud-summary', '/api/setup/keys', '/api/realtime/token', '/api/google/geocode', '/api/vessels', '/api/firms', '/api/tomtom/status', '/api/mapillary']) {
    const response = await fetch(base + path);
    assert.equal(response.status, 410, path);
    assert.match((await response.json()).error, /removed/);
  }
  assert.equal((await fetch(base + '/api/flights?lat=999&lon=0')).status, 400);
  assert.equal((await fetch(base + '/api/flights', { method: 'POST' })).status, 405);
  assert.deepEqual(await (await fetch(base + '/api/flights/track')).json(), { path: [] });
  assert.equal((await fetch(base + '/unknown')).status, 404);
});
