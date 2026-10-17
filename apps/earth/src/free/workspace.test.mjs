import test from 'node:test';
import assert from 'node:assert/strict';
import { blockedApi, layerAllowed, clearProviderCredentials } from './policy.js';
import { parseWorkspace, readWorkspace, saveWorkspace, workspaceGeoJSON } from './workspace.js';

const view = { id: 'view-1', name: 'India', position: [1, 2, 3], heading: 0, pitch: -1, roll: 0, layers: ['earthquakes'] };
const pin = { id: 'pin-1', name: '<script>stays text</script>', lon: 77.2, lat: 28.6 };
const workspace = () => ({ version: 1, views: [view], pins: [pin] });

test('saved workspace round-trips and exports valid point geometry', () => {
  const values = new Map(); const storage = { getItem: (key) => values.get(key) ?? null, setItem: (key, value) => values.set(key, value) };
  saveWorkspace(workspace(), storage);
  assert.deepEqual(readWorkspace(storage), workspace());
  const geo = workspaceGeoJSON(readWorkspace(storage));
  assert.deepEqual(geo.features[0].geometry.coordinates, [77.2, 28.6]);
  assert.equal(geo.features[0].properties.name, pin.name);
  assert.deepEqual(geo.properties.views, [view]);
});
test('malformed, oversized, nonfinite and credential-based restored states are refused', () => {
  for (const invalid of [null, { version: 2 }, { ...workspace(), pins: [{ ...pin, lat: 91 }] },
    { ...workspace(), views: [{ ...view, position: [NaN, 0, 0] }] },
    { ...workspace(), views: [{ ...view, layers: ['traffic'] }] },
    { ...workspace(), pins: Array(101).fill(pin) }]) assert.throws(() => parseWorkspace(invalid));
});
test('storage failures remain visible to the caller', () => {
  assert.throws(() => saveWorkspace(workspace(), { setItem() { throw new Error('quota'); } }), /quota/);
  assert.throws(() => readWorkspace({ getItem() { return '{bad'; } }));
});
test('billing routes are blocked while free feeds and static files pass', () => {
  for (const path of ['/api/openai/hud-summary', '/api/google/geocode', '/api/tomtom/flow', '/api/vessels', '/api/mapillary', '/api/firms', '/api/KEY-SETUP/']) assert.equal(blockedApi(path), true, path);
  for (const path of ['/api/flights', '/api/celestrak', '/api/weather', '/logo.svg']) assert.equal(blockedApi(path), false, path);
  assert.equal(layerAllowed('traffic'), false);
  assert.equal(layerAllowed('earthquakes'), true);
});
test('ambient credentials cannot activate optional billed fallbacks', () => {
  const environment = { GOOGLE_MAPS_API_KEY: 'fixture', GOOGLE_MAPS_SERVER_API_KEY: 'fixture', OPENAI_API_KEY: 'fixture', LL2_API_TOKEN: 'fixture', TFL_APP_KEY: 'fixture', PORT: '4173', PATH: '/usr/bin' };
  clearProviderCredentials(environment);
  assert.deepEqual(environment, { PORT: '4173', PATH: '/usr/bin' });
});
