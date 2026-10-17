import { layerAllowed } from './policy.js';

const KEY = 'godseye:free-workspace:v1';
const finite = (value, low, high) => typeof value === 'number' && Number.isFinite(value) && value >= low && value <= high;
const name = (value) => typeof value === 'string' && value.trim().length > 0 && value.length <= 100;

export function validView(value) {
  return value && name(value.id) && name(value.name) && Array.isArray(value.position) && value.position.length === 3 &&
    value.position.every((n) => finite(n, -1e9, 1e9)) && ['heading', 'pitch', 'roll'].every((key) => finite(value[key], -10, 10)) &&
    Array.isArray(value.layers) && value.layers.length <= 40 && value.layers.every(layerAllowed);
}
export function validPin(value) {
  return value && name(value.id) && name(value.name) && finite(value.lon, -180, 180) && finite(value.lat, -90, 90);
}
export function parseWorkspace(value) {
  if (!value || value.version !== 1 || !Array.isArray(value.views) || !Array.isArray(value.pins) ||
    value.views.length > 12 || value.pins.length > 100 || !value.views.every(validView) || !value.pins.every(validPin))
    throw new Error('Saved workspace is invalid. Export or clear site storage before trying again.');
  return value;
}
export function readWorkspace(storage = localStorage) {
  const text = storage.getItem(KEY);
  return text ? parseWorkspace(JSON.parse(text)) : { version: 1, views: [], pins: [] };
}
export function saveWorkspace(value, storage = localStorage) {
  storage.setItem(KEY, JSON.stringify(parseWorkspace(value)));
}
export function workspaceGeoJSON(value) {
  const workspace = parseWorkspace(value);
  return { type: 'FeatureCollection', properties: { application: 'Gods Eye keyless edition', exportedAt: new Date().toISOString(), views: workspace.views },
    features: workspace.pins.map((pin) => ({ type: 'Feature', properties: { name: pin.name }, geometry: { type: 'Point', coordinates: [pin.lon, pin.lat] } })) };
}
