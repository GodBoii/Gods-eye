// This edition never loads provider credentials or registers billing endpoints.
export const EXCLUDED = Object.freeze([
  { name: 'Google 3D, Places & Street View', reason: 'Billing-enabled Google APIs', replacement: 'Esri / OSM imagery, Photon search and keyless terrain' },
  { name: 'Cesium ion & Bing imagery', reason: 'Account token and hosted asset quotas', replacement: 'Open-source Cesium renderer with Re:Earth terrain' },
  { name: 'OpenAI realtime voice', reason: 'Metered audio and model API', replacement: 'Local command palette and keyboard controls' },
  { name: 'TomTom live traffic', reason: 'Provider API key and usage quotas', replacement: 'OSM map and public transit / bikeshare' },
  { name: 'AISStream vessel feed', reason: 'Credential-dependent streaming service', replacement: 'No live vessel feed in this edition' },
  { name: 'Mapillary street imagery', reason: 'Account token required', replacement: 'Public transport cameras where available' },
  { name: 'NASA FIRMS live detections', reason: 'Free registration key required', replacement: 'Keyless wildfire perimeters and NASA imagery' },
  { name: 'OpenSky authenticated feed', reason: 'Account credentials and credit budget', replacement: 'Viewport-scoped adsb.lol reports, 250 nautical miles' },
]);
export const BLOCKED_LAYERS = new Set(['traffic', 'ais-live-vessels', 'street-level', 'local-firms']);
export const BLOCKED_SOURCES = ['traffic', 'vessels', 'mapillary', 'firms'];
export function layerAllowed(id) { return typeof id === 'string' && !BLOCKED_LAYERS.has(id); }
export function blockedApi(path) {
  const normalized = path.toLowerCase().replace(/\/+$/, '');
  return /^\/api\/(?:openai|voice|realtime|google|tomtom|ais|vessels|mapillary|firms|setup|key-setup|settings|provider-settings)(?:\/|$)/.test(normalized);
}
