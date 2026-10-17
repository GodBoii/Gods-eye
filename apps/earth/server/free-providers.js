import { normalizeAdsbLolPointResponse } from '../src/data/adsbLolFallback.js';
import { readResponseJsonCapped } from './providers/common/http.js';
import { blockedApi } from '../src/free/policy.js';

/** Fixed upstream hosts, bounded cache and coalesced requests. No credentials. */
export function freeEditionGateway({ fetchImpl = (...args) => fetch(...args) } = {}) {
  const cache = new Map();
  const pending = new Map();
  const install = (server) => { server.middlewares.use(async (req, res, next) => {
    const url = new URL(req.url || '/', 'http://localhost');
    const send = (status, value, headers = {}) => {
      res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers });
      res.end(JSON.stringify(value));
    };
    if (blockedApi(url.pathname)) return send(410, { error: 'Provider removed in the keyless edition. See Excluded providers.' });
    if (url.pathname === '/api/flights/track') return send(200, { path: [] });
    if (url.pathname === '/api/military/track') return send(200, { timestamp: Math.floor(Date.now() / 1000), trace: [] });
    if (url.pathname !== '/api/flights') return next();
    if (req.method !== 'GET') return send(405, { error: 'GET required' });
    const latText = url.searchParams.get('lat'), lonText = url.searchParams.get('lon');
    const latitude = latText === null ? 30.27 : Number(latText);
    const longitude = lonText === null ? -97.74 : Number(lonText);
    if (!Number.isFinite(latitude) || Math.abs(latitude) > 90 || !Number.isFinite(longitude) || Math.abs(longitude) > 180)
      return send(400, { error: 'Invalid coordinates' });
    const key = `${(Math.round(latitude * 4) / 4).toFixed(2)}/${(Math.round(longitude * 4) / 4).toFixed(2)}`;
    const stored = cache.get(key);
    const headers = { 'X-Flight-Source': 'adsb.lol', 'X-Flight-Coverage': '250 nautical miles around the view center; ODbL' };
    if (stored && Date.now() - stored.at < 15000) return send(200, stored.body, headers);
    try {
      if (!pending.has(key)) {
        const request = (async () => {
          const signal = AbortSignal.timeout(12000);
          const response = await fetchImpl(`https://api.adsb.lol/v2/point/${key}/250`, {
            signal,
            headers: { 'User-Agent': 'godseye-keyless/1.0 (+https://github.com/bilawalsidhu/gods-eye-view)', Accept: 'application/json' },
          });
          if (!response.ok) { void response.body?.cancel(); throw new Error(`Aircraft provider returned ${response.status}`); }
          const payload = await readResponseJsonCapped(response, 8 * 1024 * 1024, signal);
          if (!payload || !Array.isArray(payload.ac)) throw new Error('Malformed aircraft feed');
          const body = normalizeAdsbLolPointResponse(payload);
          cache.delete(key);
          cache.set(key, { at: Date.now(), body });
          if (cache.size > 80) cache.delete(cache.keys().next().value);
          return body;
        })();
        pending.set(key, request);
      }
      send(200, await pending.get(key), headers);
    } catch (error) {
      send(502, { error: error instanceof Error ? error.message : 'Aircraft source unavailable' });
    } finally { pending.delete(key); }
  }); };
  return { name: 'free-edition-gateway', configureServer: install, configurePreviewServer: install };
}
