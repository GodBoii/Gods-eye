import {
  normalizeNaturalEvents,
  EONET_URL,
} from '../../src/layers/naturalEvents/records.js';
import { readResponseJsonCapped, coalesceProxyRequest } from './common/http.js';

/** A fixed NASA endpoint shared by dev and production preview, with bounded acquisition. */
export function naturalEventsProxy({
  fetchImpl = (...args) => globalThis.fetch(...args),
  now = () => Date.now(),
} = {}) {
  let cached = null;
  let retryAt = 0;
  const pending = new Map();
  async function snapshot() {
    if (cached && now() < cached.expiresAt)
      return { ...cached, status: 'fresh', error: null };
    if (now() < retryAt) {
      if (cached)
        return {
          ...cached,
          status: 'stale',
          error: 'NASA EONET unavailable; showing the last fetched snapshot.',
        };
      throw new Error('NASA EONET unavailable; retry in one minute.');
    }
    return coalesceProxyRequest(pending, 'events', async () => {
      try {
        const signal = AbortSignal.timeout(12000);
        const response = await fetchImpl(EONET_URL, {
          signal,
          redirect: 'error',
          headers: { Accept: 'application/json' },
        });
        if (!response.ok) {
          await response.body?.cancel();
          throw new Error('NASA EONET unavailable');
        }
        const rows = normalizeNaturalEvents(
          await readResponseJsonCapped(response, 2 * 1024 * 1024, signal),
        );
        const fetchedAt = now();
        cached = {
          rows,
          fetchedAt,
          expiresAt: fetchedAt + 600000,
          sourceUrl: EONET_URL,
        };
        retryAt = 0;
        return { ...cached, status: 'fresh', error: null };
      } catch {
        retryAt = now() + 60000;
        if (cached)
          return {
            ...cached,
            status: 'stale',
            error: 'NASA EONET unavailable; showing the last fetched snapshot.',
          };
        throw new Error('NASA EONET unavailable; retry in one minute.');
      }
    }).promise;
  }
  const install = (server) => {
    server.middlewares.use(async (req, res, next) => {
      const url = new URL(req.url || '/', 'http://localhost');
      if (url.pathname !== '/api/natural-events') return next();
      const send = (status, value) => {
        res.writeHead(status, {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store',
        });
        res.end(JSON.stringify(value));
      };
      if (req.method !== 'GET') return send(405, { error: 'GET required' });
      if (url.search)
        return send(400, { error: 'This feed accepts no query parameters' });
      try {
        send(200, await snapshot());
      } catch (error) {
        send(502, { error: error.message });
      }
    });
  };
  return {
    name: 'nasa-natural-events',
    configureServer: install,
    configurePreviewServer: install,
  };
}
