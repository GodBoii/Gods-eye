import { readResponseJsonCapped } from '../../sources/httpBody.js';
import { safeNaturalEventLink } from './records.js';

/** Acquire the bounded same-origin EONET snapshot, including its freshness. */
export function createNaturalEventsSource({
  fetchImpl = (...args) => globalThis.fetch(...args),
} = {}) {
  return {
    async getSnapshot({ signal } = {}) {
      signal?.throwIfAborted();
      const response = await fetchImpl('/api/natural-events', { signal });
      if (!response.ok) throw new Error(`NASA EONET HTTP ${response.status}`);
      const data = await readResponseJsonCapped(
        response,
        2 * 1024 * 1024,
        signal,
      );
      if (
        !['fresh', 'stale'].includes(data?.status) ||
        !Number.isFinite(data.fetchedAt) ||
        !Number.isFinite(data.expiresAt) ||
        (data.error !== null && typeof data.error !== 'string') ||
        !Array.isArray(data.rows) ||
        data.rows.length > 100 ||
        new Set(data.rows.map((row) => row?.id)).size !== data.rows.length ||
        data.rows.some(
          (row) =>
            typeof row?.id !== 'string' ||
            !row.id ||
            row.id.length > 200 ||
            typeof row.title !== 'string' ||
            !row.title.trim() ||
            row.title.length > 200 ||
            typeof row.categories !== 'string' ||
            !Number.isFinite(row.lon) ||
            Math.abs(row.lon) > 180 ||
            !Number.isFinite(row.lat) ||
            Math.abs(row.lat) > 90 ||
            !Number.isFinite(Date.parse(row.observedAt)) ||
            (row.url !== null && safeNaturalEventLink(row.url) !== row.url),
        )
      )
        throw new Error('Malformed NASA EONET snapshot');
      signal?.throwIfAborted();
      return data;
    },
  };
}
