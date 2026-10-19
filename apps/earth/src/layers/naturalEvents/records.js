export const EONET_URL =
  'https://eonet.gsfc.nasa.gov/api/v3/events?status=open&days=30&limit=100';

export function safeNaturalEventLink(value) {
  if (typeof value !== 'string' || value.length > 2048) return null;
  try {
    const url = new URL(value);
    return ['https:', 'http:'].includes(url.protocol) &&
      !url.username &&
      !url.password
      ? url.href
      : null;
  } catch {
    return null;
  }
}

/** Keep the latest valid reported point per open event, never an invented area. */
export function normalizeNaturalEvents(payload) {
  if (!Array.isArray(payload?.events) || payload.events.length > 100)
    throw new Error('Malformed NASA EONET snapshot');
  const ids = new Set();
  return payload.events.flatMap((event) => {
    if (
      typeof event?.id !== 'string' ||
      !event.id ||
      event.id.length > 200 ||
      ids.has(event.id) ||
      typeof event.title !== 'string' ||
      !event.title.trim() ||
      !Array.isArray(event.geometry) ||
      !Array.isArray(event.categories) ||
      !Array.isArray(event.sources)
    )
      throw new Error('Malformed NASA EONET event');
    ids.add(event.id);
    if (event.closed != null) return [];
    let latest = null;
    for (const geometry of event.geometry) {
      if (geometry?.type !== 'Point' || !Array.isArray(geometry.coordinates))
        continue;
      const [lon, lat] = geometry.coordinates;
      const time =
        typeof geometry.date === 'string' ? Date.parse(geometry.date) : NaN;
      if (
        !Number.isFinite(lon) ||
        Math.abs(lon) > 180 ||
        !Number.isFinite(lat) ||
        Math.abs(lat) > 90 ||
        !Number.isFinite(time)
      )
        continue;
      if (!latest || time > latest.time) latest = { lon, lat, time };
    }
    if (!latest) return [];
    return [
      {
        id: event.id,
        title: event.title.trim().slice(0, 200),
        categories: event.categories
          .flatMap((category) =>
            typeof category?.title === 'string'
              ? [category.title.slice(0, 100)]
              : [],
          )
          .join(', '),
        lon: latest.lon,
        lat: latest.lat,
        observedAt: new Date(latest.time).toISOString(),
        url:
          event.sources
            .map((source) => safeNaturalEventLink(source?.url))
            .find(Boolean) || safeNaturalEventLink(event.link),
      },
    ];
  });
}
