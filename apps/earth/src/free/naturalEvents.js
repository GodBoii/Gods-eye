const node = (tag, text) => {
  const value = document.createElement(tag);
  if (text !== undefined) value.textContent = text;
  return value;
};

/** An accessible companion to EONET map points, refreshed only when facts change. */
export function mountNaturalEvents(container, { getLayer, fly }) {
  const details = node('details');
  details.className = 'free-natural-events';
  details.append(node('summary', 'Natural event records'));
  const search = node('input');
  search.type = 'search';
  search.placeholder = 'Filter natural events…';
  search.setAttribute('aria-label', 'Filter natural event records');
  const status = node('p');
  status.setAttribute('role', 'status');
  const list = node('div');
  const source = node('a', 'NASA EONET · source and limitations ↗');
  source.href = 'https://eonet.gsfc.nasa.gov/docs/v3';
  source.target = '_blank';
  source.rel = 'noopener noreferrer';
  details.append(
    search,
    status,
    list,
    node(
      'p',
      'Latest reported points for open events in the past 30 days, up to 100 events. Locations may be approximate; affected areas are not shown.',
    ),
    source,
  );
  container.append(details);
  let signature = null;
  function update() {
    const layer = getLayer();
    const records = layer?.getRecords() || [];
    const stats = layer?.getStats();
    const next = JSON.stringify([records, stats, search.value]);
    if (signature === next) return;
    signature = next;
    details.hidden = !stats || stats.status === 'idle';
    status.textContent = `${records.length} records · ${stats?.status || 'waiting'}${stats?.lastUpdate ? ` · fetched ${new Date(stats.lastUpdate).toLocaleString()}` : ''}${stats?.error ? ` · ${stats.error}` : ''}`;
    const query = search.value.trim().toLowerCase();
    const filtered = records.filter((record) =>
      `${record.title} ${record.categories}`.toLowerCase().includes(query),
    );
    list.replaceChildren();
    for (const record of filtered) {
      const item = node('article');
      const locate = node('button', record.title);
      locate.type = 'button';
      locate.addEventListener('click', () =>
        fly(record.lon, record.lat, 1200000),
      );
      item.append(
        locate,
        node(
          'small',
          `${record.categories} · ${new Date(record.observedAt).toLocaleString()} · ${record.lat.toFixed(2)}°, ${record.lon.toFixed(2)}°`,
        ),
      );
      if (record.url) {
        const link = node('a', 'Event source ↗');
        link.href = record.url;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        item.append(link);
      }
      list.append(item);
    }
    if (!filtered.length)
      list.append(
        node('p', query ? 'No matching events.' : 'No event points available.'),
      );
  }
  search.addEventListener('input', update);
  return update;
}
