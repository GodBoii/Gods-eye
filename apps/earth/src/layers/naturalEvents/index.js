import * as Cesium from 'cesium';

/** Own EONET points and their cancellation/refresh lifecycle. */
export function createNaturalEventsLayer({ source } = {}) {
  if (typeof source?.getSnapshot !== 'function')
    throw new TypeError('Natural events require a snapshot source');
  let dataSource = null;
  let request = null;
  let enabled = false;
  let rows = [];
  let fetchedAt = null;
  let error = null;
  let status = 'idle';
  return {
    id: 'natural-events',
    name: 'Natural events',
    icon: '◉',
    source: 'NASA EONET',
    updateInterval: 60000,
    init(viewer) {
      dataSource = new Cesium.CustomDataSource('natural-events');
      dataSource.show = false;
      viewer.dataSources.add(dataSource);
    },
    enable() {
      enabled = true;
      if (dataSource) dataSource.show = true;
    },
    disable() {
      enabled = false;
      request?.abort();
      request = null;
      if (dataSource) dataSource.show = false;
    },
    async update(viewer) {
      if (!enabled || !dataSource) return false;
      request?.abort();
      const current = new AbortController();
      request = current;
      try {
        const snapshot = await source.getSnapshot({ signal: current.signal });
        if (current.signal.aborted || request !== current || !enabled)
          return false;
        const entities = snapshot.rows.map(
          (row) =>
            new Cesium.Entity({
              id: `natural-event:${row.id}`,
              name: row.title,
              position: Cesium.Cartesian3.fromDegrees(row.lon, row.lat),
              point: {
                heightReference: Cesium.HeightReference.CLAMP_TO_GROUND,
                pixelSize: 9,
                color: Cesium.Color.fromCssColorString('#d6eea0'),
                outlineColor: Cesium.Color.BLACK,
                outlineWidth: 2,
                disableDepthTestDistance: 0,
              },
              label: {
                heightReference: Cesium.HeightReference.CLAMP_TO_GROUND,
                text: row.title,
                font: '12px sans-serif',
                fillColor: Cesium.Color.WHITE,
                showBackground: true,
                pixelOffset: new Cesium.Cartesian2(0, -20),
                distanceDisplayCondition: new Cesium.DistanceDisplayCondition(
                  0,
                  4000000,
                ),
              },
            }),
        );
        dataSource.entities.removeAll();
        for (const entity of entities) dataSource.entities.add(entity);
        rows = snapshot.rows;
        fetchedAt = snapshot.fetchedAt;
        error = snapshot.error;
        status = snapshot.status;
        viewer.scene.requestRender();
        return true;
      } catch (failure) {
        if (current.signal.aborted || request !== current || !enabled)
          return false;
        error =
          failure instanceof Error ? failure.message : 'NASA EONET unavailable';
        status = fetchedAt === null ? 'unavailable' : 'stale';
        return false;
      } finally {
        if (request === current) request = null;
      }
    },
    getRecords() {
      return enabled ? rows : [];
    },
    getStats() {
      return { count: rows.length, lastUpdate: fetchedAt, status, error };
    },
    destroy(viewer) {
      request?.abort();
      request = null;
      enabled = false;
      if (dataSource) viewer.dataSources.remove(dataSource, true);
      dataSource = null;
      rows = [];
      fetchedAt = null;
      error = null;
      status = 'idle';
    },
  };
}
