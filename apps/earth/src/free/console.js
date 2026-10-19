import * as Cesium from 'cesium';
import { EXCLUDED, layerAllowed } from './policy.js';
import { readWorkspace, saveWorkspace, workspaceGeoJSON } from './workspace.js';
import { setScopeMaskEnabled } from '../scopeMask.js';
import { forecastAt } from './forecast.js';
import { mountNaturalEvents } from './naturalEvents.js';
import './console.css';

const descriptions = {
  flights: 'adsb.lol · within 250 nautical miles', military: 'adsb.lol · reported aircraft', satellites: 'CelesTrak · calculated orbital positions',
  earthquakes: 'USGS · past 24 hours', 'natural-events': 'NASA EONET · open events, past 30 days', 'fire-perimeters': 'NIFC · reported fire boundaries', 'air-quality': 'ECCC · Canadian observations',
  'local-datacenters': 'OpenStreetMap · bundled snapshot', 'local-dams': 'OpenStreetMap · bundled snapshot',
  'telegeography-submarine-cables': 'TeleGeography · CC BY-NC-SA', cctv: 'Public traffic cameras · regional coverage',
  radio: 'Radio Browser · public streams', bikeshare: 'GBFS · supported cities', transit: 'Public transit · supported networks',
  'rocket-launches': 'Launch Library 2 · scheduled missions', 'recent-imagery': 'NASA / USGS · published imagery',
  wind: 'NOAA · model forecast', 'weather-radar': 'Iowa Mesonet · precipitation', 'weather-satellite': 'NASA / NOAA · clouds',
  'weather-lightning': 'NOAA · observed lightning', 'weather-cyclones': 'NOAA · tropical systems',
  'gnss-integrity': 'ADS-B observations · estimated interference', 'military-installations': 'OpenStreetMap · mapped locations',
  'military-awareness': 'Context from enabled layers', 'alpr-cameras': 'OpenStreetMap · mapped cameras',
  directions: 'OSRM · public routing', 'bhote-koshi-2026': 'Recorded case study · CC BY-NC',
  'bhote-koshi-locator': 'Nepal · geographic context', 'local-adsb': 'Optional local receiver',
};
const jumps = [ ['Earth', 10, 20, 22000000], ['India', 78.96, 22.59, 5500000], ['Tokyo', 139.69, 35.68, 45000], ['Austin', -97.74, 30.27, 45000], ['Iceland', -19, 64.8, 900000] ];
const priority = ['earthquakes', 'natural-events', 'flights', 'satellites', 'weather-radar', 'wind', 'cctv', 'rocket-launches', 'fire-perimeters'];
const element = (tag, className, text) => { const node = document.createElement(tag); if (className) node.className = className; if (text !== undefined) node.textContent = text; return node; };
const button = (text, action, className = '') => { const node = element('button', className, text); node.type = 'button'; node.addEventListener('click', action); return node; };

/** A new control shell over the upstream viewer, lifecycle, tools and layer engines. */
export function mountFreeConsole(application) {
  const { scene: { viewer, mapStackController }, data: { dataManager }, controls: { styleManager } } = application.getComponents();
  const lifetime = new AbortController();
  const { signal } = lifetime;
  let workspace = { version: 1, views: [], pins: [] };
  let tab = 'layers';
  let query = '';
  let updateNaturalEvents = null;
  const rows = new Map();
  const root = element('div', 'free-console');
  root.innerHTML = `
    <header class="free-header">
      <a class="free-brand" href="http://127.0.0.1:8765"><span class="free-eye" aria-hidden="true">◉</span><span>GOD'S EYE<small>EARTH CONSOLE</small></span></a>
      <nav aria-label="Workspaces"><a href="http://127.0.0.1:8765">Security</a><span aria-current="page">Earth</span></nav>
      <button class="free-command" type="button">Search a place or command <kbd>Ctrl K</kbd></button>
      <span class="free-keyless"><i></i> KEYLESS EDITION</span>
      <button class="free-mobile-toggle" type="button" aria-expanded="false" aria-controls="free-sidebar">Layers</button>
    </header>
    <aside class="free-sidebar" id="free-sidebar" aria-label="Earth workspace">
      <div class="free-side-heading"><span>Observe the planet.</span><p>Public sources. Your own perspective.</p></div>
      <div class="free-tabs" role="group" aria-label="Console sections">
        <button type="button" data-tab="layers" aria-pressed="true">Layers</button><button type="button" data-tab="options" aria-pressed="false">Options</button><button type="button" data-tab="views" aria-pressed="false">Views</button><button type="button" data-tab="excluded" aria-pressed="false">Excluded</button>
      </div>
      <div class="free-layer-search"><input aria-label="Filter layers" placeholder="Filter layers…" type="search" /></div>
      <div class="free-side-content"></div>
      <div class="free-side-footer"><span class="free-active-count">0 layers enabled</span><button type="button" class="free-clear">Clear all</button><p>Source code by Bilawal Sidhu · MIT<br>Data retains its original terms.</p></div>
    </aside>
    <main class="free-map-ui" aria-label="Interactive Earth">
      <div class="free-map-heading"><span class="free-overline">LIVE EARTH / OPEN SOURCES</span><h1>A different point of view.</h1><p>Drag to explore. Scroll to get closer.</p></div>
      <div class="free-quick-jumps" aria-label="Quick locations"></div>
      <div class="free-map-actions"><button type="button" data-action="tools" aria-pressed="false">Map tools</button><button type="button" data-action="details" aria-pressed="false">Context</button><button type="button" data-action="focus" aria-pressed="false">Focus view</button></div>
      <div class="free-scale"><span class="free-coordinates">Locating camera…</span><span class="free-clock"></span></div>
      <div class="free-map-bottom"><label>Base map <select aria-label="Base map"><option value="esri-imagery">Satellite</option><option value="osm">OpenStreetMap</option></select></label><button type="button" data-action="weather">Weather here</button><button type="button" data-action="sun" aria-pressed="false">Day / night</button><button type="button" data-action="pin">Pin center</button><button type="button" data-action="save">Save view</button><button type="button" data-action="export">Export</button></div>
    </main>
    <div class="free-notice" role="status" aria-live="polite"></div>
    <aside class="free-weather" aria-label="Weather at map center" hidden><header><span>WEATHER AT MAP CENTER</span><button type="button" aria-label="Close weather">×</button></header><div role="status"></div><a href="https://open-meteo.com/" target="_blank" rel="noopener">Open-Meteo · CC BY 4.0 · free for noncommercial use</a></aside>
    <dialog class="free-palette" aria-label="Search places and commands"><form method="dialog"><span>GO SOMEWHERE</span><button aria-label="Close command palette">Esc</button></form><input type="search" aria-label="Place, coordinates or command" placeholder="Tokyo, 28.6 77.2, or a layer name…" /><p>Enter to search places. Coordinates use latitude, longitude.</p><div class="free-command-results"></div></dialog>
    <dialog class="free-name-dialog" aria-label="Name saved item"><form><label>Name<input name="name" maxlength="100" required autocomplete="off" /></label><div><button type="button" data-cancel>Cancel</button><button type="submit">Save</button></div></form></dialog>`;
  document.body.append(root);
  const find = (selector) => root.querySelector(selector);
  const advancedLayers = document.getElementById('data-toggles');
  const advancedParent = advancedLayers.parentNode;
  const notice = (message) => { find('.free-notice').textContent = message; };
  try { workspace = readWorkspace(); } catch (error) { notice(error.message); }
  const persist = (next) => { saveWorkspace(next); workspace = next; };
  setScopeMaskEnabled(false);
  viewer.scene.backgroundColor = Cesium.Color.BLACK;
  viewer.scene.skyBox.show = false;
  styleManager.orbitController.stop();
  const pinSource = new Cesium.CustomDataSource('Personal map pins');
  void viewer.dataSources.add(pinSource);
  const renderPins = () => {
    pinSource.entities.removeAll();
    for (const pin of workspace.pins) pinSource.entities.add({ position: Cesium.Cartesian3.fromDegrees(pin.lon, pin.lat),
      point: { pixelSize: 8, color: Cesium.Color.fromCssColorString('#d6eea0'), outlineColor: Cesium.Color.BLACK, outlineWidth: 2, disableDepthTestDistance: Number.POSITIVE_INFINITY },
      label: { text: pin.name, font: '12px sans-serif', pixelOffset: new Cesium.Cartesian2(0, -20), fillColor: Cesium.Color.WHITE, showBackground: true, backgroundColor: Cesium.Color.BLACK.withAlpha(.8), disableDepthTestDistance: Number.POSITIVE_INFINITY } });
    viewer.scene.requestRender();
  };
  renderPins();
  const fly = (lon, lat, height) => {
    styleManager.orbitController.stop();
    viewer.trackedEntity = undefined;
    viewer.camera.flyTo({ destination: Cesium.Cartesian3.fromDegrees(lon, lat, height), duration: matchMedia('(prefers-reduced-motion: reduce)').matches ? 0 : 1.5 });
  };
  for (const [name, lon, lat, height] of jumps) find('.free-quick-jumps').append(button(name, () => fly(lon, lat, height)));

  function layerRow(layer) {
    const row = element('label', 'free-layer');
    const checkbox = element('input'); checkbox.type = 'checkbox'; checkbox.checked = layer.enabled;
    const copy = element('span', 'free-layer-copy');
    copy.append(element('strong', '', layer.name), element('small', '', descriptions[layer.id] || layer.source));
    const status = element('span', 'free-layer-status', 'OFF');
    checkbox.addEventListener('change', async () => {
      checkbox.disabled = true;
      try { await dataManager.setEnabled(layer.id, checkbox.checked, { origin: 'user' }); }
      catch (error) { notice(`${layer.name}: ${error.message}`); }
      finally { checkbox.disabled = false; sync(); }
    });
    row.append(checkbox, copy, status); rows.set(layer.id, { checkbox, status, row }); return row;
  }
  function sync() {
    const layers = dataManager.getAll();
    let active = 0;
    for (const layer of layers) {
      if (layer.enabled && layerAllowed(layer.id)) active++;
      const ui = rows.get(layer.id); if (!ui) continue;
      if (!ui.checkbox.disabled) ui.checkbox.checked = layer.enabled;
      const error = layer.stats?.error || layer.stats?.lastError || layer.stats?.managerRefreshError;
      const busy = layer.lifecycleState === 'enabling' || layer.stats?.refreshing;
      ui.status.textContent = error ? 'ERR' : busy ? '…' : layer.enabled ? (layer.stats?.count > 0 ? layer.stats.count.toLocaleString() : 'ON') : 'OFF';
      ui.row.dataset.active = String(layer.enabled); ui.row.dataset.error = String(Boolean(error));
      ui.row.title = error ? String(error) : descriptions[layer.id] || layer.source;
    }
    find('.free-active-count').textContent = `${active} ${active === 1 ? 'layer' : 'layers'} enabled`;
    updateNaturalEvents?.();
  }
  async function restore(view) {
    for (const layer of dataManager.getAll().filter((layer) => layerAllowed(layer.id)))
      await dataManager.setEnabled(layer.id, view.layers.includes(layer.id), { origin: 'user' });
    viewer.camera.flyTo({ destination: new Cesium.Cartesian3(...view.position), orientation: { heading: view.heading, pitch: view.pitch, roll: view.roll }, duration: 1 });
    notice(`Restored ${view.name}. Feed observations are current, not a historical replay.`);
  }
  function renderPanel() {
    updateNaturalEvents = null;
    if (advancedLayers.parentNode !== advancedParent) advancedParent.append(advancedLayers);
    const content = find('.free-side-content'); content.replaceChildren(); rows.clear();
    find('.free-layer-search').hidden = tab !== 'layers';
    for (const node of root.querySelectorAll('[data-tab]')) node.setAttribute('aria-pressed', String(node.dataset.tab === tab));
    if (tab === 'layers') {
      content.append(element('div', 'free-section-label', 'DATA CATALOG'));
      const rank = (id) => priority.includes(id) ? priority.indexOf(id) : priority.length;
      const layers = dataManager.getAll().filter((layer) => layerAllowed(layer.id) && `${layer.name} ${descriptions[layer.id] || ''}`.toLowerCase().includes(query)).sort((a, b) => rank(a.id) - rank(b.id));
      for (const layer of layers) {
        content.append(layerRow(layer));
        if (layer.id === 'natural-events') updateNaturalEvents = mountNaturalEvents(content, {
          getLayer: () => dataManager.isEnabled('natural-events') ? dataManager.layers.get('natural-events')?.module : null,
          fly,
        });
      }
      if (!layers.length) content.append(element('p', 'free-empty', 'No layers match your search.'));
      sync();
    } else if (tab === 'options') {
      content.append(element('h2', '', 'Layer options'), element('p', 'free-explanation', 'The upstream controls for source filters, orbital groups, radio, routing and imagery. Options vary by layer.'), advancedLayers);
    } else if (tab === 'excluded') {
      content.append(element('h2', '', 'Excluded providers'), element('p', 'free-explanation', 'These integrations are disconnected. No key entry or billing setup exists in this edition. Free feeds still have their own terms and rate limits.'));
      for (const entry of EXCLUDED) { const item = element('article', 'free-excluded-item'); item.append(element('h3', '', entry.name), element('small', '', entry.reason), element('p', '', entry.replacement)); content.append(item); }
    } else {
      content.append(element('h2', '', 'Your perspectives'), element('p', 'free-explanation', 'Camera positions, selected layers and pins stay in this browser. Imported files last for this session.'));
      if (!workspace.views.length) content.append(element('p', 'free-empty', 'Find a place, choose layers, then save your view.'));
      for (const view of workspace.views) {
        const row = element('div', 'free-saved-row'); row.append(button(view.name, () => void restore(view).catch((error) => notice(error.message))), button('×', () => { try { persist({ ...workspace, views: workspace.views.filter((v) => v.id !== view.id) }); renderPanel(); } catch (error) { notice(error.message); } }));
        row.lastChild.setAttribute('aria-label', `Delete view ${view.name}`); content.append(row);
      }
      content.append(element('div', 'free-section-label', 'MAP PINS'));
      for (const pin of workspace.pins) {
        const row = element('div', 'free-saved-row'); row.append(button(pin.name, () => fly(pin.lon, pin.lat, 100000)), button('×', () => { try { persist({ ...workspace, pins: workspace.pins.filter((p) => p.id !== pin.id) }); renderPins(); renderPanel(); } catch (error) { notice(error.message); } }));
        row.lastChild.setAttribute('aria-label', `Delete pin ${pin.name}`); content.append(row);
      }
      if (!workspace.pins.length) content.append(element('p', 'free-empty', 'Use Pin center to mark a location.'));
    }
  }
  for (const node of root.querySelectorAll('[data-tab]')) node.addEventListener('click', () => { tab = node.dataset.tab; renderPanel(); });
  find('.free-layer-search input').addEventListener('input', (event) => { query = event.target.value.toLowerCase(); renderPanel(); });
  find('.free-clear').addEventListener('click', () => void dataManager.clearSelectedLayers().catch((error) => notice(error.message)));
  const unsubscribe = dataManager.subscribe(sync);
  const syncTimer = setInterval(() => { if (!document.hidden) sync(); }, 2000);
  renderPanel();

  const palette = find('.free-palette'), search = palette.querySelector('input'), results = find('.free-command-results');
  let searchRequest = null;
  const openPalette = () => { palette.showModal(); search.focus(); search.select(); renderCommands(); };
  find('.free-command').addEventListener('click', openPalette);
  function renderCommands() {
    results.replaceChildren(); const text = search.value.toLowerCase();
    for (const jump of jumps.filter(([name]) => name.toLowerCase().includes(text))) results.append(button(`Go to ${jump[0]}`, () => { fly(jump[1], jump[2], jump[3]); palette.close(); }));
    for (const layer of dataManager.getAll().filter((layer) => layerAllowed(layer.id) && layer.name.toLowerCase().includes(text)).slice(0, 8))
      results.append(button(`${layer.enabled ? 'Disable' : 'Enable'} ${layer.name}`, async () => { palette.close(); try { await dataManager.setEnabled(layer.id, !layer.enabled, { origin: 'user' }); sync(); } catch (error) { notice(error.message); } }));
  }
  search.addEventListener('input', renderCommands);
  search.addEventListener('keydown', async (event) => {
    if (event.key !== 'Enter' || !search.value.trim()) return;
    event.preventDefault(); searchRequest?.abort(); searchRequest = new AbortController();
    const controller = searchRequest;
    const query = search.value.trim();
    const coordinates = /^(-?\d+(?:\.\d+)?)\s*[,\s]\s*(-?\d+(?:\.\d+)?)$/.exec(query);
    if (coordinates) {
      const lat = Number(coordinates[1]), lon = Number(coordinates[2]);
      if (Math.abs(lat) > 90 || Math.abs(lon) > 180) { notice('Latitude must be within 90 degrees and longitude within 180.'); return; }
      fly(lon, lat, 100000); palette.close(); return;
    }
    results.replaceChildren(element('p', 'free-empty', 'Searching Photon…'));
    try {
      const response = await fetch(`https://photon.komoot.io/api/?q=${encodeURIComponent(query.slice(0, 200))}&limit=5`, { signal: AbortSignal.any([controller.signal, AbortSignal.timeout(12000)]) });
      if (!response.ok) throw new Error(`Place search returned ${response.status}`);
      const data = await response.json();
      if (!Array.isArray(data.features)) throw new Error('Place search returned invalid data');
      results.replaceChildren();
      for (const feature of data.features.slice(0, 5)) {
        const coords = feature?.geometry?.coordinates;
        if (!Array.isArray(coords) || !coords.slice(0, 2).every(Number.isFinite) || Math.abs(coords[0]) > 180 || Math.abs(coords[1]) > 90) continue;
        const label = [feature.properties?.name, feature.properties?.country].filter((v) => typeof v === 'string').join(', ') || query;
        results.append(button(label, () => { fly(coords[0], coords[1], 70000); palette.close(); }));
      }
      if (!results.childElementCount) results.append(element('p', 'free-empty', 'No places found. Try coordinates.'));
    } catch (error) { if (!controller.signal.aborted) results.replaceChildren(element('p', 'free-empty', error.message)); }
  });
  palette.addEventListener('close', () => searchRequest?.abort());
  document.addEventListener('keydown', (event) => { if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); if (!palette.open) openPalette(); } if (event.key === 'Escape') { document.body.classList.remove('free-focus'); find('[data-action="focus"]').setAttribute('aria-pressed', 'false'); } }, { signal });
  find('.free-mobile-toggle').addEventListener('click', (event) => { const open = document.body.classList.toggle('free-mobile-open'); event.currentTarget.setAttribute('aria-expanded', String(open)); });
  find('[aria-label="Base map"]').addEventListener('change', async (event) => { try { await mapStackController.setStack(event.target.value); } catch (error) { notice(error.message); } });
  const nameDialog = find('.free-name-dialog');
  const weatherPanel = find('.free-weather');
  let weatherRequest = null;
  weatherPanel.querySelector('button').addEventListener('click', () => { weatherRequest?.abort(); weatherPanel.hidden = true; });
  let nameAction = null;
  nameDialog.querySelector('[data-cancel]').addEventListener('click', () => nameDialog.close());
  nameDialog.querySelector('form').addEventListener('submit', (event) => { event.preventDefault(); try { nameAction?.(nameDialog.querySelector('input').value.trim()); nameDialog.close(); if (tab === 'views') renderPanel(); } catch (error) { notice(error.message); } });
  const askName = (initial, action) => { nameAction = action; nameDialog.querySelector('input').value = initial; nameDialog.showModal(); nameDialog.querySelector('input').select(); };
  const center = () => {
    const canvas = viewer.scene.canvas;
    const ray = viewer.camera.getPickRay(new Cesium.Cartesian2(canvas.clientWidth / 2, canvas.clientHeight / 2));
    const point = viewer.scene.globe.pick(ray, viewer.scene);
    if (!point) throw new Error('Point the camera at the Earth before adding a pin.');
    const geo = Cesium.Cartographic.fromCartesian(point);
    return { lon: Cesium.Math.toDegrees(geo.longitude), lat: Cesium.Math.toDegrees(geo.latitude) };
  };
  for (const action of root.querySelectorAll('[data-action]')) action.addEventListener('click', async () => {
    try {
      switch (action.dataset.action) {
        case 'weather': {
          const point = center(); weatherRequest?.abort(); weatherRequest = new AbortController();
          const request = weatherRequest;
          weatherPanel.hidden = false;
          const content = weatherPanel.querySelector('[role="status"]');
          content.replaceChildren(element('p', '', 'Loading forecast…'));
          try {
            const forecast = await forecastAt({ ...point, signal: request.signal });
            if (request.signal.aborted) break;
            content.replaceChildren(element('p', 'free-weather-place', `${point.lat.toFixed(2)}°, ${point.lon.toFixed(2)}°`), element('strong', 'free-temperature', `${forecast.temperature.toFixed(1)}°C`), element('p', '', `Wind ${forecast.wind.toFixed(1)} km/h · Humidity ${forecast.humidity.toFixed(0)}%`));
            const bars = element('div', 'free-temperature-bars');
            const low = Math.min(...forecast.hours), high = Math.max(...forecast.hours);
            for (const temperature of forecast.hours) { const bar = element('span'); bar.style.height = `${8 + 32 * (temperature - low) / Math.max(1, high - low)}px`; bar.title = `${temperature.toFixed(1)}°C`; bars.append(bar); }
            content.append(bars, element('p', 'free-weather-caption', `Today's hourly temperature · UTC · ${low.toFixed(0)}° to ${high.toFixed(0)}°C`));
          } catch (error) { if (!request.signal.aborted) content.replaceChildren(element('p', '', error.message)); }
          break;
        }
        case 'tools': { const open = document.body.classList.toggle('free-tools'); if (open) document.getElementById('pp-toggles').classList.remove('collapsed'); document.body.classList.remove('free-details'); find('[data-action="details"]').setAttribute('aria-pressed', 'false'); action.setAttribute('aria-pressed', String(open)); break; }
        case 'details': { const open = document.body.classList.toggle('free-details'); document.body.classList.remove('free-tools'); find('[data-action="tools"]').setAttribute('aria-pressed', 'false'); action.setAttribute('aria-pressed', String(open)); break; }
        case 'focus': { const open = document.body.classList.toggle('free-focus'); action.setAttribute('aria-pressed', String(open)); break; }
        case 'sun': viewer.scene.globe.enableLighting = !viewer.scene.globe.enableLighting; action.setAttribute('aria-pressed', String(viewer.scene.globe.enableLighting)); viewer.scene.requestRender(); break;
        case 'save': {
          if (workspace.views.length >= 12) throw new Error('Twelve views saved. Delete one before saving another.');
          const position = viewer.camera.positionWC;
          const view = { id: crypto.randomUUID(), position: [position.x, position.y, position.z], heading: viewer.camera.heading, pitch: viewer.camera.pitch, roll: viewer.camera.roll, layers: dataManager.getAll().filter((layer) => layer.enabled && layerAllowed(layer.id)).map((layer) => layer.id) };
          askName(`View ${workspace.views.length + 1}`, (name) => { persist({ ...workspace, views: [...workspace.views, { ...view, name }] }); notice('View saved in this browser.'); }); break;
        }
        case 'pin': {
          if (workspace.pins.length >= 100) throw new Error('One hundred pins saved. Delete a pin first.');
          const coordinates = center();
          askName('Map pin', (name) => { persist({ ...workspace, pins: [...workspace.pins, { ...coordinates, name, id: crypto.randomUUID() }] }); renderPins(); notice('Pin saved in this browser.'); }); break;
        }
        case 'export': {
          const blob = new Blob([JSON.stringify(workspaceGeoJSON(workspace), null, 2)], { type: 'application/geo+json' });
          const url = URL.createObjectURL(blob); const link = element('a'); link.href = url; link.download = 'godseye-workspace.geojson'; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); notice('Exported saved views and map pins. Live provider datasets are not included.'); break;
        }
      }
    } catch (error) { notice(error.message); }
  });
  const updateCamera = () => {
    const position = viewer.camera.positionCartographic;
    find('.free-coordinates').textContent = `${Cesium.Math.toDegrees(position.latitude).toFixed(2)}° / ${Cesium.Math.toDegrees(position.longitude).toFixed(2)}° / ${(position.height / 1000).toFixed(0)} km`;
  };
  const removeCamera = viewer.camera.moveEnd.addEventListener(updateCamera); updateCamera();
  const clock = setInterval(() => { find('.free-clock').textContent = new Date().toISOString().slice(11, 19) + ' UTC'; }, 1000);
  window.addEventListener('pagehide', () => { lifetime.abort(); searchRequest?.abort(); weatherRequest?.abort(); unsubscribe(); removeCamera(); clearInterval(clock); clearInterval(syncTimer); }, { once: true });
  // Do not let the legacy first-run camera flight leave the initial view at street level.
  void styleManager.initialRestorePromise.then(() => {
    if (!styleManager.hasShareState) { viewer.camera.cancelFlight(); fly(30, 18, 22000000); }
  }).catch((error) => notice(error.message));
  notice('Ready. Enable a layer to load its public source.');
}
