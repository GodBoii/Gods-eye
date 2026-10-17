# Earth console, keyless edition

The complete `bilawalsidhu/gods-eye-view` checkout at commit `1df2a272cf7cfbb2f1a4c637c897e90719b0af95` was copied into `apps/earth` on 2026-10-17. Git metadata and installed dependencies are excluded. Original source, tests, build tools, documentation, models, datasets and license notices are retained. This is a full source adaptation, not the earlier two-helper World view subset.

Run `pwsh -File scripts/start.ps1 -Build` on the first run. Subsequent starts can omit `-Build`. Node.js 24.14 or newer in the upstream supported major range and Go 1.25 or newer are required to build. Open the Earth console at `http://127.0.0.1:4173`. The existing security workspace runs at `http://127.0.0.1:8765` and links to it through its Earth console section. Both services bind to loopback.

## Active edition

The new black interface uses the actual upstream Cesium viewer, catalog and lifecycle manager. Its 29 free layer entries cover reported civil and military aircraft, satellites, earthquakes, cameras, radio, public transport, bike sharing, weather, geographic infrastructure, cables and recorded case studies. Layers load only when enabled. Provider outages and coverage limits still apply. The Context and Map tools buttons expose inherited detail and display tools, including drawing, recording and local GeoJSON/KML/KMZ/GPX import. The Options tab preserves the upstream source filters and layer-specific controls.

Added in this edition:

- A command palette opened with Ctrl K or the search button. It searches layer actions locally and places through Photon on explicit submission. Latitude/longitude navigation works without a place-search service.
- Up to twelve saved camera views with selected layers, plus up to one hundred named map pins in browser-local storage. Restoring a view loads current observations; it does not replay historical feeds.
- GeoJSON export of personal pins, with saved camera views as collection metadata. Live third-party datasets are not silently copied into this export. Imported geographic files last for the browser session.
- A weather inspector at the map center. Open-Meteo supplies current temperature, wind, humidity and a UTC daily temperature chart. The free hosted API is for noncommercial use and its data requires CC BY 4.0 attribution. See [Open-Meteo](https://open-meteo.com/).
- Focus view, quick locations, day/night lighting and an explicit Excluded providers section.

## Removed from the running application

The edition's Vite configuration does not load dotenv files, does not install the provider-key setup endpoint, and does not register Google, Cesium ion, TomTom, AISStream, Mapillary, FIRMS or OpenAI provider proxies. It removes known provider credentials from its own process environment so optional camera and launch-service fallbacks cannot pick up ambient keys. This does not change system environment settings. Google token acquisition and voice startup are disconnected. The HUD cannot request AI summaries. Billing and setup routes return HTTP 410. Source records from removed providers cannot be enabled through restored layer state. Historical upstream modules remain in the source copy for provenance, but are not an active service configuration. Run this edition using the root `vite.config.js`, not the historical alternate standalone configuration.

| Excluded integration | Replacement or result |
| --- | --- |
| Google 3D tiles, Places and Street View | Esri / OpenStreetMap imagery, Photon place search, Re:Earth terrain |
| Cesium ion and Bing token-based imagery | Open-source Cesium renderer; no ion account or hosted assets |
| OpenAI audio and summaries | Local command palette and deterministic telemetry |
| TomTom traffic | No live traffic-flow layer; public transport and bike feeds remain |
| AISStream | No live vessel feed |
| Mapillary | No account-token street imagery |
| FIRMS live fire detections | Free registration is still a key requirement, so the live feed is removed; keyless fire perimeters remain |
| OpenSky authentication | Direct adsb.lol viewport reports, bounded to 250 nautical miles, with ODbL attribution |

The aircraft proxy validates coordinates, limits response size, applies a deadline, coalesces concurrent requests and bounds its short-lived cache. Failed requests are shown as unavailable instead of displaying old positions as fresh. It does not provide historical tracks or global coverage.

## Rights and operating limits

The upstream MIT license covers source code. Keep `apps/earth/LICENSE` and its attribution. Third-party models and data retain the notices in `apps/earth/DATA_SOURCES.md` and their own directories. TeleGeography cables use CC BY-NC-SA 3.0, and Bhote Koshi imagery uses CC BY-NC 4.0. These retained datasets are free for permitted noncommercial use; they are not granted unrestricted commercial rights. Other sources have attribution, share-alike, quota or regional limitations. Keyless access is not a guarantee of unlimited service or availability.

The original security scanner, assets, HTTPS checks, report downloads, and compact World view remain independent of the Earth process. This console does not add an exploit runner or any of the previously listed pentesting tools.

The copied source distribution includes large geographic datasets and binary models. A scan of the entire workspace therefore reports partial coverage under the scanner's existing input rules. This is intentional; the scanner does not silently skip those files and claim completion. The dashboard smoke script defaults to the native `internal` source directory, and its binary fixture separately verifies partial-coverage reporting. Use `-SourceTarget` to choose another source directory.
