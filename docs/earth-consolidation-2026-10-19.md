# Earth console consolidation verification

Verified on 19 October 2026.

World view has been removed from security navigation, its React implementation and public basemap asset have been deleted, and its Go feed service and `/api/world/{layer}` routes have been removed. Unused dashboard D3 and satellite.js dependencies were removed. Historical license notices and existing user storage were preserved.

NASA EONET was the missing dataset. Earth console now provides `GET /api/natural-events` and a selectable Natural events layer. Its records include categories, reported coordinates, observation times and safe provider links. The expandable list supports filtering and map navigation. Existing USGS, CelesTrak and ADSB.lol implementations remain in Earth console. The new layer uses permanent state token `5`; all previously published token assignments remain unchanged.

## Automated checks

- All Go package tests and `go vet ./...` pass. The Docker dashboard build also ran all Go tests on Linux.
- Five dashboard tests and its TypeScript/production build pass.
- Eighty-four focused Earth tests pass, covering the EONET provider/source/display lifecycle, catalog construction, absent sources and layer-state serialization. The existing Street Level source test was aligned with the keyless edition's excluded Mapillary provider.
- All 26 existing free-edition tests pass.
- Eight EONET tests also pass inside the rebuilt Earth container on Node 26. These cover fixed routing, dev/preview hooks, concurrent acquisition, cache reuse, stale retention, retry cooldown, malformed/oversized responses, missing-provider failures, normalized records, real Cesium entities and cancellation.
- The import-direction check passes. A direct allocation check against `origin/main`'s published ledger confirms that existing layer tokens are preserved and the new token is allocated correctly. The inherited token-check CLI assumes a standalone upstream Git root, so its unmodified command cannot resolve the ledger under this monorepo's `apps/earth` prefix.
- Both production frontends build. Earth retains its existing large-chunk build warning.

## Running application

`docker compose up --build -d --wait` completed. Dashboard, Earth and the Python migration candidate are healthy. The existing named state volumes were retained. An initial esbuild installation failure cleared on retry.

Headless Chrome checks ran against the rebuilt services at `http://127.0.0.1:8765` and `http://127.0.0.1:4173`:

- World view is absent from navigation, and the Earth console entry describes natural events.
- The removed `/api/world/events` route returns HTTP 404.
- The live EONET endpoint returned 49 event points at verification time. Counts change with provider data.
- Natural events can be enabled and disabled. Categories, observation times, coordinates and provider links appear in the record list.
- Filtering, clearing the filter and jumping to an event work. The Cesium map and event marker render visibly.
- The enabled layer restores after reload.
- At 1440 × 960 and 390 × 844, the records and mobile drawer work without horizontal page overflow.
- No browser runtime errors or failed network requests were observed during the final check.

Screenshots and browser results remain local under ignored `.godseye/qa-consolidation/`. Temporary native verification servers on ports 4174 and 8777 were stopped after the container checks.

The old combined World view record browser and live-layer GeoJSON export were removed with that section. Earth retains its personal pins and saved-view export. Existing World view pins and disk caches were left untouched and were not automatically imported. See [Earth console](earth-edition.md) for current provider coverage and terms.
