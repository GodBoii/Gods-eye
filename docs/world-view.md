# World view retired

World view has been removed from the security workspace. Use [Earth console](earth-edition.md) at http://127.0.0.1:4173/ for geographic data.

NASA EONET was the only live dataset missing from Earth console. Its open natural events now appear in Earth console's Natural events layer through `GET /api/natural-events`. USGS earthquakes, CelesTrak satellites and ADSB.lol aircraft reports already have Earth implementations, so their duplicate World view endpoints were removed with the Go feed service.

The compact vector globe, combined record list, live-layer GeoJSON export and old React components have been removed. Earth console keeps its saved views, pins, map tools and personal-workspace export. Existing World view browser pins and `.godseye/world-cache/` files have not been deleted or automatically migrated. Historical license notices remain in `licenses/`.

For current feed coverage, caching, source links and data terms, see the [Earth console guide](earth-edition.md). Earlier verification documents describe the application at the date of those checks.