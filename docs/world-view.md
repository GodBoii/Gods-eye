# World view, version 0.3

Open the local dashboard and select **World view**. It is a separate section alongside security checks. It requires no API key, account or paid service. The geographic view uses a locally bundled vector basemap; internet access is needed only for enabled public live feeds.

## Working functionality

| Capability | Implementation and scope |
| --- | --- |
| Globe | Orthographic globe with Natural Earth land, graticule, hemisphere clipping, drag rotation, keyboard arrows, zoom controls and coordinate navigation |
| Earthquakes | USGS last-24-hour feed, normalized with the reference repository's helper; only known magnitudes M2.5+ appear |
| Natural events | NASA EONET open events from the past 30 days, at most 100 provider events; the latest valid point is shown, not an affected-area outline |
| Station orbits | CelesTrak station TLE catalog and satellite.js SGP4 propagation; positions update locally every ten seconds while the page is visible |
| Aircraft | ADSB.lol reported positions within 250 nautical miles of 20°N, 79°E; this is a central-India regional view, not global flight coverage |
| Inspection | Searchable paginated records, selected-record details, coordinates, observation/calculation time and provider links |
| Local annotations | Up to 100 labeled coordinate pins saved in browser storage, with validation and removal controls |
| Export | GeoJSON of all records in enabled layers plus saved pins, retaining source links and aircraft-data attribution |

Earthquakes and natural events start enabled. Aircraft and orbital layers start off and can be enabled explicitly. Provider data is never replaced with invented live records when a feed fails. Empty data and unavailable data are different states.

Satellite markers show calculated ground positions and altitude estimates, not camera imagery or live GPS measurements. TLE checksums and matching catalog numbers are checked; orbital elements more than 14 days from the calculation time are omitted. Legacy TLEs cover only the available five-digit catalog subset, not all newly cataloged satellites. NASA event metadata may be approximate or revised. Aircraft reports older than two minutes are hidden, and coverage depends on volunteer receivers.

## Free sources and licensing

Source code, data and hosted services have separate terms. Free access does not grant unrestricted redistribution or a guaranteed service level.

| Source | Use and terms |
| --- | --- |
| [God's Eye View](https://github.com/bilawalsidhu/gods-eye-view) | Two MIT-licensed source helpers, with copyright and permission notice retained |
| [Natural Earth](https://www.naturalearthdata.com/about/terms-of-use/) | Public-domain 110m land geometry, bundled locally; no tile provider or token |
| [USGS](https://earthquake.usgs.gov/earthquakes/feed/v1.0/geojson.php) | Public earthquake summaries; USGS attribution retained |
| [NASA EONET](https://eonet.gsfc.nasa.gov/docs/v3) | Public natural-event metadata, with source links; no linked third-party imagery or article content is copied |
| [CelesTrak](https://celestrak.org/usage-policy.php) | Public orbital data under provider usage policy; cached for two hours, including across server restarts |
| [ADSB.lol](https://www.adsb.lol/docs/open-data/api/) | Free public aircraft data under [ODbL 1.0](https://opendatacommons.org/licenses/odbl/1-0/); visible attribution and export attribution are retained. Redistribution of a derived aircraft database must comply with its share-alike terms |

The exact reused source files are:

- `src/sources/tle.js`, stored locally as `apps/web/src/world/upstream/tle.mjs`.
- `src/layers/earthquakes/records.js`, stored locally as `apps/web/src/world/upstream/earthquakes.mjs`.

Both come from upstream commit `1df2a272cf7cfbb2f1a4c637c897e90719b0af95`. Only attribution headers were added to their helper code. Type declarations and integration logic are local additions. The full upstream license, including its warning that third-party data is separate, is retained in `licenses/gods-eye-view.txt`.

Natural Earth geometry comes from `nvkelso/natural-earth-vector` commit `ca96624a56bd078437bca8184e78163e5039ad19`, `geojson/ne_110m_land.geojson`. Its SHA-256 is `9e0729ee253ca7d7a5c4ae9395fb1902264c5377c52e224d13dd85010e2835d9`. The D3 and satellite.js notices are in `licenses/world-libraries.txt`. Source code for those dependencies is obtained from pinned npm versions recorded in the lockfile.

## Explicitly excluded

No Google Maps key, Cesium ion account, paid photorealistic tiles, metered AI voice, commercial imagery, non-commercial TeleGeography cable bundle, flood-imagery bundle or upstream 3D model is required or included. The original repository's entire application has not been copied. Camera feeds, ship tracking, radios, weather rendering, military layers, tours and voice control are not implemented in this section, even where an individual free source might exist.

The 26 pentesting tools listed by the user remain unintegrated. The source secret scanner and limited HTTPS checker remain native project features. World view adds public geographic context, not additional penetration-testing engines.

## Resource and privacy behavior

The Go server accepts only four fixed upstream feed IDs. It does not provide an arbitrary URL proxy. Requests have a 12-second deadline, a 2 MiB response-body limit and redirect refusal. Per-layer request coalescing avoids duplicate upstream downloads. Cache durations are one minute for USGS, ten minutes for EONET, two hours for CelesTrak and thirty seconds for regional aircraft. The UI checks for expired feeds each minute while visible.

Validated last transport-level snapshots are cached under `.godseye/world-cache/`, with source and acquisition timestamps. Provider failures retain the dated last snapshot as stale and apply a one-minute cooldown. Browser-side structural validation rejects malformed records before rendering. A malformed structural payload is shown as a layer error. The endpoint never accepts API keys or provider credentials.

No location permission is requested. Panning, coordinate searches and pins do not send the user's coordinates to a provider. The aircraft query uses the documented fixed region. Pins are saved only in this browser and local origin; the map does not infer the physical location of registered security assets. GeoJSON exports are portable local downloads. Changing host or port changes browser-storage scope.

The world chunk is lazy-loaded only when selected. The SVG globe has no continuous render loop. Hidden tabs suspend position refresh and automatic feed acquisition. Public feeds may be delayed, rate-limited or unavailable; those states remain visible.

## Verification

`npm test` exercises the reused earthquake/TLE helpers, malformed coordinates, magnitude filtering, source-link sanitation, SGP4 position changes, checksum rejection, stale aircraft filtering, pin bounds, GeoJSON coordinate order and data attribution.

Go tests exercise concurrent request coalescing, fresh cache reuse across service restart, stale-data retention, cooldowns, unknown-source rejection, malformed/oversized responses and redirects. Existing scan, inventory and reporting tests still run.

Browser checks cover real-feed rendering, layer toggles, coordinate navigation, keyboard rotation, zoom, pin creation, pin persistence across reload, filtering, record inspection and GeoJSON download. Counts are a point-in-time observation and change with source data. Desktop/mobile layout and browser logs are checked before delivery.
