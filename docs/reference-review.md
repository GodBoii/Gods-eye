# God's Eye View reference review

Reviewed [bilawalsidhu/gods-eye-view](https://github.com/bilawalsidhu/gods-eye-view) at commit `a0400b52fb25d269158f476ff429185c28ab621b` on 2026-10-16. This is a geospatial visualization application using Cesium and public data feeds; it is not a source-code auditing engine.

Its [license](https://github.com/bilawalsidhu/gods-eye-view/blob/a0400b52fb25d269158f476ff429185c28ab621b/LICENSE) permits source-code reuse under MIT, with the original copyright and permission notice retained. The same file explicitly excludes third-party datasets and 3D assets from that grant. Some bundled data has non-commercial terms, and provider services have separate credentials, quotas and usage terms. Open source does not imply unrestricted data rights or free infrastructure.

Inspected the package structure, license, `src/renderGovernor.js` and `src/services/requests.js`. Useful patterns include modular visualization layers, cancellation-aware requests, explicit unavailable-capability states, and avoiding continuous rendering when a scene is idle.

At the initial 0.2 review, no reference code was copied. Version 0.3 now has a separate World view section. It vendors the MIT-licensed `src/sources/tle.js` and `src/layers/earthquakes/records.js` from upstream commit `1df2a272cf7cfbb2f1a4c637c897e90719b0af95`, with original helper bodies, source-path headers and full attribution in `licenses/gods-eye-view.txt`. These helpers support live earthquake normalization and station-orbit parsing; satellite.js performs SGP4 calculations.

The globe renderer and React interface are original project code using D3's orthographic projection. Natural Earth land geometry was obtained separately under public-domain terms. Live public feeds include USGS, NASA EONET, CelesTrak and a bounded regional ADSB.lol aircraft query. Local pins and GeoJSON export are included. See [World view](world-view.md) for feature coverage, data licensing and verification.

No upstream non-commercial datasets, imagery, 3D models, credentials, paid tiles or paid-provider integration was copied. Camera/ship feeds, cinematic tours, AI voice and the reference application's full Cesium renderer are not implemented. A geographic location remains separate from ownership, reachability or security coverage.
