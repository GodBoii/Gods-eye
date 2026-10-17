# Earth edition verification, 2026-10-17

## Source copy and configuration

All 2,063 tracked files from `bilawalsidhu/gods-eye-view` revision `1df2a272cf7cfbb2f1a4c637c897e90719b0af95` exist in `apps/earth`. Original licensing, per-dataset attribution, documentation and executable script modes are retained. Git metadata and installed dependencies are not vendored.

The active Vite configuration uses only the selected free provider middleware. Known credential variables are cleared in the server process. Google token acquisition, provider-key setup, metered voice and AI summary requests are disconnected. Real HTTP tests confirmed that removed provider and setup endpoints return 410, invalid flight coordinates return 400, and unsupported methods return 405.

## Automated checks

| Check | Result |
| --- | --- |
| Earth production build, Vite 6.4.3 on Node 24.19.0 | Passed |
| `npm run test:free` | 26 tests passed |
| Existing React dashboard type check and production build | Passed |
| Existing compact World view frontend tests | 6 tests passed |
| `go test ./...` | Passed at the time of verification |
| Live dashboard smoke checks | 12 checks passed |
| Launcher PowerShell syntax | Passed |
| Full upstream source-file presence | 2,063 present, zero missing |

The Earth suite covers billing/setup blocking through a real HTTP server, invalid coordinates and methods, application identification for aircraft requests, normalization and cache reuse, ambient-credential isolation, workspace persistence and export, malformed storage, forecast validation, inherited earthquake cancellation/ownership, satellite source contracts, and terrain retry behavior.

The live smoke run exercised native source scanning, all three secret rules, JSON/SARIF redaction, report mapping, partial coverage, cancellation, finding limits, overwrite protection and temporary inventory registration/removal. Evidence is saved locally under `.godseye/smoke-90cb0805e4ef49ed8ee9c91d6eeb9383`.

An initial full-workspace smoke scan correctly returned partial coverage because the newly copied repository includes binary models and oversized datasets. The smoke script now defaults to `internal` and retains a separate binary-coverage assertion. Scanner policy was not weakened. The smoke script also now resets the caller's native exit status after the intentionally rejected overwrite test.

## Browser checks

Verified the real production app at `http://127.0.0.1:4173`, with the existing dashboard at `http://127.0.0.1:8765`.

- The Cesium globe, satellite base imagery and keyless terrain rendered. Quick location navigation changed the actual camera.
- USGS earthquake geometry and labels rendered with a live count that changed from 54 to 55 during verification.
- The live aircraft endpoint returned HTTP 200 and 58 normalized reports for the Austin region. The first request exposed the provider's requirement for an identifying application User-Agent; this is fixed and covered by regression testing.
- Photon place search returned Tokyo matches. The command palette, coordinate navigation, filter controls and keyboard focus were exercised.
- Saved a camera view and a geographic pin. Both remained after reload. A GeoJSON download contained the saved pin and view metadata.
- The map-center forecast displayed real current temperature, humidity, wind and hourly temperatures with Open-Meteo attribution.
- The Options tab exposed inherited source controls. The Map tools drawer exposed drawing/import and display controls after fixing its inherited collapsed state. Removed providers do not appear as usable layer toggles.
- The Excluded section displayed eight disconnected provider groups and their replacements or unavailable capabilities.
- Checked desktop and 390 × 844 mobile layouts. Mobile document width and scroll width were both 390 pixels. The mobile layer drawer and map-tools controls were reachable.
- The dashboard's Earth console navigation section and launch link rendered with the black theme. Existing scan and report workflows passed their live smoke tests.

Previews are saved locally in `.godseye/earth-console-preview.png`, `.godseye/earth-exclusions-preview.png` and `.godseye/earth-mobile-preview.png`.

## Limits

The entire original upstream test suite was retained, but not rerun as an acceptance suite for the changed edition. It includes assertions about deliberately removed providers. The selected inherited tests and edition suite above are the checks executed for this change. Not every geographic feed, camera region or hardware receiver was exercised live. Availability and coverage still depend on each public source.

The complete upstream application retains a large bundle. Its main JavaScript is approximately 3.24 MB before compression, about 1.02 MB gzip; Vite reports a chunk-size warning. Optional source packages and geographic datasets load separately. This change preserves the full engine rather than claiming a small bundle.

Some retained data permits noncommercial use only. See `earth-edition.md` and `apps/earth/DATA_SOURCES.md`. Source-code permission is separate from data rights.

This shared checkout also contains unrelated workbench changes from another ongoing task. They were left out of this task's commits. There is no configured Git remote, so pushing is unavailable.
