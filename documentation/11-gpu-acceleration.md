# GPU acceleration

Earth renders on the computer running the browser. Docker serves JavaScript, map data and provider responses; giving the Earth container a CUDA device does not select the browser GPU.

The Cesium globe, street panoramas, cockpit clouds and model shader compatibility probe request WebGL's `high-performance` power preference. This is a hint, not a guarantee of a particular GPU. WebGL continues to work on other devices when the browser chooses them. Earth keeps its 60 FPS target, idle render governor, hidden-tab suspension and capped cloud framebuffer. The existing drawing-buffer setting is retained for viewport capture compatibility.

## Windows setup

Run from the repository root with PowerShell 7.4 or newer:

```powershell
# Inspect installed Edge and Chrome preferences without changes.
./scripts/configure-gpu.ps1

# Prefer the high-performance GPU for those browsers for the current user.
./scripts/configure-gpu.ps1 -Mode Apply

# Or configure the browser executable used by your installation.
./scripts/configure-gpu.ps1 -Mode Apply -BrowserPath 'C:\path\to\browser.exe'

# Restore the exact preferences saved before the first Apply.
./scripts/configure-gpu.ps1 -Mode Restore
```

Apply supports `-WhatIf`, requires no administrator account and preserves unrelated graphics flags. Its backup stays in ignored `.godseye/gpu-preferences.json`. This preference affects every page in the selected browser, including the security dashboard and browser video/compositing where supported. It can increase battery consumption. It does not disable the integrated GPU or change the system power plan.

Fully exit and reopen the browser after Apply. Enable its graphics acceleration setting. In Windows Settings > System > Display > Graphics, check that High performance selects the NVIDIA RTX 3050. Open Earth > Options > Graphics to see the actual renderer. An NVIDIA/RTX renderer confirms device selection. A masked renderer name does not confirm which GPU was chosen; use the browser GPU diagnostics or Windows Task Manager's GPU engine column. Context preference is the browser's reported hint, not proof of adapter selection. Software rendering produces guidance in Options; a lost context produces a reload message. FPS target is a limit, not a measured frame rate.

Rebuild the served frontend after changing source:

```powershell
docker compose up --build -d --wait earth
```

## Other workloads

| Existing workload | Execution and GPU relevance |
| --- | --- |
| Globe, overlays, panoramas, clouds | WebGL shaders and browser rendering use the selected graphics adapter. |
| Browser video, 2D canvas and dashboard composition | Browser/driver decides acceleration; hardware video decode depends on codec support. |
| Satellite positions, data transforms, source scanning, PCAP/JSON/XML parsing | Current JavaScript/Go/Python CPU implementations have no GPU kernels. |
| HTTPS, DNS, TCP and public feed requests | Network and I/O bound; selecting a GPU does not accelerate remote services. |
| Bounded local digest audit | Computes at most 4,096 supplied candidates on CPU. No Hashcat engine or CUDA implementation is present. |
| Python migration candidate | FastAPI, validation, scanning and reports; no Torch, ONNX or CUDA model inference. |

The reviewed machine has an NVIDIA GeForce RTX 3050 Laptop GPU with 4,096 MiB VRAM and an AMD integrated GPU. A future compute engine must implement and test a GPU backend, select the NVIDIA device through that engine's API, bound VRAM and concurrency, and preserve CPU fallback. Environment variables alone cannot accelerate the existing CPU code. There is no unused CUDA service to configure in this release.

References: [Cesium viewer context options](https://cesium.com/learn/cesiumjs/ref-doc/Viewer.html), [WebGL context attributes](https://developer.mozilla.org/en-US/docs/Web/API/WebGLRenderingContext/getContextAttributes), [Windows graphics preferences](https://support.microsoft.com/en-au/windows/hardware/display-graphics/optimizations-for-windowed-games-in-windows-11).

## Verification on 19 October 2026

- Applied current-user high-performance preferences to installed Edge and Chrome. Tested dry runs, repeated Apply, preserving unrelated flags and registry entries, and exact restoration of both present and absent values.
- The rebuilt Earth container is healthy. A fresh host Chrome process running the production console reported `NVIDIA GeForce RTX 3050 Laptop GPU` through ANGLE Direct3D 11 and `high-performance` context attributes.
- Checked actual globe pixels and Options at 1440 x 1000 and 390 x 844, camera movement, layer selection, and the forced context-loss message. No page errors or failed requests occurred during the check. This verifies device selection and rendering, not a before/after frame-rate improvement or every public feed.
- All 55 focused rendering/lifecycle tests and all 30 free-edition tests passed on the container's Node 26 runtime. The suites overlap on graphics diagnostics. Tests cover integrated and masked renderer identities, software rendering, disabled WebGL and context loss.
- Import-direction checks passed. The package ownership check still fails because `src/app/data.js` imports unowned `src/free/policy.js`; both the import and missing ownership declaration predate this change. The format check reports existing drift in 12 files, including the previously unformatted console shell. The production build retains its large-chunk warning.
