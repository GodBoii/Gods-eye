import { defineConfig } from 'vite';
import { createBrowserViteConfig } from './build/vite.js';
import { freeEditionGateway } from './server/free-providers.js';
import { celestrakProxy, rocketLaunchesProxy } from './server/providers/space.js';
import { terrainHeightsProxy } from './server/providers/terrain.js';
import { adsbdbProxy } from './server/providers/aircraft/enrichment.js';
import { overpassProxy } from './server/providers/overpass.js';
import { militaryInstallationsProxy } from './server/providers/military-installations.js';
import { regionalBriefProxy } from './server/providers/regional/briefing.js';
import { geocodeProxy } from './server/providers/regional/place.js';
import { weatherEffectsProxy } from './server/providers/regional/weather-effects.js';
import { cctvProxy } from './server/providers/cctv.js';
import { defaultSourceRoot } from './server/providers/common/source-root.js';
import { radioBrowserProxy } from './server/providers/radio.js';
import { gbfsProxy } from './server/providers/gbfs.js';
import { localReceiversProxy } from './server/providers/local-receivers.js';
import { transitProxy } from './server/providers/transit.js';
import { adsbLolProxy } from './server/providers/aircraft/adsb-lol.js';
import { weatherProxy } from './server/providers/weather.js';
import { firePerimetersProxy } from './server/providers/firePerimeters.js';
import { naturalEventsProxy } from './server/providers/naturalEvents.js';
import { gnssIntegrityProxy } from './server/providers/gnssIntegrity.js';
import { cycloneProxy } from './server/providers/cyclones.js';
import { windProxy } from './server/providers/wind.js';
import { apiNotFoundPlugin } from './server/standalone/api-not-found.js';
import { installRouteMiddleware } from './server/providers/places/routes.js';
import { clearProviderCredentials } from './src/free/policy.js';

const freeRouting = () => ({ name: 'keyless-osrm-routing',
  configureServer(server) { installRouteMiddleware(server.middlewares); },
  configurePreviewServer(server) { installRouteMiddleware(server.middlewares); },
});

// No dotenv loading, credential setup endpoint, paid proxy, or MCP server.
export default defineConfig(({ command }) => {
  clearProviderCredentials(process.env);
  const config = createBrowserViteConfig({ command, host: '127.0.0.1', port: 4173,
    googleApiKey: '', cesiumToken: '', mapillaryToken: '',
    plugins: [freeEditionGateway(), celestrakProxy(), rocketLaunchesProxy(), terrainHeightsProxy(), adsbdbProxy(),
      overpassProxy(), militaryInstallationsProxy(), regionalBriefProxy(), geocodeProxy(), weatherEffectsProxy(),
      cctvProxy({ sourceRoot: defaultSourceRoot }), radioBrowserProxy(), gbfsProxy(), localReceiversProxy(),
      transitProxy(), adsbLolProxy(), windProxy(), weatherProxy(), cycloneProxy(), firePerimetersProxy(), naturalEventsProxy(), gnssIntegrityProxy(), freeRouting(), apiNotFoundPlugin()],
  });
  config.envDir = false;
  config.server.strictPort = true;
  config.preview = { ...config.preview, host: '127.0.0.1', port: 4173, strictPort: true };
  return config;
});
