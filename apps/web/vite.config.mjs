// SPDX-License-Identifier: Apache-2.0
import { defineConfig } from "vite";

const backend = "http://127.0.0.1:8765";
const developmentOrigins = new Set(["http://127.0.0.1:5173", "http://localhost:5173"]);

export default defineConfig({
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": {
        target: backend,
        changeOrigin: true,
        configure(proxy) {
          proxy.on("proxyReq", (outgoing, incoming) => {
            // Translate only this development app's origin. Other origins and
            // Sec-Fetch-Site retain the backend's normal rejection behavior.
            if (developmentOrigins.has(incoming.headers.origin)) {
              outgoing.setHeader("Origin", backend);
            }
          });
        },
      },
    },
  },
});
