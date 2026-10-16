# Open-source policy

Original project code and scanner rules use Apache-2.0. The only direct Go dependency is Google's Protobuf runtime, BSD-3-Clause. Dependency versions and integrity hashes are pinned in go.mod and go.sum. The source scanner runs offline and has no analytics, API key, subscription or external account requirement. The optional HTTPS checker contacts only the target explicitly submitted for a check.

The frontend uses React, React DOM, scheduler and Zod under MIT licenses. Their complete notices are retained in `licenses/frontend.txt`. Vite and TypeScript build the frontend; package-lock.json pins the dependency graph. No external fonts, hosted telemetry or paid data feeds are required. The browser downloads JavaScript from the local server only.

Keep upstream copyright and license notices with binary/source distributions. `NOTICE` identifies dependencies; the `licenses/` directory preserves their full license text. Generated bindings are checked in, so users need only Go to build the CLI. Python and grpcio-tools are development tools for regenerating the contract, not runtime dependencies.

Do not assume a free hosted tier is open source. Every future scanner, rule pack, dataset and optional service needs a separate license check before integration. Pin engine versions and verify downloaded checksums. Do not use `latest` tags in release builds.

Semgrep's engine is LGPL-2.1, but Semgrep-maintained registry rules have a separate license that restricts certain uses. Those rules are not bundled. Future SAST integration must use original rules or a separately verified open-source rule set. See [Semgrep's licensing explanation](https://semgrep.dev/blog/2024/important-updates-to-semgrep-oss/).

Planned Envoy, WireGuard, OpenTelemetry, OSV, Checkov and other adapters remain unimplemented. Their names in the architecture do not mean they have been bundled or audited. Distribution checks must include transitive dependencies, data licenses, optional components and the obligations of the exact selected versions.

Free software does not make hosting, bandwidth or third-party infrastructure free. The current CLI runs on the user's own computer without paid services.
