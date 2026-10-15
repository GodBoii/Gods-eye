# God's Eye

Architecture and versioned contracts for a defensive security auditing, runtime debugging, and private networking platform.

This repository contains the Step 1 design requested in the supplied brief. It does not yet contain running scanners, a dashboard, proxy configuration, or a VPN deployment. Performance numbers are proposed acceptance targets, not measurements.

- [Architecture, stack, complete planned tree, and rollout](docs/architecture.md)
- [Plugin registration, execution, validation, and SARIF mapping](docs/plugin-protocol.md)
- [Exact Protobuf contracts and gRPC plugin interface](api/godseye/v1/plugin.proto)

The design separates live network traffic from scan execution. Go manages jobs and results; Envoy handles proxy connections; WireGuard handles VPN packets. Existing scanners supply analysis through adapters. No custom tunnel cryptography is proposed.

Privacy reduces exposure to specific observers. A VPN, proxy, or Tor cannot guarantee anonymity to everyone. The architecture records the remaining exposures and keeps diagnostic collection separate from ordinary private networking.

The `.proto` file is the canonical contract. Its standard Protobuf JSON encoding is the internal JSON representation. Generated language bindings belong in `gen/` when implementation starts.

Validation on 2026-10-16: the complete contract compiled successfully to a descriptor set with `grpcio-tools` 1.84.0, including the standard Timestamp and Duration imports. This verifies Protobuf syntax and references; runtime validation, network behavior and performance remain implementation work.
