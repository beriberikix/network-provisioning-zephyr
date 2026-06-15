# Protocol definitions (`proto/`)

These `.proto` files define the **protocomm wire format** the device speaks with
the stock Espressif provisioning apps and `esp_prov`. They are taken **verbatim**
from ESP-IDF's protocomm component and the `idf-extra-components`
`network_provisioning` component, so field numbering — and therefore the
on-the-wire encoding — is identical to upstream. Do not renumber fields: a change
here silently breaks interoperability with the apps.

Messages are encoded with [nanopb](https://jpa.kapsi.fi/nanopb/) (`CONFIG_NANOPB`)
rather than ESP-IDF's `protobuf-c`; the generated `*.pb.c`/`*.pb.h` are built from
these files at compile time.

## Scope

Wi-Fi **and** Thread provisioning (selected per build via
`CONFIG_NETWORK_PROV_NETWORK_TYPE`, mutually exclusive like upstream). The Thread
config/ctrl/scan messages are all wired to OpenThread (scan via
`otThreadDiscover`). `sec2.proto` (SRP6a, security scheme 2) is intentionally
omitted — this port implements
security schemes **0** (plaintext) and **1** (Curve25519 + AES-256-CTR +
optional proof-of-possession). All field numbers are unchanged from upstream, so
the wire format stays compatible.

## File ↔ endpoint map

Each protocomm endpoint (a BLE GATT characteristic, an HTTP POST URI, or a
console sub-command — see the top-level [README](../README.md#protocol-surface))
carries one top-level message:

| Endpoint       | Message (file)                          | Purpose                                              |
| -------------- | --------------------------------------- | ---------------------------------------------------- |
| `proto-ver`    | JSON (not protobuf)                     | Version / capabilities (`sec_ver`, `wifi_scan`, …)   |
| `prov-session` | `SessionData` (`session.proto`)         | Security handshake; wraps `Sec0Payload`/`Sec1Payload`|
| `prov-scan`    | `NetworkScanPayload` (`network_scan.proto`)   | Wi-Fi scan request / AP list                   |
| `prov-config`  | `NetworkConfigPayload` (`network_config.proto`) | Set/apply credentials, report status         |
| `prov-ctrl`    | `NetworkCtrlPayload` (`network_ctrl.proto`)     | Reset state machine / re-provision           |

Supporting definitions:

| File                     | Defines                                                              |
| ------------------------ | ------------------------------------------------------------------- |
| `session.proto`          | `SessionData`, `SecSchemeVersion` (the security-handshake envelope) |
| `sec0.proto`             | `Sec0Payload` — trivial command/response, no crypto                 |
| `sec1.proto`             | `Sec1Payload` — Cmd0/Resp0 (ECDH) + Cmd1/Resp1 (PoP verify)         |
| `constants.proto`        | `Status` (shared result codes)                                      |
| `network_constants.proto`| `WifiStationState`, `WifiAuthMode`, `WifiConnectedState`, …         |

## `.options` files

The `*.options` files are nanopb field options that bound otherwise-unbounded
`bytes`/`string` fields to fixed-size C arrays (no heap, deterministic stack
usage). For example `network_config.options` caps SSID/passphrase lengths and
`sec1.options` caps the public-key and verify-data byte fields. When editing a
`.proto`, keep its `.options` in sync so the generated struct stays statically
sized.

## Regenerating

The generated sources are produced by the nanopb integration during the build;
there is nothing to commit. `protoc` (with the nanopb plugin) is only needed for
the host-side `esp_prov` test — see [`../tests/esp_prov/README.md`](../tests/esp_prov/README.md).
