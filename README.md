# network-provisioning-zephyr

[![CI](https://github.com/beriberikix/network-provisioning-zephyr/actions/workflows/build.yml/badge.svg)](https://github.com/beriberikix/network-provisioning-zephyr/actions/workflows/build.yml)

A Zephyr RTOS port of Espressif's
[network provisioning](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/provisioning/provisioning.html)
protocol for **Wi-Fi over Bluetooth LE or SoftAP**.

It speaks the same protocomm wire protocol as ESP-IDF, so the **stock Espressif
provisioning apps work out of the box** — no app changes, no custom client:

- [ESP BLE Provisioning — Android](https://github.com/espressif/esp-idf-provisioning-android)
  ([Play Store](https://play.google.com/store/apps/details?id=com.espressif.provble))
- [ESP BLE Provisioning — iOS](https://github.com/espressif/esp-idf-provisioning-ios)
  ([App Store](https://apps.apple.com/app/esp-ble-provisioning/id1473590141))
- [ESP SoftAP Provisioning — Android](https://play.google.com/store/apps/details?id=com.espressif.provsoftap)
  / [iOS](https://apps.apple.com/app/esp-softap-provisioning/id1474040630)

Wi-Fi credentials are stored through Zephyr's **native `wifi_credentials`
subsystem**, and the connection is driven through the standard `net_mgmt` Wi-Fi
management API.

> Scope: Wi-Fi only (Thread is intentionally out of scope), BLE and SoftAP
> transports, security schemes **0** (plaintext) and **1**
> (Curve25519 + AES-256-CTR + proof-of-possession). Security 2 (SRP6a) is not
> implemented.

## How it maps to ESP-IDF

| ESP-IDF building block            | Zephyr-native replacement                                  |
| --------------------------------- | ---------------------------------------------------------- |
| protocomm BLE transport (GATT)    | Zephyr Bluetooth GATT (`BT_GATT_DYNAMIC_DB`)               |
| protocomm HTTP transport (httpd)  | Zephyr HTTP server (`CONFIG_HTTP_SERVER`)                  |
| SoftAP + DHCP (esp_netif)         | `net_mgmt` AP mode + `CONFIG_NET_DHCPV4_SERVER`            |
| protobuf (protobuf-c)             | nanopb (`CONFIG_NANOPB`)                                    |
| security1 crypto (mbedTLS)        | PSA Crypto: X25519 ECDH, AES-256-CTR, SHA-256              |
| Wi-Fi credentials in NVS          | `wifi_credentials` subsystem (settings backend)            |
| `esp_wifi` connect/scan           | `net_mgmt` (`NET_REQUEST_WIFI_CONNECT` / `_SCAN`)          |
| `wifi_prov_mgr_*` API             | `network_prov_mgr_*` API (`network_provisioning/...`)      |

## Protocol surface

Over BLE, each protocomm endpoint is exposed as one GATT characteristic; the
endpoint name is carried in the characteristic's `0x2901` (Characteristic User
Description) descriptor, which is how the apps map names to characteristics.
Over SoftAP, each endpoint is an HTTP POST URI (`/proto-ver`, `/prov-session`,
…) served on the device-hosted access point at `192.168.4.1:80`, with the
session tracked by a `session=<id>` cookie.

| Endpoint       | Purpose                                                        |
| -------------- | -------------------------------------------------------------- |
| `proto-ver`    | Version / capabilities JSON (`sec_ver`, `wifi_scan`, `no_pop`) |
| `prov-session` | Security handshake (`SessionData` / sec0 / sec1)               |
| `prov-scan`    | Wi-Fi scan (`NetworkScanPayload`)                              |
| `prov-config`  | Set/apply credentials, report status (`NetworkConfigPayload`)  |
| `prov-ctrl`    | Wi-Fi state reset / re-provision (`NetworkCtrlPayload`)        |

A scan started with `blocking = true` (what the apps send) withholds its
response until the scan completes, matching ESP-IDF; the apps query the scan
status only once.

The `.proto` files under [`proto/`](proto/) are taken verbatim from ESP-IDF
(protocomm) and the `network_provisioning` component, so field numbering — and
therefore the wire format — is identical. `sec2.proto` and the Thread messages
are trimmed for scope but Wi-Fi/sec0/sec1 field numbers are unchanged.

## Repository layout

```
proto/        protobuf definitions (+ nanopb .options) — verbatim wire format
include/      public API (network_provisioning/network_prov_mgr.h)
src/          protocomm core, BLE + SoftAP transports, security 0/1, Wi-Fi handlers, manager
samples/      wifi_prov_ble and wifi_prov_softap — the reference applications
tests/        ztest suites for the protocol core + HTTP transport (run on native_sim)
zephyr/       module.yml (consumable as a Zephyr module)
west.yml      standalone west manifest (pins the current stable Zephyr release)
```

## Public API

```c
#include <network_provisioning/network_prov_mgr.h>

network_prov_mgr_init(config);                 /* load settings + credential store */
network_prov_mgr_is_provisioned(&provisioned); /* !wifi_credentials_is_empty()      */
/* BLE: service_key unused (NULL). SoftAP: service_key = AP password (or NULL
 * for an open AP); select the transport with .scheme in the init config.
 */
network_prov_mgr_start_provisioning(NETWORK_PROV_SECURITY_1, "abcd1234",
                                    "PROV_1234", NULL);
network_prov_mgr_wait();                        /* blocks until connected            */
network_prov_mgr_stop_provisioning();
network_prov_mgr_reset_wifi_provisioning();     /* explicit factory reset: erase creds */
```

Lifecycle events (`NETWORK_PROV_START`, `CRED_RECV`, `CRED_FAIL`, `CRED_SUCCESS`,
`END`, …) are delivered to the callback registered in `network_prov_mgr_config`.
Setting `.wifi_conn_attempts` in the config retries transient connect failures
during provisioning before reporting failure — while retrying, status polls
answer `Connecting` with the attempts remaining (`WifiAttemptFailed`), matching
upstream's `wifi_conn_attempts` behavior. `0` keeps single-attempt semantics.

## Quick start

```sh
# Standalone workspace
west init -m https://github.com/beriberikix/network-provisioning-zephyr wsp
cd wsp && west update

# Build & flash the sample (ESP32-S3 has native Wi-Fi + BLE coexistence)
west build -b esp32s3_devkitc/esp32s3/procpu \
    network-provisioning-zephyr/samples/wifi_prov_ble
west flash
```

Then open the ESP BLE Provisioning app, scan for **`PROV_ZEPHYR`**, enter the
proof-of-possession **`abcd1234`**, pick your Wi-Fi network and submit. The
device connects, persists the credentials, and reconnects automatically on the
next boot.

See [`samples/wifi_prov_ble/README.rst`](samples/wifi_prov_ble/README.rst) for
details, the `esp_prov.py` flow, and configuration knobs.

For SoftAP provisioning, build
[`samples/wifi_prov_softap`](samples/wifi_prov_softap/README.rst) instead: the
device hosts a `PROV_ZEPHYR` access point; join it with the phone and run the
ESP SoftAP Provisioning app (or `esp_prov.py --transport softap`).

## Running the tests

Unit tests for the protocol core (protocomm engine, security schemes 0/1 —
including a full client-side security-1 handshake) and an integration suite
for the HTTP transport (a loopback HTTP client exercising URI routing and the
cookie session semantics) run on `native_sim`:

```sh
west twister -T network-provisioning-zephyr/tests -p native_sim --inline-logs
```

CI runs the same suites plus `esp32s3_devkitc` and `esp32c3_devkitm` builds of
both samples against the Zephyr release pinned in [`west.yml`](west.yml) on
every push and pull request; moving to a newer stable release is a one-line
bump of that pin.

## Using it as a module in an existing workspace

Add this repo to your `west.yml` and enable `CONFIG_NETWORK_PROV_MGR=y` plus
at least one transport: `CONFIG_NETWORK_PROV_BLE=y` and/or
`CONFIG_NETWORK_PROV_SOFTAP=y`. The required Zephyr subsystems (`WIFI`,
`MBEDTLS`, `NANOPB`, `WIFI_CREDENTIALS`, `SETTINGS`, and per transport
`BT_PERIPHERAL` + a large ATT MTU or `HTTP_SERVER` + `NET_DHCPV4_SERVER`) are
set up in the samples' `prj.conf` files — copy the relevant lines from
[`wifi_prov_ble`](samples/wifi_prov_ble/prj.conf) or
[`wifi_prov_softap`](samples/wifi_prov_softap/prj.conf).

> **Important:** `CONFIG_BT_RX_STACK_SIZE=4096` (or larger) is required. The
> security-1 session setup and handshake run PSA crypto on the Bluetooth host
> RX thread via the GATT callbacks; Zephyr's default 1.2 kB RX stack silently
> overflows there and wedges the BLE controller as soon as a central connects.

## License

Apache-2.0. The `proto/` files originate from Espressif's ESP-IDF and
`idf-extra-components` (also Apache-2.0).
