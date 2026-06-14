# network-provisioning-zephyr

[![CI](https://github.com/beriberikix/network-provisioning-zephyr/actions/workflows/build.yml/badge.svg)](https://github.com/beriberikix/network-provisioning-zephyr/actions/workflows/build.yml)

A Zephyr RTOS port of Espressif's
[network provisioning](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/provisioning/provisioning.html)
protocol for **Wi-Fi over Bluetooth LE, SoftAP or the device console**.

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

> Scope: Wi-Fi only (Thread is intentionally out of scope), BLE, SoftAP and
> console transports, security schemes **0** (plaintext) and **1**
> (Curve25519 + AES-256-CTR + proof-of-possession). Security 2 (SRP6a) is not
> implemented.

## How it maps to ESP-IDF

| ESP-IDF building block            | Zephyr-native replacement                                  |
| --------------------------------- | ---------------------------------------------------------- |
| protocomm BLE transport (GATT)    | Zephyr Bluetooth GATT (`BT_GATT_DYNAMIC_DB`)               |
| protocomm HTTP transport (httpd)  | Zephyr HTTP server (`CONFIG_HTTP_SERVER`)                  |
| protocomm console transport       | Zephyr shell command (`CONFIG_SHELL`)                      |
| SoftAP + DHCP (esp_netif)         | `net_mgmt` AP mode + `CONFIG_NET_DHCPV4_SERVER`            |
| protobuf (protobuf-c)             | nanopb (`CONFIG_NANOPB`)                                    |
| security1 crypto (mbedTLS)        | PSA Crypto: X25519 ECDH, AES-256-CTR, SHA-256              |
| Wi-Fi credentials in NVS          | `wifi_credentials` subsystem (settings backend)            |
| `esp_wifi` connect/scan           | `net_mgmt` (`NET_REQUEST_WIFI_CONNECT` / `_SCAN`)          |
| `wifi_prov_mgr_*` API             | `network_prov_mgr_*` API (`network_provisioning/...`)      |
| `network_prov_scheme_*` objects   | `network_prov_scheme_ble/softap/console` (`scheme_*.h`)    |

## Architecture

The manager is transport-agnostic: it drives a `struct network_prov_scheme`
vtable (`start`/`stop`) and never knows which transport is underneath. The
transport feeds bytes to the protocomm core, which dispatches to endpoint
handlers after the security layer has decrypted the request.

```
                    application
                        │  network_prov_mgr_* (include/network_provisioning/network_prov_mgr.h)
                        ▼
              ┌───────────────────────┐   lifecycle events
              │  manager / state machine │ ─────────────────► app event callback
              │  (network_prov_mgr.c)    │
              └───────────┬───────────────┘
                          │  struct network_prov_scheme vtable (start / stop)
              ┌───────────▼───────────────────────────────────┐
              │  transport scheme                               │
              │   BLE (GATT)  │  SoftAP (HTTP)  │  console (shell)│
              └───────────┬───────────────────────────────────┘
                          │  protocomm endpoints (proto-ver, prov-session, prov-config, …)
              ┌───────────▼───────────┐
              │  protocomm core         │ ── security 0 / 1 (handshake + encrypt/decrypt)
              │  (endpoint dispatch)    │
              └───────────┬───────────┘
                          │  endpoint handlers
              ┌───────────▼───────────────────────────┐
              │  Wi-Fi handlers: config / scan / ctrl   │
              └───────────┬───────────────────────────┘
                          │  net_mgmt  +  wifi_credentials
                          ▼
                Zephyr Wi-Fi  (or the fake_wifi backend under test)
```

Adding a transport means implementing one `network_prov_scheme` object; adding a
device-specific feature means registering a [custom endpoint](#public-api). The
protocol core and Wi-Fi handlers stay untouched in both cases.

## Protocol surface

Over BLE, each protocomm endpoint is exposed as one GATT characteristic; the
endpoint name is carried in the characteristic's `0x2901` (Characteristic User
Description) descriptor, which is how the apps map names to characteristics.
Over SoftAP, each endpoint is an HTTP POST URI (`/proto-ver`, `/prov-session`,
…) served on the device-hosted access point at `192.168.4.1:80`, with the
session tracked by a `session=<id>` cookie. Over the console
(`CONFIG_NETWORK_PROV_CONSOLE`), the same endpoints are reached through a single
shell command — `net_prov <endpoint> <session_id> <hex-request>` — which prints
the response as lowercase hex; this is the transport `esp_prov --transport
console` speaks, useful for bring-up and debugging without BLE or a Wi-Fi AP.

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
are trimmed for scope but Wi-Fi/sec0/sec1 field numbers are unchanged. See
[`proto/README.md`](proto/README.md) for the endpoint ↔ message map and the
nanopb `.options` conventions.

## Repository layout

```
proto/        protobuf definitions (+ nanopb .options) — verbatim wire format
include/      public API (network_provisioning/network_prov_mgr.h)
src/          protocomm core, BLE + SoftAP transports, security 0/1, Wi-Fi handlers, manager
samples/      wifi_prov_ble and wifi_prov_softap — the reference applications
sim/          test-only fake Wi-Fi backend for headless simulation (native_sim/bsim)
tests/        native_sim ztest suites + a BabbleSim BLE end-to-end test (tests/bsim)
zephyr/       module.yml (consumable as a Zephyr module)
west.yml      standalone west manifest (pins the current stable Zephyr release)
```

## Public API

```c
#include <network_provisioning/network_prov_mgr.h>
#include <network_provisioning/scheme_ble.h>     /* or scheme_softap.h / scheme_console.h */

/* Pick the transport with a scheme object in the init config, e.g.
 * config.scheme = &network_prov_scheme_ble; (or _softap / _console).
 */
network_prov_mgr_init(config);                 /* load settings + credential store */
network_prov_mgr_is_provisioned(&provisioned); /* !wifi_credentials_is_empty()      */
/* BLE: service_key unused (NULL). SoftAP: service_key = AP password (or NULL
 * for an open AP).
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

Additional upstream-parity manager APIs:

```c
/* Advertise an app section in proto-ver (ver + extra capabilities). */
network_prov_mgr_set_app_info("myapp", "1.0", caps, ARRAY_SIZE(caps));

/* By default the service auto-stops a grace period after success
 * (CONFIG_NETWORK_PROV_AUTOSTOP_TIMEOUT_MS); opt out to manage teardown yourself. */
network_prov_mgr_disable_auto_stop(0);
network_prov_mgr_is_sm_idle();                  /* no session active */

/* Programmatic (headless) provisioning + post-failure / re-provision resets. */
network_prov_mgr_configure_wifi_sta("ssid", "passphrase");
network_prov_mgr_reset_wifi_sm_state_on_failure();
network_prov_mgr_reset_wifi_sm_state_for_reprovision();

/* Application-defined custom endpoints: create before start (so the transport
 * advertises them — a BLE characteristic / HTTP route / console endpoint),
 * register the handler after start (e.g. from the NETWORK_PROV_START event).
 * Reachable over all transports; up to CONFIG_NETWORK_PROV_MAX_CUSTOM_ENDPOINTS. */
network_prov_mgr_endpoint_create("custom-data");
network_prov_mgr_endpoint_register("custom-data", my_handler, my_ctx);
network_prov_mgr_endpoint_unregister("custom-data");
```

For the BLE transport, `<network_provisioning/scheme_ble.h>` adds
`network_prov_scheme_ble_set_service_uuid()` and
`network_prov_scheme_ble_set_mfg_data()` (call before `start_provisioning`) to
override the 128-bit GATT service UUID and add manufacturer data to the scan
response, e.g. for app-side device matching.

### Console transport

With `CONFIG_NETWORK_PROV_CONSOLE=y` (which needs `CONFIG_SHELL`) and
`.scheme = &network_prov_scheme_console`, the protocol is carried over the device
console by a single shell command:

```
net_prov <endpoint> <session_id> <hex-request>
```

It decodes the hex request, dispatches it to the named protocomm endpoint and
prints the response as lowercase hex. The `session_id` mirrors the per-session
reset of the other transports — changing it opens a fresh protocomm session
(resetting the security handshake), as a BLE reconnect or a new HTTP cookie
does. `service_name`/`service_key` are unused for this scheme.

`esp_prov`'s console transport is human-in-the-loop: drive it with

```sh
esp_prov.py --transport console --sec_ver 1 --pop abcd1234 \
            --ssid HomeNet --passphrase correct-horse-battery
```

and for each `Client->Device msg : <endpoint> <session_id> <hex>` line it prints,
run `net_prov <endpoint> <session_id> <hex>` on the device console and paste the
device's hex response back into `esp_prov`.

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
including a full client-side security-1 handshake), an integration suite for
the HTTP transport (a loopback HTTP client exercising URI routing and the
cookie session semantics), an integration suite for the console transport (the
full manager with the console scheme driven over the dummy shell
backend — proto-ver, the sec1 handshake and an encrypted GetWifiStatus) and a
unit test for the simulated Wi-Fi backend run on `native_sim`:

```sh
west twister -T network-provisioning-zephyr/tests -p native_sim --inline-logs
```

See [`tests/README.md`](tests/README.md) for a per-suite breakdown and how to run
each layer (native_sim, BabbleSim, esp_prov) individually.

A **BabbleSim end-to-end test** (`tests/bsim/ble_e2e`) exercises the BLE
transport and the whole manager headlessly: a Zephyr "tester" central drives a
full provisioning flow (sec1 handshake, scan, config, status) over a simulated
radio against the device, which runs the real manager backed by a fake Wi-Fi
driver ([`sim/wifi`](sim/wifi)). Both a successful provisioning and a
wrong-password failure injection are checked. With [BabbleSim][bsim] built
(`BSIM_OUT_PATH`/`BSIM_COMPONENTS_PATH` set):

```sh
BOARD=nrf52_bsim/native network-provisioning-zephyr/tests/bsim/compile.sh
network-provisioning-zephyr/tests/bsim/ble_e2e/test_scripts/provision_success.sh
network-provisioning-zephyr/tests/bsim/ble_e2e/test_scripts/provision_wrong_password.sh
```

[bsim]: https://babblesim.github.io/

An **esp_prov SoftAP end-to-end test** ([`tests/esp_prov`](tests/esp_prov))
drives Espressif's real `esp_prov` client against a `native_sim` build over a
host Ethernet TAP, asserting the success, wrong-password and unknown-SSID
outcomes — verifying interoperability with the actual upstream tool, not just an
in-tree client. See its [README](tests/esp_prov/README.md) to run it locally.

CI runs all of the above — the `native_sim` suites, the BabbleSim BLE
end-to-end test, the esp_prov SoftAP end-to-end test, and `esp32s3_devkitc` and
`esp32c3_devkitm` builds of both samples — against the Zephyr release pinned in
[`west.yml`](west.yml) on every push and pull request; moving to a newer stable
release is a one-line bump of that pin.

## Using it as a module in an existing workspace

Add this repo to your `west.yml` and enable `CONFIG_NETWORK_PROV_MGR=y` plus
at least one transport: `CONFIG_NETWORK_PROV_BLE=y`, `CONFIG_NETWORK_PROV_SOFTAP=y`
and/or `CONFIG_NETWORK_PROV_CONSOLE=y`. The required Zephyr subsystems (`WIFI`,
`MBEDTLS`, `NANOPB`, `WIFI_CREDENTIALS`, `SETTINGS`, and per transport
`BT_PERIPHERAL` + a large ATT MTU, `HTTP_SERVER` + `NET_DHCPV4_SERVER`, or
`SHELL`) are
set up in the samples' `prj.conf` files — copy the relevant lines from
[`wifi_prov_ble`](samples/wifi_prov_ble/prj.conf) or
[`wifi_prov_softap`](samples/wifi_prov_softap/prj.conf).

> **Important:** `CONFIG_BT_RX_STACK_SIZE=4096` (or larger) is required. The
> security-1 session setup and handshake run PSA crypto on the Bluetooth host
> RX thread via the GATT callbacks; Zephyr's default 1.2 kB RX stack silently
> overflows there and wedges the BLE controller as soon as a central connects.

## Troubleshooting

Most field issues are subsystem sizing, not protocol bugs. The samples'
`prj.conf` files carry the working values; the common symptoms:

| Symptom | Cause / fix |
| ------- | ----------- |
| BLE controller wedges, or no response once the app connects (security 1) | `CONFIG_BT_RX_STACK_SIZE` too small. The sec1 handshake runs PSA crypto on the Bluetooth host RX thread; the default 1.2 kB stack overflows. Set **≥ 4096**. |
| SoftAP app reports **"Null input buffer"** | `CONFIG_ZVFS_POLL_MAX` too small. The HTTP server polls `1 eventfd + 1 listener + MAX_CLIENTS` sockets at once; a too-small budget fails `zsock_poll()` with `ENOMEM` and the extra client gets an empty body. Set **≥ `2 + CONFIG_HTTP_SERVER_MAX_CLIENTS`**. |
| SoftAP HTTP server never starts / silently restart-loops | `CONFIG_ZVFS_EVENTFD_MAX` too small. The DHCPv4 server and the HTTP server each need one eventfd. Set **≥ 2**. |
| Wi-Fi RX allocations fail as soon as a station associates (SoftAP) | `CONFIG_HEAP_MEM_POOL_SIZE` too small for AP+STA concurrent mode (the esp32 driver allocates from the kernel heap). Give it real headroom. |
| App reports failure even though Wi-Fi connected | The service was torn down before the app read the final status. Keep it up for the auto-stop grace window (`CONFIG_NETWORK_PROV_AUTOSTOP_TIMEOUT_MS`), or manage teardown via `network_prov_mgr_disable_auto_stop()`. |
| Device boots straight to connected and never advertises | Expected once credentials are stored — it reconnects instead of provisioning. To force provisioning again, erase them with `network_prov_mgr_reset_wifi_provisioning()` (e.g. from a factory-reset button). |

A failed connection **never** erases stored credentials automatically; only an
explicit `network_prov_mgr_reset_wifi_provisioning()` does.

## License

Apache-2.0. The `proto/` files originate from Espressif's ESP-IDF and
`idf-extra-components` (also Apache-2.0).
