# Tests

The suite is layered: fast `native_sim` unit/integration tests for the protocol
core and each transport, a BabbleSim end-to-end test for the real BLE stack, and
a host-driven end-to-end test against Espressif's actual `esp_prov` client.

All of them run without hardware. CI runs every suite on each push and pull
request (see [`.github/workflows/build.yml`](../.github/workflows/build.yml)).

## native_sim suites (ztest)

| Suite (`tests/<dir>`) | What it verifies                                                                                          |
| --------------------- | --------------------------------------------------------------------------------------------------------- |
| `protocomm`           | Core engine: endpoint registry, request dispatch, version endpoint, security gating, a full sec0 session, and a malformed-frame rejection. |
| `security1`           | Security scheme 1 end to end: Curve25519 ECDH + AES-256-CTR keystream, proof-of-possession verify, session reset / re-handshake, malformed-handshake rejection. |
| `protocomm_http`      | SoftAP/HTTP transport over loopback: `session=` cookie semantics, per-request vs keep-alive connections, concurrent clients (server poll budget). |
| `console`             | Console (shell) transport: hex request/response over the dummy shell backend, sec1 handshake + encrypted `GetWifiStatus`, per-`session_id` reset. |
| `fake_wifi`           | The test-only fake Wi-Fi backend ([`sim/wifi`](../sim/wifi)): canned scan results, connect outcomes, error injection, and credential-matching mode. |
| `manager_api`         | The public manager C-API on the real manager + SoftAP + fake Wi-Fi: auto-stop / `is_sm_idle`, `configure_wifi_sta`, state-reset wrappers, custom endpoints, `is_provisioned`/`reset_wifi_provisioning`, remaining-attempts counter, and blocking `wait()`. |

Run them all:

```sh
west twister -T network-provisioning-zephyr/tests -p native_sim --inline-logs
```

Run one suite, e.g.:

```sh
west twister -T network-provisioning-zephyr/tests/manager_api -p native_sim --inline-logs
```

`security1`, `protocomm_http`, `console` and `manager_api` reuse the shared
client-side security-1 implementation in
[`tests/common/prov_client.c`](common/prov_client.c) — the inverse of
`src/security1.c`, doing what `esp_prov`'s security1 client does — so each
transport is exercised with one real handshake/encryption implementation.

## Thread config build (`tests/thread_config`)

A compile/link integration check for the Thread network type
(`CONFIG_NETWORK_PROV_NETWORK_TYPE_THREAD`): the real manager + the Thread
prov-config handler driven through OpenThread (`otDatasetSetActiveTlvs` and the
Set → Apply → GetStatus path). OpenThread needs a real 802.15.4 radio, which
`native_sim` lacks, so this is **build_only on `nrf52840dk/nrf52840`**; a full
BabbleSim attach E2E (à la `ble_e2e`) is a follow-up.

```sh
west twister -T network-provisioning-zephyr/tests/thread_config \
    -p nrf52840dk/nrf52840 --build-only
```

## BabbleSim BLE end-to-end (`tests/bsim/ble_e2e`)

A two-device simulation over a virtual radio: a Zephyr "tester" central drives a
full provisioning flow (sec1 handshake, scan, config, status) against a device
running the **real manager** backed by the fake Wi-Fi driver. Both a successful
provisioning and a wrong-password failure injection are checked. Requires
[BabbleSim](https://babblesim.github.io/) with `BSIM_OUT_PATH` /
`BSIM_COMPONENTS_PATH` set:

```sh
BOARD=nrf52_bsim/native network-provisioning-zephyr/tests/bsim/compile.sh
network-provisioning-zephyr/tests/bsim/ble_e2e/test_scripts/provision_success.sh
network-provisioning-zephyr/tests/bsim/ble_e2e/test_scripts/provision_wrong_password.sh
```

## esp_prov SoftAP end-to-end (`tests/esp_prov`)

Drives Espressif's real `esp_prov` client against a `native_sim` SoftAP build
over a host Ethernet TAP, asserting the success, wrong-password and unknown-SSID
outcomes — interoperability with the actual upstream tool, not just an in-tree
client. It needs host privileges for the TAP device; see
[`esp_prov/README.md`](esp_prov/README.md) to run it locally.

## Shared fixtures

- [`tests/common/prov_client.{c,h}`](common/) — reusable security-1 client used
  across the transport suites and the BLE E2E test.
- [`sim/wifi`](../sim/wifi) (`CONFIG_NETWORK_PROV_FAKE_WIFI`) — the fake Wi-Fi
  backend; its control API is
  [`include/network_provisioning/test/fake_wifi.h`](../include/network_provisioning/test/fake_wifi.h).
