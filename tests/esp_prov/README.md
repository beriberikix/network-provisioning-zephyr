# esp_prov SoftAP end-to-end test

Drives the **real** [`esp_prov`][esp_prov] tool (Espressif's provisioning
client, from `idf-extra-components`) against a `native_sim` build of this module
over a host Ethernet TAP — no hardware. It proves the device's SoftAP/HTTP
transport and manager interoperate with the actual upstream client, and
exercises the failure paths deterministically.

## Pieces

- `dut/` — a `native_sim` app: the real manager + SoftAP transport + the fake
  Wi-Fi backend (`sim/wifi`). The HTTP server binds to all interfaces, so it is
  reachable from the host at `192.0.2.1:80` over the `zeth` TAP. The fake Wi-Fi
  backend runs in credential-matching mode, so esp_prov drives the outcome
  purely through the SSID/passphrase it sends.
- `setup.sh <dir>` — clones esp_prov (pinned) and generates the protobuf Python
  modules it needs with the local `protoc`; prints `export` lines for
  `ESP_PROV` and `IDF_PATH`.
- `run.sh` — brings up `zeth`, launches the DUT, and runs three esp_prov
  scenarios, asserting each: correct credentials → *Provisioning was
  successful*; wrong passphrase → *Incorrect Password*; unknown SSID →
  *Incorrect SSID*.

## Running locally

`run.sh` needs `CAP_NET_ADMIN` to create the TAP. With no root, a user+network
namespace works:

```sh
west build -b native_sim tests/esp_prov/dut
eval "$(tests/esp_prov/setup.sh /tmp/esp_prov_work)"
DUT_EXE="$PWD/build/zephyr/zephyr.exe" PYTHON="$(which python3)" \
  unshare -rn env ESP_PROV="$ESP_PROV" IDF_PATH="$IDF_PATH" \
    DUT_EXE="$DUT_EXE" PYTHON="$PYTHON" \
    tests/esp_prov/run.sh
```

(On Ubuntu 24.04 unprivileged user namespaces may be AppArmor-restricted; the
CI job relaxes `kernel.apparmor_restrict_unprivileged_userns` first.)

CI runs exactly this in the `esp_prov` job.

[esp_prov]: https://github.com/espressif/idf-extra-components/tree/master/network_provisioning/tool/esp_prov
