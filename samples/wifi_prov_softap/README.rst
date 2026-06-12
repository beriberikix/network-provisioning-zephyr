.. _wifi_prov_softap_sample:

Wi-Fi Provisioning over SoftAP
##############################

Overview
********

Hosts an Espressif-compatible provisioning access point. The stock
**ESP SoftAP Provisioning** apps (Android/iOS) — or ``esp_prov.py`` — join the
AP, run the security handshake over HTTP at ``192.168.4.1``, optionally scan
for networks, and hand over Wi-Fi credentials. The device connects as a
station while keeping the AP up (AP/STA concurrent mode) so the app can read
the final status. Credentials persist via ``wifi_credentials``; the reboot
path retries them with backoff and falls back to provisioning mode if the
network stays unreachable (credentials kept — see the BLE sample for the
shared policy).

Requirements
************

* A board with Wi-Fi AP/STA concurrent mode. Validated on
  ``esp32s3_devkitc``.
* One of the Espressif SoftAP provisioning apps, or ``esp_prov.py`` from
  ``idf-extra-components/network_provisioning/tool/esp_prov``.

Building and Running
********************

.. code-block:: console

   west build -b esp32s3_devkitc/esp32s3/procpu \
       network-provisioning-zephyr/samples/wifi_prov_softap
   west flash

Provision with the phone app
============================

1. Open **ESP SoftAP Provisioning** and let it join **PROV_ZEPHYR** (or join
   the AP manually from the Wi-Fi settings).
2. Enter the proof-of-possession **abcd1234**.
3. Choose your Wi-Fi network and enter its password.
4. The app reports success once the device connects.

Provision with esp_prov.py
==========================

Join the ``PROV_ZEPHYR`` AP from your computer first, then:

.. code-block:: console

   python esp_prov.py --transport softap --service_name 192.168.4.1:80 \
       --sec_ver 1 --pop abcd1234 \
       --ssid "<your-ssid>" --passphrase "<your-pass>"

Configuration
*************

Defaults live in ``src/main.c`` and ``prj.conf``:

* ``PROV_SERVICE_NAME`` — AP SSID; keep the ``PROV_`` prefix the apps filter
  on. ``PROV_SERVICE_KEY`` — AP password (8..64 characters → WPA2-PSK) or
  ``NULL`` for an open AP.
* ``CONFIG_HTTP_SERVER_STACK_SIZE`` — must stay at 8192 or larger: the
  security-1 crypto runs in the HTTP server thread via the endpoint handlers.
* ``CONFIG_HEAP_MEM_POOL_SIZE`` — the esp32 Wi-Fi driver allocates from the
  kernel heap and AP+STA mode needs real headroom; with too little, RX
  allocations fail as soon as a station associates.
* ``CONFIG_ZVFS_EVENTFD_MAX=2`` — the DHCPv4 server's socket service and the
  HTTP server each need one eventfd; with the default of 1 the HTTP server
  fails to start and silently restart-loops.
* ``CONFIG_HTTP_SERVER_MAX_CLIENTS=3`` — when the device joins a Wi-Fi
  network on a different channel than the AP, clients connected to the AP
  briefly glitch (AP/STA share one radio). The app's TCP connection dies in
  the shift and its replacement must not be blocked behind the stale socket,
  or the final status polls time out in the app.
