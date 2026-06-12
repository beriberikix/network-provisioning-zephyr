.. _wifi_prov_ble_sample:

Wi-Fi Provisioning over BLE
###########################

Overview
********

Advertises an Espressif-compatible BLE provisioning peripheral. The stock
**ESP BLE Provisioning** apps (Android/iOS) connect to it, run the security
handshake, optionally scan for access points, and hand over Wi-Fi credentials.
Credentials are persisted via the native ``wifi_credentials`` subsystem, so on
the next boot the device reconnects automatically instead of advertising.

Requirements
************

* A board with both Wi-Fi and Bluetooth LE. The sample is validated on
  ``esp32s3_devkitc`` (Wi-Fi + BLE coexistence). Other ESP32-family devkits
  work too; the original esp32 is RAM-tight for the full Wi-Fi + BLE + mbedTLS
  image, so enable PSRAM there.
* One of the Espressif provisioning apps, or the ``esp_prov.py`` CLI from
  ``idf-extra-components/network_provisioning/tool/esp_prov``.

Building and Running
********************

.. code-block:: console

   west build -b esp32s3_devkitc/esp32s3/procpu \
       network-provisioning-zephyr/samples/wifi_prov_ble
   west flash

Provision with the phone app
============================

1. Open **ESP BLE Provisioning**.
2. Scan and select **PROV_ZEPHYR**.
3. Enter the proof-of-possession **abcd1234**.
4. Choose your Wi-Fi network and enter its password.
5. The app reports success once the device connects.

Provision with esp_prov.py
==========================

.. code-block:: console

   python esp_prov.py --transport ble --service_name PROV_ZEPHYR \
       --sec_ver 1 --pop abcd1234 \
       --ssid "<your-ssid>" --passphrase "<your-pass>"

Configuration
*************

Defaults live in ``src/main.c`` and ``prj.conf``:

* ``PROV_POP`` — proof-of-possession string. Set it to ``""`` to advertise the
  ``no_pop`` capability (security 1 without a PoP).
* ``CONFIG_BT_DEVICE_NAME`` — advertised name; keep the ``PROV_`` prefix the
  apps filter on.
* Security scheme — ``main.c`` uses ``NETWORK_PROV_SECURITY_1``. Pass
  ``NETWORK_PROV_SECURITY_0`` (and ``--sec_ver 0`` in the app/CLI) for an
  unencrypted bring-up session.
* ``CONFIG_BT_RX_STACK_SIZE`` — must stay at 4096 or larger: the security-1
  crypto runs on the Bluetooth host RX thread, and the Zephyr default (1.2 kB)
  silently overflows there, wedging the controller on connect.
* After a successful connection ``main.c`` keeps the provisioning service up
  for 30 more seconds before stopping it. The app is still connected over BLE
  at that point and polls the final status; stopping immediately makes the
  apps report a failure even though Wi-Fi connected.

Sample output
*************

.. code-block:: console

   [00:00:00.100] <inf> app: Device not provisioned, starting BLE provisioning
   [00:00:00.135] <inf> app: Provisioning started; connect with the ESP provisioning app
   [00:01:13.811] <inf> network_prov: central connected
   [00:01:19.343] <inf> network_prov: Scan done: 16 AP(s)
   [00:01:28.552] <inf> network_prov: Received credentials for SSID '<your-ssid>'
   [00:01:28.753] <inf> app: Wi-Fi credentials received, connecting...
   [00:01:33.824] <inf> network_prov: Wi-Fi connected
   [00:01:33.824] <inf> app: Provisioning successful, Wi-Fi connected
   [00:01:41.502] <inf> network_prov: central disconnected (reason 19)
