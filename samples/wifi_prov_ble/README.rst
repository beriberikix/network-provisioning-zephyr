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

Sample output
*************

.. code-block:: console

   [00:00:00.123] <inf> app: Device not provisioned, starting BLE provisioning
   [00:00:00.456] <inf> app: Provisioning started; connect with the ESP provisioning app
   [00:00:30.789] <inf> app: Wi-Fi credentials received, connecting...
   [00:00:34.012] <inf> app: Provisioning successful, Wi-Fi connected
