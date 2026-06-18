.. _wifi_prov_console_sample:

Wi-Fi Provisioning over the Console
###################################

Overview
********

Provisions Wi-Fi credentials over the device console (shell), using the same
secure protocomm session as the other transports. It speaks the transport
``esp_prov --transport console`` uses: a single shell command,

.. code-block:: none

   net_prov <endpoint> <session_id> <hex-request>

decodes the hex request, runs it through the named protocomm endpoint, and
prints the response as lowercase hex. Credentials are persisted via the native
``wifi_credentials`` subsystem, so on the next boot the device reconnects
automatically instead of provisioning. If the stored network stays unreachable
(5 attempts with backoff), the sample re-enters provisioning while keeping the
credentials (retried on the next boot, never erased automatically — call
``network_prov_mgr_reset_wifi_provisioning()`` for an explicit wipe).

Why the console transport
=========================

This sample exists for boards that have Wi-Fi but **no usable BLE or SoftAP
provisioning transport under Zephyr** — most notably the **Raspberry Pi
Pico 2W** (Infineon CYW43439). On that part the in-tree drivers provide:

* Wi-Fi **STA** only — via the AIROC/WHD driver.
* **No Bluetooth**: there is no in-tree HCI driver for the CYW43439's
  BT-over-PIO/gSPI wiring, so :ref:`wifi_prov_ble_sample` cannot run.
* **No concurrent SoftAP+STA**: the AIROC driver rejects bringing the AP up
  while STA is connected (and vice-versa), which the SoftAP/HTTP sample
  requires.

The console transport needs only a shell and Wi-Fi STA, so it runs end-to-end
on the Pico 2W. It is also handy on any board for bring-up and debugging.

Requirements
************

* A board with Wi-Fi STA and a serial console. Validated on
  ``rpi_pico2/rp2350a/m33/w`` (note the ``/w`` wireless variant); also builds
  on ``native_sim``.
* The ``esp_prov.py`` CLI from
  ``idf-extra-components/network_provisioning/tool/esp_prov``.
* For the Pico 2W: the CYW43439 firmware blobs
  (``west blobs fetch hal_infineon``) and a SWD debug adapter to flash and to
  bridge the console UART (e.g. the Raspberry Pi Debug Probe).

Building and Running
********************

On the Pico 2W, build as usual; the included board files add the flash storage
partition the credential store needs
(``boards/rpi_pico2_rp2350a_m33_w.overlay``) and route the console/shell over
**SEGGER RTT** (``boards/rpi_pico2_rp2350a_m33_w.conf``). RTT is read back over
the same SWD debug probe used to flash, so no UART wiring or USB cable is
required. (The board's USB-CDC console path is avoided here: the Zephyr
USB-device-next stack hits an iterable-section init fault on this target.)

.. code-block:: console

   west blobs fetch hal_infineon
   west build -b rpi_pico2/rp2350a/m33/w \
       network-provisioning-zephyr/samples/wifi_prov_console
   west flash               # openocd/cmsis-dap runner (Raspberry Pi Debug Probe)

If your Zephyr SDK's OpenOCD lacks RP2350 support, point the runner at a
pico-sdk OpenOCD: ``west flash --runner openocd --openocd <pico-sdk>/openocd
--openocd-search <pico-sdk>/scripts``.

Open the console over RTT (same debug probe), then connect to the RTT TCP port:

.. code-block:: console

   openocd -f interface/cmsis-dap.cfg -c "adapter speed 5000" \
       -f target/rp2350.cfg -c init -c "reset run" \
       -c 'rtt setup 0x20000000 0x80000 "SEGGER RTT"' \
       -c "rtt start" -c "rtt server start 9090 0"
   # then, in another terminal:
   nc localhost 9090            # or telnet localhost 9090

You should see the ``rtt:~$`` shell prompt and the "Provisioning started" log.
``wifi scan`` lists nearby APs (confirms the CYW43439 radio), and ``net iface``
shows the ``wlan0`` interface.

Provision with esp_prov.py
==========================

The console transport is human-in-the-loop: ``esp_prov`` prints each request as
a line to paste into the device shell, and you paste the device's hex response
back to ``esp_prov``.

.. code-block:: console

   python esp_prov.py --transport console \
       --sec_ver 1 --pop abcd1234 \
       --ssid "<your-ssid>" --passphrase "<your-pass>"

For each step esp_prov prints a line like ``net_prov prov-session 1 <hex>``;
paste it at the device shell prompt, then copy the device's hex reply back into
esp_prov when prompted. On success the device connects to Wi-Fi and obtains a
DHCP lease (check with the ``net iface`` shell command).

Configuration
*************

Defaults live in ``src/main.c`` and ``prj.conf``:

* ``PROV_POP`` — proof-of-possession string. Set it to ``""`` to advertise the
  ``no_pop`` capability (security 1 without a PoP).
* Security scheme — ``main.c`` uses ``NETWORK_PROV_SECURITY_1``. Pass
  ``NETWORK_PROV_SECURITY_0`` (and ``--sec_ver 0``) for an unencrypted bring-up
  session.
* ``session_id`` — changing it opens a fresh protocomm session (resetting the
  security handshake), the way a BLE reconnect or new HTTP cookie does.
* Logging shares the console with the shell; it is kept at INFO so manager
  diagnostics do not bury the ``net_prov`` response lines. Lower it
  (``CONFIG_NETWORK_PROV_LOG_LEVEL_WRN=y``) if log lines interfere with pasting.
* On the Pico 2W the console/shell run over RTT (see ``boards/*.conf``); on other
  boards the sample uses the board's default console (typically a UART).

Sample output
*************

.. code-block:: console

   [00:00:00.100] <inf> app: Device not provisioned, starting console provisioning
   [00:00:00.135] <inf> app: Provisioning started; drive it from the console
   [00:00:00.135] <inf> app:   shell command : net_prov <endpoint> <session_id> <hex>
   uart:~$ net_prov prov-session 1 <hex-request>
   <hex-response>
   [00:01:28.552] <inf> network_prov: Received credentials for SSID '<your-ssid>'
   [00:01:33.824] <inf> network_prov: Wi-Fi connected
   [00:01:33.824] <inf> app: Provisioning successful, Wi-Fi connected
