.. _thread_prov_ble_sample:

Thread Provisioning over BLE
############################

Overview
********

Advertises an Espressif-compatible BLE provisioning peripheral that hands a
**Thread Active Operational Dataset** to the device. The stock **ESP
provisioning** apps (Android/iOS) — or ``esp_prov.py`` — connect over BLE, run
the security handshake, and deliver the dataset, which is applied through
OpenThread (``otDatasetSetActiveTlvs``) and persisted in OpenThread's settings
store. On the next boot the device attaches with the stored dataset instead of
advertising. This is the canonical Matter-style flow: BLE commissioning to bring
a headless Thread device onto the mesh.

This is the Thread counterpart of :ref:`wifi_prov_ble_sample`; the protocol,
transport and security are identical — only the provisioned network differs
(``CONFIG_NETWORK_PROV_NETWORK_TYPE_THREAD``). Thread network scan is not yet
implemented, so the commissioner must supply the dataset directly.

Requirements
************

* A board with both Bluetooth LE and an IEEE 802.15.4 radio (BLE + Thread
  multiprotocol). Validated on ``nrf52840dk/nrf52840``.
* One of the Espressif provisioning apps, or the ``esp_prov.py`` CLI from
  ``idf-extra-components/network_provisioning/tool/esp_prov``, driven with
  ``--network thread`` and a dataset.

Building and Running
********************

.. code-block:: console

   west build -b nrf52840dk/nrf52840 \
       network-provisioning-zephyr/samples/thread_prov_ble
   west flash

Provision with esp_prov.py
==========================

Supply the Thread dataset TLVs (hex) the device should join:

.. code-block:: console

   python esp_prov.py --transport ble --service_name PROV_ZEPHYR \
       --sec_ver 1 --pop abcd1234 \
       --network thread --dataset <operational-dataset-tlvs-hex>

Configuration
*************

Defaults live in ``src/main.c`` and ``prj.conf``:

* ``PROV_POP`` — proof-of-possession string. Set it to ``""`` to advertise the
  ``no_pop`` capability (security 1 without a PoP).
* ``CONFIG_BT_DEVICE_NAME`` — advertised name; keep the ``PROV_`` prefix the
  apps filter on.
* ``CONFIG_OPENTHREAD_FTD`` — Full Thread Device. Use ``CONFIG_OPENTHREAD_MTD``
  for a sleepy/minimal end device.
* ``CONFIG_OPENTHREAD_MANUAL_START=y`` — the stack is not auto-started with
  defaults; the sample applies the provisioned dataset, and on reboot (when a
  dataset is already stored) brings Thread up with ``openthread_run()``.
* ``CONFIG_BT_RX_STACK_SIZE`` — must stay at 4096 or larger: the security-1
  crypto runs on the Bluetooth host RX thread.

The dataset is never erased automatically. For an explicit factory reset (e.g.
a button) call ``network_prov_mgr_reset_wifi_provisioning()`` — despite the
Wi-Fi-flavored name it erases the Thread dataset in a Thread build.
