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
(``CONFIG_NETWORK_PROV_NETWORK_TYPE_THREAD``). The commissioner supplies the
dataset directly; ``prov-scan`` can list nearby Thread networks
(``otThreadDiscover``) to help pick one.

Requirements
************

* A board with both Bluetooth LE and an IEEE 802.15.4 radio, plus radio
  arbitration between them. The provisioning app stays connected over BLE while
  the device attaches to Thread, so both protocols use the radio at once.
* On Nordic SoCs, that arbitration comes from the **nRF Connect SDK**: the
  Multiprotocol Service Layer (MPSL) and the SoftDevice Controller, prebuilt
  libraries under Nordic's license. Upstream Zephyr's open-source BLE controller
  cannot share the radio. The sample still builds there, with a CMake warning,
  but the controller asserts as soon as Thread starts. Validated on
  ``nrf52840dk/nrf52840`` with NCS v3.4.2.
* One of the Espressif provisioning apps, or the ``esp_prov.py`` CLI from
  ``idf-extra-components/network_provisioning/tool/esp_prov``, driven with
  ``--dataset_tlvs`` and a dataset.

Building and Running
********************

Create an NCS workspace from this repository's ``west-ncs.yml``. It imports
NCS v3.4.2 trimmed to the projects this build needs:

.. code-block:: console

   west init -m https://github.com/beriberikix/network-provisioning-zephyr \
       --mf west-ncs.yml ncs-workspace
   cd ncs-workspace && west update
   west build -b nrf52840dk/nrf52840 \
       network-provisioning-zephyr/samples/thread_prov_ble
   west flash

To use an existing NCS workspace instead, add this repository to its manifest,
or pass it as an extra module:
``west build ... -- -DZEPHYR_EXTRA_MODULES=/path/to/network-provisioning-zephyr``.

.. note::

   Recent nRF52840 silicon locks the debug port (APPROTECT) at boot when UICR
   is erased, for example after ``west flash --erase``. A J-Link that then
   connects has to unlock the chip, which mass-erases it and wipes the
   firmware and the stored dataset. If you need to halt or reset the device
   with a debugger during testing, first open the port by writing ``0x5A`` to
   ``UICR.APPROTECT`` (``0x10001208``).

Provision with esp_prov.py
==========================

Supply the Thread dataset TLVs (hex) the device should join:

.. code-block:: console

   python esp_prov.py --transport ble --service_name PROV_ZEPHYR \
       --sec_ver 1 --pop abcd1234 \
       --dataset_tlvs <operational-dataset-tlvs-hex>

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
