# Network provisioning manager (Wi-Fi over BLE) for Zephyr
#
# SPDX-License-Identifier: Apache-2.0

if(CONFIG_NETWORK_PROV_MGR)
  zephyr_library_named(network_provisioning)

  zephyr_library_sources(
    src/protocomm.c
    src/protocomm_ble.c
    src/pb_util.c
    src/security0.c
    src/security1.c
    src/network_prov_mgr.c
    src/wifi_config_handler.c
    src/wifi_scan_handler.c
  )

  zephyr_include_directories(include)
  zephyr_library_include_directories(src)

  # Compile the protobuf definitions with nanopb. The matching <name>.options
  # files alongside each .proto bound the dynamic fields for static allocation.
  list(APPEND CMAKE_MODULE_PATH ${ZEPHYR_BASE}/modules/nanopb)
  include(nanopb)

  zephyr_nanopb_sources(network_provisioning
    proto/constants.proto
    proto/sec0.proto
    proto/sec1.proto
    proto/session.proto
    proto/network_constants.proto
    proto/network_config.proto
    proto/network_scan.proto
  )
endif()
