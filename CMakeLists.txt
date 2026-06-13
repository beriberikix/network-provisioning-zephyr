# Network provisioning manager (Wi-Fi over BLE) for Zephyr
#
# SPDX-License-Identifier: Apache-2.0

# Public API headers are exposed unconditionally (absolute path) so the
# application can include <network_provisioning/...> regardless of config or
# module processing order.
zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# The transport-agnostic protocol core (protocomm engine, protobuf helpers,
# security schemes 0/1) builds standalone — including on native_sim, which is
# how the unit tests under tests/ consume it. NETWORK_PROV_MGR selects it and
# layers the BLE transport, Wi-Fi handlers and the manager on top.
if(CONFIG_NETWORK_PROV_CORE)
  zephyr_library_named(network_provisioning)

  zephyr_library_sources(
    src/protocomm.c
    src/pb_util.c
    src/security0.c
    src/security1.c
  )

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
    proto/network_ctrl.proto
  )

  # nanopb generates the .pb.h headers under <build>/proto (mirroring the
  # proto/ source dir via RELPATH), but only the binary root is auto-added to
  # the include path. Expose the generated headers so sources can include them
  # by basename, e.g. #include "session.pb.h".
  zephyr_library_include_directories(${CMAKE_CURRENT_BINARY_DIR}/proto)

  if(CONFIG_NETWORK_PROV_BLE)
    zephyr_library_sources(src/protocomm_ble.c)
  endif()

  if(CONFIG_NETWORK_PROV_SOFTAP)
    zephyr_library_sources(src/protocomm_softap.c)
    # The HTTP service's resource list lives in a per-service iterable
    # section that the linker script must lay out.
    zephyr_linker_sources(SECTIONS src/sections-rom.ld)
    zephyr_linker_section(NAME http_resource_desc_network_prov_http_service
                          KVMA RAM_REGION GROUP RODATA_REGION)
  endif()

  if(CONFIG_NETWORK_PROV_MGR)
    zephyr_library_sources(
      src/network_prov_mgr.c
      src/wifi_config_handler.c
      src/wifi_scan_handler.c
      src/wifi_ctrl_handler.c
    )
  endif()
endif()

# Test-only simulated Wi-Fi offload backend, built as its own library so it
# stays out of the real samples (which never set CONFIG_NETWORK_PROV_FAKE_WIFI).
add_subdirectory_ifdef(CONFIG_NETWORK_PROV_FAKE_WIFI sim/wifi)
