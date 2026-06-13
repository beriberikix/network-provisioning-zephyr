# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(protocomm_http_test)

target_sources(app PRIVATE
  src/main.c
  ${ZEPHYR_NETWORK_PROVISIONING_MODULE_DIR}/tests/common/prov_client.c
)

# Internal module headers (protocomm.h, network_prov_internal.h), the shared
# test client and the nanopb-generated *.pb.h headers from the module's build
# directory.
target_include_directories(app PRIVATE
  ${ZEPHYR_NETWORK_PROVISIONING_MODULE_DIR}/src
  ${ZEPHYR_NETWORK_PROVISIONING_MODULE_DIR}/tests/common
  ${CMAKE_BINARY_DIR}/modules/network_provisioning/proto
)
