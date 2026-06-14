# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(console_transport_test)

target_sources(app PRIVATE
  src/main.c
  ${ZEPHYR_NETWORK_PROVISIONING_MODULE_DIR}/tests/common/prov_client.c
)

# The shared test client and the nanopb-generated *.pb.h headers (constants /
# network_config) from the module's build directory.
target_include_directories(app PRIVATE
  ${ZEPHYR_NETWORK_PROVISIONING_MODULE_DIR}/tests/common
  ${CMAKE_BINARY_DIR}/modules/network_provisioning/proto
)
