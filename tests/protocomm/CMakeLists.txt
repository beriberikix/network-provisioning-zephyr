# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(protocomm_test)

target_sources(app PRIVATE src/main.c)

# Internal module headers (protocomm.h, security.h) and the nanopb-generated
# *.pb.h headers, which land in the module's build directory.
target_include_directories(app PRIVATE
  ${ZEPHYR_NETWORK_PROVISIONING_MODULE_DIR}/src
  ${CMAKE_BINARY_DIR}/modules/network_provisioning/proto
)
