# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(network_provisioning_bsim_thread_e2e)

target_sources(app PRIVATE
  src/main.c
  src/dut.c
  src/peer.c
  src/common.c
)

# Internal module headers (network_prov_internal.h) and the nanopb-generated
# *.pb.h headers from the module's build directory.
target_include_directories(app PRIVATE
  ${ZEPHYR_NETWORK_PROVISIONING_MODULE_DIR}/src
  ${CMAKE_BINARY_DIR}/modules/network_provisioning/proto
)

# babblesim test-case helpers (TEST_PASS/TEST_FAIL, bst_test).
add_subdirectory(${ZEPHYR_BASE}/tests/bsim/babblekit babblekit)
target_link_libraries(app PRIVATE babblekit)

zephyr_include_directories(
  ${BSIM_COMPONENTS_PATH}/libUtilv1/src/
  ${BSIM_COMPONENTS_PATH}/libPhyComv1/src/
)
