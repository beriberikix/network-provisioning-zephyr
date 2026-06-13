#!/usr/bin/env bash
# Build the BabbleSim images for this module's bsim tests.
#
# SPDX-License-Identifier: Apache-2.0
set -ue

: "${ZEPHYR_BASE:?ZEPHYR_BASE must point to the zephyr root directory}"
: "${BSIM_COMPONENTS_PATH:?BSIM_COMPONENTS_PATH must be defined (BabbleSim)}"

# Repository root (this script lives in <repo>/tests/bsim).
REPO_DIR="$(realpath "$(dirname "${BASH_SOURCE[0]}")/../..")"

source "${ZEPHYR_BASE}/tests/bsim/compile.source"

# Build the test as an out-of-tree application against this module. Add it via
# EXTRA_ZEPHYR_MODULES (additive) rather than ZEPHYR_MODULES, which would
# replace the workspace's auto-discovered modules (nanopb, mbedtls, ...).
cmake_extra_args="-DEXTRA_ZEPHYR_MODULES=${REPO_DIR}" \
	app_root="${REPO_DIR}" app="tests/bsim/ble_e2e" \
	exe_name="bs_${BOARD_TS}_network_prov_ble_e2e" \
	compile

wait_for_background_jobs
