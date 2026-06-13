#!/usr/bin/env bash
# Run one BLE provisioning end-to-end simulation: DUT (device 0) + tester
# (device 1) + the 2G4 physical layer. The scenario is selected by dut_id /
# tester_id (set by the wrapper scripts).
#
# SPDX-License-Identifier: Apache-2.0
set -eu

source "${ZEPHYR_BASE}/tests/bsim/sh_common.source"

verbosity_level=2
simulation_id="${simulation_id:?must be set by the wrapper script}"
dut_id="${dut_id:?must be set by the wrapper script}"
tester_id="${tester_id:?must be set by the wrapper script}"

EXE="./bs_${BOARD_TS}_network_prov_ble_e2e"

cd "${BSIM_OUT_PATH}/bin"

Execute "${EXE}" -v=${verbosity_level} -s="${simulation_id}" -d=0 \
	-RealEncryption=1 -testid="${dut_id}"

Execute "${EXE}" -v=${verbosity_level} -s="${simulation_id}" -d=1 \
	-RealEncryption=1 -testid="${tester_id}"

Execute ./bs_2G4_phy_v1 -v=${verbosity_level} -s="${simulation_id}" \
	-D=2 -sim_length=60e6 "$@"

wait_for_background_jobs
