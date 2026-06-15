#!/usr/bin/env bash
# Run one Thread provisioning end-to-end simulation over the 802.15.4 radio.
# device_count + the per-device testids are set by the wrapper scripts.
#
# SPDX-License-Identifier: Apache-2.0
set -eu

source "${ZEPHYR_BASE}/tests/bsim/sh_common.source"

verbosity_level=2
simulation_id="${simulation_id:?must be set by the wrapper script}"
device_count="${device_count:?must be set by the wrapper script}"
dut_id="${dut_id:?must be set by the wrapper script}"
# peer_id is optional (only the scan scenario uses a second node).
peer_id="${peer_id:-}"

EXE="./bs_${BOARD_TS}_network_prov_thread_e2e"

cd "${BSIM_OUT_PATH}/bin"

Execute "${EXE}" -v=${verbosity_level} -s="${simulation_id}" -d=0 \
	-RealEncryption=1 -testid="${dut_id}"

if [ -n "${peer_id}" ]; then
	Execute "${EXE}" -v=${verbosity_level} -s="${simulation_id}" -d=1 \
		-RealEncryption=1 -testid="${peer_id}"
fi

# 802.15.4 uses the same 2.4GHz phy as BLE; -argschannel/-at select the radio
# channel model (mirrors Zephyr's echo_test_ot.sh).
Execute ./bs_2G4_phy_v1 -v=${verbosity_level} -s="${simulation_id}" \
	-D="${device_count}" -sim_length=60e6 -argschannel -at=40 -argsmain "$@"

wait_for_background_jobs
