#!/usr/bin/env bash
# Successful BLE provisioning: the DUT connects with the supplied credentials.
#
# SPDX-License-Identifier: Apache-2.0
simulation_id="net_prov_ble_success" \
	dut_id="dut_success" \
	tester_id="tester_success" \
	"$(dirname "${BASH_SOURCE[0]}")/_run_test.sh"
