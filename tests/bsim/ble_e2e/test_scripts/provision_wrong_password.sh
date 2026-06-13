#!/usr/bin/env bash
# Failure injection: the DUT's Wi-Fi connect is programmed to fail with a wrong
# password, and the tester must observe a ConnectionFailed status.
#
# SPDX-License-Identifier: Apache-2.0
simulation_id="net_prov_ble_wrong_password" \
	dut_id="dut_wrong_password" \
	tester_id="tester_wrong_password" \
	"$(dirname "${BASH_SOURCE[0]}")/_run_test.sh"
