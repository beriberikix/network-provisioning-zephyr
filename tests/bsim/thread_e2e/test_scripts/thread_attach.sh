#!/usr/bin/env bash
# Thread attach: the DUT applies a dataset and forms its own network (leader).
# Single node.
#
# SPDX-License-Identifier: Apache-2.0
simulation_id="net_prov_thread_attach" \
	device_count=1 \
	dut_id="dut_attach" \
	"$(dirname "${BASH_SOURCE[0]}")/_run_test.sh"
