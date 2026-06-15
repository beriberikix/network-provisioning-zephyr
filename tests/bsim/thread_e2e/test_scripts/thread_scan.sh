#!/usr/bin/env bash
# Thread scan: a peer node forms a network and the DUT discovers it via
# otThreadDiscover. Two nodes.
#
# SPDX-License-Identifier: Apache-2.0
simulation_id="net_prov_thread_scan" \
	device_count=2 \
	dut_id="dut_scan" \
	peer_id="peer" \
	"$(dirname "${BASH_SOURCE[0]}")/_run_test.sh"
