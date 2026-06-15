/*
 * BabbleSim end-to-end test for Thread provisioning over a simulated 802.15.4
 * radio (no BLE — the BLE transport is covered by ble_e2e).
 *
 * dut_attach (1 node): the manager's Thread config handler applies a dataset
 * and the node attaches (forms its own network → leader) → CRED_SUCCESS.
 * dut_scan (2 nodes): a "peer" node forms a known network and the DUT's Thread
 * scan handler discovers it via otThreadDiscover.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "bstests.h"

extern struct bst_test_list *dut_install(struct bst_test_list *tests);
extern struct bst_test_list *peer_install(struct bst_test_list *tests);

bst_test_install_t test_installers[] = {
	dut_install,
	peer_install,
	NULL,
};

int main(void)
{
	bst_main();
	return 0;
}
