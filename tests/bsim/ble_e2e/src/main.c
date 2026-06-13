/*
 * BabbleSim end-to-end test for the BLE provisioning transport.
 *
 * Device 0 (DUT) runs the real provisioning manager over the real BLE GATT
 * transport, backed by the fake Wi-Fi driver. Device 1 (tester) is a GATT
 * central that drives a full provisioning flow (sec1 handshake, scan, config,
 * status) against it. Two simulations are run: a successful provisioning and a
 * wrong-password failure injection.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "bstests.h"

extern struct bst_test_list *dut_install(struct bst_test_list *tests);
extern struct bst_test_list *tester_install(struct bst_test_list *tests);

bst_test_install_t test_installers[] = {
	dut_install,
	tester_install,
	NULL,
};

int main(void)
{
	bst_main();
	return 0;
}
