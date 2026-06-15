/*
 * Peer (device 1) for the dut_scan scenario: a plain OpenThread FTD (no
 * provisioning manager) that forms a known Thread network and stays up so the
 * DUT's otThreadDiscover finds it.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>

#include "bstests.h"
#include "babblekit/testcase.h"

#include <openthread.h>
#include <openthread/dataset.h>
#include <openthread/instance.h>
#include <openthread/ip6.h>
#include <openthread/thread.h>

#include "common.h"

#define WAIT_TIME_S 40
#define WAIT_TIME   (WAIT_TIME_S * 1e6)

static struct openthread_state_changed_callback peer_cb;

static void peer_state(otChangedFlags flags, void *context)
{
	ARG_UNUSED(context);

	if ((flags & OT_CHANGED_THREAD_ROLE) == 0) {
		return;
	}

	otDeviceRole role = otThreadGetDeviceRole(openthread_get_default_instance());

	TEST_PRINT("peer: role -> %d", role);
	if (role == OT_DEVICE_ROLE_LEADER && bst_result != Passed) {
		/* Network formed. Pass, but keep running (OpenThread continues under
		 * the bsim scheduler) so the DUT's discovery gets a response.
		 */
		TEST_PASS("peer: formed network '%s' (leader)", PEER_NET_NAME);
	}
}

static void peer_main(void)
{
	otInstance *inst = openthread_get_default_instance();
	otOperationalDatasetTlvs tlvs;
	int rc;

	/* Register the role callback before enabling, so a fast leader transition
	 * is not missed.
	 */
	peer_cb.otCallback = peer_state;
	TEST_ASSERT(openthread_state_changed_callback_register(&peer_cb) == 0,
		    "peer: state callback register failed");

	openthread_mutex_lock();
	rc = build_peer_dataset(&tlvs);
	if (rc == 0) {
		(void)otDatasetSetActiveTlvs(inst, &tlvs);
		(void)otIp6SetEnabled(inst, true);
		(void)otThreadSetEnabled(inst, true);
	}
	openthread_mutex_unlock();

	TEST_ASSERT(rc == 0, "peer: failed to build dataset");
	/* Return; the verdict is set in peer_state() once we become leader. */
}

static void peer_tick(bs_time_t HW_device_time)
{
	ARG_UNUSED(HW_device_time);
	if (bst_result != Passed) {
		TEST_FAIL("peer: never became leader within %d seconds", WAIT_TIME_S);
	}
}

static void peer_init(void)
{
	bst_ticker_set_next_tick_absolute(WAIT_TIME);
	bst_result = In_progress;
}

static const struct bst_test_instance peer_tests[] = {
	{
		.test_id = "peer",
		.test_descr = "OpenThread FTD that forms a discoverable network",
		.test_pre_init_f = peer_init,
		.test_tick_f = peer_tick,
		.test_main_f = peer_main,
	},
	BSTEST_END_MARKER,
};

struct bst_test_list *peer_install(struct bst_test_list *tests)
{
	return bst_add_tests(tests, peer_tests);
}
