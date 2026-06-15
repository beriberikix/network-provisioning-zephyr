/*
 * DUT: the real provisioning manager (Thread network type). Two scenarios:
 *
 *  - dut_attach: apply a freshly generated dataset via the Thread config
 *    handler; a lone FTD forms its own network and becomes leader, so the
 *    manager reports NETWORK_PROV_CRED_SUCCESS.
 *  - dut_scan: drive the Thread scan handler (otThreadDiscover) and assert the
 *    peer node's network is discovered.
 *
 * The manager is init'd (console scheme — satisfies the >=1-transport guard,
 * never started) so its event/semaphore plumbing is live; the handlers are
 * invoked directly (no transport client).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <zephyr/kernel.h>

#include "bstests.h"
#include "babblekit/testcase.h"

#include <openthread.h>
#include <openthread/dataset.h>
#include <openthread/dataset_ftd.h>
#include <openthread/instance.h>

#include <pb_encode.h>
#include <pb_decode.h>
#include "network_scan.pb.h"

#include "network_provisioning/network_prov_mgr.h"
#include "network_provisioning/scheme_console.h"
#include "network_prov_internal.h"

#include "common.h"

#define WAIT_TIME_S 40
#define WAIT_TIME   (WAIT_TIME_S * 1e6)

static void prov_event(void *user_data, enum network_prov_cb_event event, void *event_data)
{
	ARG_UNUSED(user_data);
	ARG_UNUSED(event_data);

	switch (event) {
	case NETWORK_PROV_CRED_RECV:
		TEST_PRINT("DUT: dataset received, attaching...");
		break;
	case NETWORK_PROV_CRED_SUCCESS:
		TEST_PASS("DUT: Thread attached");
		break;
	case NETWORK_PROV_CRED_FAIL:
		TEST_FAIL("DUT: Thread attach failed");
		break;
	default:
		break;
	}
}

static void dut_init_mgr(void)
{
	struct network_prov_mgr_config cfg = {
		.scheme = &network_prov_scheme_console,
		.app_event_handler = { .event_cb = prov_event },
	};

	TEST_ASSERT(network_prov_mgr_init(cfg) == 0, "manager init failed");
}

static void dut_attach_main(void)
{
	otOperationalDataset ds;
	otOperationalDatasetTlvs tlvs;
	otError err;

	dut_init_mgr();

	openthread_mutex_lock();
	err = otDatasetCreateNewNetwork(openthread_get_default_instance(), &ds);
	if (err == OT_ERROR_NONE) {
		otDatasetConvertToTlvs(&ds, &tlvs);
	}
	openthread_mutex_unlock();
	TEST_ASSERT(err == OT_ERROR_NONE, "dataset create failed: %d", err);

	/* Applies the dataset, enables Thread; the verdict is set in prov_event()
	 * once the node attaches (forms its own network → leader).
	 */
	TEST_ASSERT(network_prov_thread_config_set_and_apply(tlvs.mTlvs, tlvs.mLength) == 0,
		    "apply failed");
}

/* Encode a NetworkScanPayload, run the Thread scan handler, decode the
 * response. Returns the handler's return code.
 */
static int run_scan(const NetworkScanPayload *req, NetworkScanPayload *resp)
{
	uint8_t buf[64];
	pb_ostream_t os = pb_ostream_from_buffer(buf, sizeof(buf));

	TEST_ASSERT(pb_encode(&os, NetworkScanPayload_fields, req), "encode failed");

	uint8_t *out = NULL;
	size_t outlen = 0;
	int ret = network_prov_thread_scan_handler(NULL, buf, os.bytes_written, &out, &outlen);

	if (ret != 0) {
		return ret;
	}

	pb_istream_t is = pb_istream_from_buffer(out, outlen);

	TEST_ASSERT(pb_decode(&is, NetworkScanPayload_fields, resp), "decode failed");
	k_free(out);
	return 0;
}

static void dut_scan_main(void)
{
	dut_init_mgr();
	TEST_ASSERT(network_prov_thread_scan_init() == 0, "scan init failed");

	/* Let the peer form its network first. */
	k_sleep(K_SECONDS(5));

	/* Blocking discovery on the peer's channel. */
	NetworkScanPayload req = NetworkScanPayload_init_default;
	NetworkScanPayload resp = NetworkScanPayload_init_default;

	req.msg = NetworkScanMsgType_TypeCmdScanThreadStart;
	req.which_payload = NetworkScanPayload_cmd_scan_thread_start_tag;
	req.payload.cmd_scan_thread_start.blocking = true;
	req.payload.cmd_scan_thread_start.channel_mask = BIT(PEER_CHANNEL);

	TEST_ASSERT(run_scan(&req, &resp) == 0, "scan start failed");
	TEST_ASSERT(resp.payload.resp_scan_thread_start.status == Status_Success ||
			    resp.status == Status_Success,
		    "scan start status not success");

	/* Pull the results and look for the peer's network. */
	req = (NetworkScanPayload)NetworkScanPayload_init_default;
	resp = (NetworkScanPayload)NetworkScanPayload_init_default;
	req.msg = NetworkScanMsgType_TypeCmdScanThreadResult;
	req.which_payload = NetworkScanPayload_cmd_scan_thread_result_tag;
	req.payload.cmd_scan_thread_result.start_index = 0;
	req.payload.cmd_scan_thread_result.count = 4;

	TEST_ASSERT(run_scan(&req, &resp) == 0, "scan result failed");

	RespScanThreadResult *r = &resp.payload.resp_scan_thread_result;
	bool found = false;

	for (size_t i = 0; i < r->entries_count; i++) {
		TEST_PRINT("DUT: discovered '%s' (pan 0x%04x, ch %u)",
			   r->entries[i].network_name, r->entries[i].pan_id,
			   r->entries[i].channel);
		if (strcmp(r->entries[i].network_name, PEER_NET_NAME) == 0) {
			found = true;
		}
	}

	if (found) {
		TEST_PASS("DUT: discovered peer network '%s'", PEER_NET_NAME);
	} else {
		TEST_FAIL("DUT: peer network '%s' not found (%u result(s))",
			  PEER_NET_NAME, (unsigned int)r->entries_count);
	}
}

static void dut_tick(bs_time_t HW_device_time)
{
	ARG_UNUSED(HW_device_time);
	if (bst_result != Passed) {
		TEST_FAIL("DUT: test did not pass within %d seconds", WAIT_TIME_S);
	}
}

static void dut_init(void)
{
	bst_ticker_set_next_tick_absolute(WAIT_TIME);
	bst_result = In_progress;
}

static const struct bst_test_instance dut_tests[] = {
	{
		.test_id = "dut_attach",
		.test_descr = "Apply a dataset and attach (form network as leader)",
		.test_pre_init_f = dut_init,
		.test_tick_f = dut_tick,
		.test_main_f = dut_attach_main,
	},
	{
		.test_id = "dut_scan",
		.test_descr = "Discover the peer's Thread network via otThreadDiscover",
		.test_pre_init_f = dut_init,
		.test_tick_f = dut_tick,
		.test_main_f = dut_scan_main,
	},
	BSTEST_END_MARKER,
};

struct bst_test_list *dut_install(struct bst_test_list *tests)
{
	return bst_add_tests(tests, dut_tests);
}
