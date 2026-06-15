/*
 * Thread prov-config handler test: generate a valid Active Operational Dataset
 * with OpenThread, then drive the handler's Set -> Apply -> GetStatus path and
 * assert the dataset is accepted, committed, and reported.
 *
 * Runs the real manager (Thread network type) + OpenThread on a Thread-capable
 * board (built for nrf52840dk; native_sim has no 802.15.4 radio, so this is
 * build_only — see testcase.yaml). The handler is invoked directly: the manager
 * is init'd so its event/semaphore plumbing is live, but no transport is
 * started. Assertions stay on the deterministic apply/commit path — a live
 * radio attach is not required.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/ztest.h>

#include <openthread.h>
#include <openthread/dataset.h>
#include <openthread/dataset_ftd.h> /* otDatasetCreateNewNetwork (FTD) */
#include <openthread/thread.h>

#include <pb_encode.h>
#include <pb_decode.h>
#include "network_config.pb.h"
#include "network_scan.pb.h"

#include "network_provisioning/network_prov_mgr.h"
#include "network_provisioning/scheme_console.h"
#include "network_prov_internal.h"

static struct {
	bool recv;
	bool success;
	bool fail;
} ev;

static void on_event(void *user_data, enum network_prov_cb_event event, void *event_data)
{
	ARG_UNUSED(user_data);
	ARG_UNUSED(event_data);

	switch (event) {
	case NETWORK_PROV_CRED_RECV:
		ev.recv = true;
		break;
	case NETWORK_PROV_CRED_SUCCESS:
		ev.success = true;
		break;
	case NETWORK_PROV_CRED_FAIL:
		ev.fail = true;
		break;
	default:
		break;
	}
}

/* Encode a NetworkConfigPayload, run the Thread config handler, decode the
 * response back into @p resp. Returns the handler's return code.
 */
static int run_handler(const NetworkConfigPayload *req, NetworkConfigPayload *resp)
{
	uint8_t buf[300];
	pb_ostream_t os = pb_ostream_from_buffer(buf, sizeof(buf));

	zassert_true(pb_encode(&os, NetworkConfigPayload_fields, req),
		     "encode failed: %s", PB_GET_ERROR(&os));

	uint8_t *out = NULL;
	size_t outlen = 0;
	int ret = network_prov_thread_config_handler(NULL, buf, os.bytes_written,
						     &out, &outlen);

	if (ret != 0) {
		return ret;
	}

	pb_istream_t is = pb_istream_from_buffer(out, outlen);

	zassert_true(pb_decode(&is, NetworkConfigPayload_fields, resp),
		     "decode failed: %s", PB_GET_ERROR(&is));
	k_free(out);
	return 0;
}

ZTEST(thread_config, test_set_apply_status)
{
	struct network_prov_mgr_config cfg = {
		.scheme = &network_prov_scheme_console,
		.app_event_handler = { .event_cb = on_event },
	};

	memset(&ev, 0, sizeof(ev));
	zassert_equal(network_prov_mgr_init(cfg), 0, "manager init failed");
	zassert_equal(network_prov_thread_config_init(), 0, "thread config init failed");

	/* Generate a valid Active Operational Dataset and serialise it to TLVs —
	 * exactly the blob a commissioner hands the device.
	 */
	otInstance *inst = openthread_get_default_instance();

	zassert_not_null(inst, "no OpenThread instance");

	otOperationalDataset ds;
	otOperationalDatasetTlvs tlvs;

	openthread_mutex_lock();
	zassert_equal(otDatasetCreateNewNetwork(inst, &ds), OT_ERROR_NONE,
		      "create new network");
	otDatasetConvertToTlvs(&ds, &tlvs);
	openthread_mutex_unlock();
	zassert_true(tlvs.mLength > 0 && tlvs.mLength <= 254, "bad TLV length %u",
		     (unsigned int)tlvs.mLength);

	/* CmdSetThreadConfig: stage the dataset. */
	NetworkConfigPayload req = NetworkConfigPayload_init_default;
	NetworkConfigPayload resp = NetworkConfigPayload_init_default;

	req.msg = NetworkConfigMsgType_TypeCmdSetThreadConfig;
	req.which_payload = NetworkConfigPayload_cmd_set_thread_config_tag;
	req.payload.cmd_set_thread_config.dataset.size = tlvs.mLength;
	memcpy(req.payload.cmd_set_thread_config.dataset.bytes, tlvs.mTlvs, tlvs.mLength);

	zassert_equal(run_handler(&req, &resp), 0, "set handler failed");
	zassert_equal(resp.msg, NetworkConfigMsgType_TypeRespSetThreadConfig, "set resp type");
	zassert_equal(resp.payload.resp_set_thread_config.status, Status_Success,
		      "set status not success");

	/* CmdApplyThreadConfig: commit the dataset and enable Thread. */
	req = (NetworkConfigPayload)NetworkConfigPayload_init_default;
	resp = (NetworkConfigPayload)NetworkConfigPayload_init_default;
	req.msg = NetworkConfigMsgType_TypeCmdApplyThreadConfig;
	req.which_payload = NetworkConfigPayload_cmd_apply_thread_config_tag;

	zassert_equal(run_handler(&req, &resp), 0, "apply handler failed");
	zassert_equal(resp.msg, NetworkConfigMsgType_TypeRespApplyThreadConfig, "apply resp type");
	zassert_equal(resp.payload.resp_apply_thread_config.status, Status_Success,
		      "apply status not success");

	zassert_true(ev.recv, "expected NETWORK_PROV_CRED_RECV on apply");
	zassert_false(ev.fail, "apply must not fail with a valid dataset");
	zassert_true(network_prov_thread_is_commissioned(),
		     "dataset must be committed after apply");

	/* CmdGetThreadStatus: state is Attaching, or Attached if the lone FTD has
	 * already formed its own network.
	 */
	req = (NetworkConfigPayload)NetworkConfigPayload_init_default;
	resp = (NetworkConfigPayload)NetworkConfigPayload_init_default;
	req.msg = NetworkConfigMsgType_TypeCmdGetThreadStatus;
	req.which_payload = NetworkConfigPayload_cmd_get_thread_status_tag;

	zassert_equal(run_handler(&req, &resp), 0, "status handler failed");
	zassert_equal(resp.msg, NetworkConfigMsgType_TypeRespGetThreadStatus, "status resp type");
	zassert_equal(resp.payload.resp_get_thread_status.status, Status_Success, "status not ok");

	ThreadNetworkState st = resp.payload.resp_get_thread_status.thread_state;

	zassert_true(st == ThreadNetworkState_Attaching || st == ThreadNetworkState_Attached,
		     "unexpected thread state %d", st);

	network_prov_thread_config_reset();
	network_prov_thread_config_deinit();
	network_prov_mgr_deinit();
}

/* Encode a NetworkScanPayload, run the Thread scan handler, decode the response
 * into @p resp. Returns the handler's return code.
 */
static int run_scan_handler(const NetworkScanPayload *req, NetworkScanPayload *resp)
{
	uint8_t buf[64];
	pb_ostream_t os = pb_ostream_from_buffer(buf, sizeof(buf));

	zassert_true(pb_encode(&os, NetworkScanPayload_fields, req),
		     "encode failed: %s", PB_GET_ERROR(&os));

	uint8_t *out = NULL;
	size_t outlen = 0;
	int ret = network_prov_thread_scan_handler(NULL, buf, os.bytes_written,
						   &out, &outlen);

	if (ret != 0) {
		return ret;
	}

	pb_istream_t is = pb_istream_from_buffer(out, outlen);

	zassert_true(pb_decode(&is, NetworkScanPayload_fields, resp),
		     "decode failed: %s", PB_GET_ERROR(&is));
	k_free(out);
	return 0;
}

ZTEST(thread_config, test_scan_start_status_result)
{
	zassert_equal(network_prov_thread_scan_init(), 0, "scan init failed");

	NetworkScanPayload req = NetworkScanPayload_init_default;
	NetworkScanPayload resp = NetworkScanPayload_init_default;

	/* Non-blocking start so the handler returns without waiting on the sweep
	 * (which a lone node can't complete without a network).
	 */
	req.msg = NetworkScanMsgType_TypeCmdScanThreadStart;
	req.which_payload = NetworkScanPayload_cmd_scan_thread_start_tag;
	req.payload.cmd_scan_thread_start.blocking = false;

	zassert_equal(run_scan_handler(&req, &resp), 0, "scan start failed");
	zassert_equal(resp.msg, NetworkScanMsgType_TypeRespScanThreadStart, "start resp type");

	/* Status: decodes and reports a count within bounds. */
	req = (NetworkScanPayload)NetworkScanPayload_init_default;
	resp = (NetworkScanPayload)NetworkScanPayload_init_default;
	req.msg = NetworkScanMsgType_TypeCmdScanThreadStatus;
	req.which_payload = NetworkScanPayload_cmd_scan_thread_status_tag;

	zassert_equal(run_scan_handler(&req, &resp), 0, "scan status failed");
	zassert_equal(resp.msg, NetworkScanMsgType_TypeRespScanThreadStatus, "status resp type");

	/* Result: first page decodes. */
	req = (NetworkScanPayload)NetworkScanPayload_init_default;
	resp = (NetworkScanPayload)NetworkScanPayload_init_default;
	req.msg = NetworkScanMsgType_TypeCmdScanThreadResult;
	req.which_payload = NetworkScanPayload_cmd_scan_thread_result_tag;
	req.payload.cmd_scan_thread_result.start_index = 0;
	req.payload.cmd_scan_thread_result.count = 4;

	zassert_equal(run_scan_handler(&req, &resp), 0, "scan result failed");
	zassert_equal(resp.msg, NetworkScanMsgType_TypeRespScanThreadResult, "result resp type");

	network_prov_thread_scan_deinit();
}

ZTEST_SUITE(thread_config, NULL, NULL, NULL, NULL, NULL);
