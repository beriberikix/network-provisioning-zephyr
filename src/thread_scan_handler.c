/*
 * prov-scan endpoint (Thread): run an MLE discovery scan via OpenThread and
 * return the discovered Thread networks to the app, paginated through
 * start_index/count.
 *
 * Thread counterpart of wifi_scan_handler.c — same prov-scan endpoint and the
 * same blocking/status/result flow, but it carries the Thread NetworkScanPayload
 * message types and scans with otThreadDiscover() instead of net_mgmt Wi-Fi.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <string.h>
#include <errno.h>

#include <openthread.h> /* Zephyr wrapper: instance + mutex */
#include <openthread/instance.h>
#include <openthread/ip6.h>
#include <openthread/link.h>
#include <openthread/thread.h>

#include <pb_encode.h>
#include <pb_decode.h>
#include "network_scan.pb.h"

#include "network_prov_internal.h"
#include "security.h"

LOG_MODULE_DECLARE(network_prov, CONFIG_NETWORK_PROV_LOG_LEVEL);

#define SCAN_MAX_ENTRIES CONFIG_NETWORK_PROV_SCAN_MAX_ENTRIES

/* Thread discovery sweeps every channel, so allow more time than the Wi-Fi
 * scan before a blocking ScanStart gives up (and frees the BT RX thread).
 */
#define SCAN_BLOCKING_TIMEOUT K_SECONDS(15)

struct thread_scan_entry {
	uint16_t pan_id;
	uint8_t channel;
	int8_t rssi;
	uint8_t lqi;
	uint8_t ext_addr[OT_EXT_ADDRESS_SIZE];
	uint8_t ext_pan_id[OT_EXT_PAN_ID_SIZE];
	char network_name[OT_NETWORK_NAME_MAX_SIZE + 1];
};

static struct {
	struct thread_scan_entry entries[SCAN_MAX_ENTRIES];
	size_t count;
	bool finished;
	bool in_progress;
} ts;

/* Guards ts: discover_cb() writes it from the OpenThread thread while the
 * handler reads it from the transport thread (a client may poll Status/Result
 * during a non-blocking sweep). Critical sections are short (field reads and a
 * bounded memcpy); kernel calls (sem give, encode) stay outside the lock.
 */
static struct k_spinlock ts_lock;

/* Given by the discovery callback's terminating (NULL) result so a blocking
 * ScanStart can hold its response until the sweep completes (ESP-IDF semantics).
 */
static K_SEM_DEFINE(scan_done_sem, 0, 1);

/* otThreadDiscover result callback (OpenThread thread context). A NULL result
 * marks the end of the sweep.
 */
static void discover_cb(otActiveScanResult *result, void *context)
{
	ARG_UNUSED(context);

	if (result == NULL) {
		size_t count;

		K_SPINLOCK(&ts_lock) {
			ts.finished = true;
			ts.in_progress = false;
			count = ts.count;
		}
		LOG_INF("Thread scan done: %u network(s)", (unsigned int)count);
		k_sem_give(&scan_done_sem);
		return;
	}

	K_SPINLOCK(&ts_lock) {
		if (ts.count < SCAN_MAX_ENTRIES) {
			struct thread_scan_entry *e = &ts.entries[ts.count++];

			e->pan_id = result->mPanId;
			e->channel = result->mChannel;
			e->rssi = result->mRssi;
			e->lqi = result->mLqi;
			memcpy(e->ext_addr, result->mExtAddress.m8, sizeof(e->ext_addr));
			memcpy(e->ext_pan_id, result->mExtendedPanId.m8,
			       sizeof(e->ext_pan_id));
			strncpy(e->network_name, result->mNetworkName.m8,
				sizeof(e->network_name) - 1);
			e->network_name[sizeof(e->network_name) - 1] = '\0';
		}
	}
}

int network_prov_thread_scan_init(void)
{
	memset(&ts, 0, sizeof(ts));
	return 0;
}

void network_prov_thread_scan_deinit(void)
{
	ts.in_progress = false;
}

static Status do_scan_start(uint32_t channel_mask)
{
	otInstance *inst = openthread_get_default_instance();

	K_SPINLOCK(&ts_lock) {
		ts.count = 0;
		ts.finished = false;
		ts.in_progress = true;
	}

	openthread_mutex_lock();
	/* otThreadDiscover requires the IPv6 interface up (it returns
	 * INVALID_STATE otherwise); a provisioning scan runs before any dataset is
	 * applied, so bring it up here. Idempotent.
	 */
	(void)otIp6SetEnabled(inst, true);

	/* An unset (0) channel_mask means "scan every supported channel"; a literal
	 * 0 bit vector would scan nothing. PAN-ID broadcast discovers every network;
	 * not a joiner; no EUI-64 filtering.
	 */
	uint32_t channels = channel_mask ? channel_mask
					 : otLinkGetSupportedChannelMask(inst);
	otError err = otThreadDiscover(inst, channels, OT_PANID_BROADCAST, false,
				       false, discover_cb, NULL);
	openthread_mutex_unlock();

	if (err != OT_ERROR_NONE) {
		LOG_ERR("otThreadDiscover failed: %d", err);
		K_SPINLOCK(&ts_lock) {
			ts.in_progress = false;
			ts.finished = true;
		}
		return Status_InternalError;
	}
	return Status_Success;
}

static int encode_resp(NetworkScanPayload *resp, uint8_t **outbuf, size_t *outlen)
{
	resp->status = Status_Success;
	return network_prov_pb_encode(NetworkScanPayload_fields, resp, outbuf, outlen);
}

int network_prov_thread_scan_handler(void *priv, const uint8_t *inbuf, size_t inlen,
				     uint8_t **outbuf, size_t *outlen)
{
	ARG_UNUSED(priv);

	NetworkScanPayload req = NetworkScanPayload_init_default;
	pb_istream_t istream = pb_istream_from_buffer(inbuf, inlen);

	if (!pb_decode(&istream, NetworkScanPayload_fields, &req)) {
		LOG_ERR("prov-scan: decode failed");
		return -EINVAL;
	}

	NetworkScanPayload resp = NetworkScanPayload_init_default;

	switch (req.msg) {
	case NetworkScanMsgType_TypeCmdScanThreadStart: {
		bool blocking =
			(req.which_payload ==
			 NetworkScanPayload_cmd_scan_thread_start_tag) &&
			req.payload.cmd_scan_thread_start.blocking;
		uint32_t channel_mask =
			(req.which_payload ==
			 NetworkScanPayload_cmd_scan_thread_start_tag)
				? req.payload.cmd_scan_thread_start.channel_mask
				: 0;

		k_sem_reset(&scan_done_sem);

		Status s = do_scan_start(channel_mask);

		/* ESP-IDF semantics: a blocking start replies only once the sweep
		 * has finished, so the apps' single status query already sees
		 * scan_finished == true.
		 */
		if (s == Status_Success && blocking &&
		    k_sem_take(&scan_done_sem, SCAN_BLOCKING_TIMEOUT) != 0) {
			LOG_WRN("blocking Thread scan timed out");
			s = Status_InternalError;
		}

		resp.msg = NetworkScanMsgType_TypeRespScanThreadStart;
		resp.which_payload = NetworkScanPayload_resp_scan_thread_start_tag;
		resp.status = s;
		return network_prov_pb_encode(NetworkScanPayload_fields, &resp,
					      outbuf, outlen);
	}
	case NetworkScanMsgType_TypeCmdScanThreadStatus:
		resp.msg = NetworkScanMsgType_TypeRespScanThreadStatus;
		resp.which_payload = NetworkScanPayload_resp_scan_thread_status_tag;
		K_SPINLOCK(&ts_lock) {
			resp.payload.resp_scan_thread_status.scan_finished = ts.finished;
			resp.payload.resp_scan_thread_status.result_count = ts.count;
		}
		return encode_resp(&resp, outbuf, outlen);

	case NetworkScanMsgType_TypeCmdScanThreadResult: {
		uint32_t start = req.payload.cmd_scan_thread_result.start_index;
		uint32_t want = req.payload.cmd_scan_thread_result.count;

		resp.msg = NetworkScanMsgType_TypeRespScanThreadResult;
		resp.which_payload = NetworkScanPayload_resp_scan_thread_result_tag;

		RespScanThreadResult *out = &resp.payload.resp_scan_thread_result;
		size_t n = 0;

		/* Snapshot the requested page under the lock so discover_cb can't
		 * mutate ts.entries/count mid-copy.
		 */
		K_SPINLOCK(&ts_lock) {
			for (uint32_t i = start;
			     i < ts.count && n < ARRAY_SIZE(out->entries) && n < want;
			     i++) {
				struct thread_scan_entry *e = &ts.entries[i];
				ThreadScanResult *t = &out->entries[n++];

				t->pan_id = e->pan_id;
				t->channel = e->channel;
				t->rssi = e->rssi;
				t->lqi = e->lqi;
				t->ext_addr.size = sizeof(e->ext_addr);
				memcpy(t->ext_addr.bytes, e->ext_addr, sizeof(e->ext_addr));
				t->ext_pan_id.size = sizeof(e->ext_pan_id);
				memcpy(t->ext_pan_id.bytes, e->ext_pan_id,
				       sizeof(e->ext_pan_id));
				strncpy(t->network_name, e->network_name,
					sizeof(t->network_name) - 1);
				t->network_name[sizeof(t->network_name) - 1] = '\0';
			}
		}
		out->entries_count = n;
		return encode_resp(&resp, outbuf, outlen);
	}
	default:
		LOG_WRN("prov-scan: unsupported msg %d", req.msg);
		return -ENOTSUP;
	}
}
