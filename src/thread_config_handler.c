/*
 * prov-config endpoint (Thread): receive the Active Operational Dataset, apply
 * it through OpenThread, drive attachment and report status back to the app.
 *
 * Thread counterpart of wifi_config_handler.c — same prov-config endpoint and
 * the same NETWORK_PROV_CRED_* lifecycle events, but it carries the Thread
 * NetworkConfigPayload message types and talks to the OpenThread stack
 * (otDatasetSetActiveTlvs + otThreadSetEnabled) instead of net_mgmt Wi-Fi. The
 * dataset persists through OpenThread's own settings store, so there is no
 * wifi_credentials analog. All OpenThread API calls hold the OT mutex.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/atomic.h>
#include <string.h>
#include <errno.h>

#include <openthread.h> /* Zephyr wrapper: instance, mutex, state callback */
#include <openthread/dataset.h>
#include <openthread/instance.h>
#include <openthread/ip6.h>
#include <openthread/link.h>
#include <openthread/thread.h>

#include <pb_encode.h>
#include <pb_decode.h>
#include "network_config.pb.h"

#include "network_prov_internal.h"
#include "security.h"

LOG_MODULE_DECLARE(network_prov, CONFIG_NETWORK_PROV_LOG_LEVEL);

/* Grace window for the node to attach after a dataset is applied before the
 * attempt is reported as failed (the apps keep polling GetThreadStatus, which
 * reports Attaching until then).
 */
#define ATTACH_TIMEOUT K_SECONDS(30)

static struct {
	otOperationalDatasetTlvs dataset; /* staged by CmdSetThreadConfig */
	bool dataset_staged;

	ThreadNetworkState state;            /* reported wire state */
	ThreadAttachFailedReason fail_reason;
	/* 1 while an apply is in flight and its terminal outcome is still
	 * unclaimed. The attach callback (OT thread) and the timeout (system
	 * workqueue) race to claim it; atomic_cas() guarantees exactly one wins,
	 * so a success is never dropped by a near-simultaneous timeout.
	 */
	atomic_t pending;

	struct openthread_state_changed_callback ot_cb;
	bool cb_registered;
	struct k_work_delayable attach_timeout;
} tc;

static bool role_is_attached(otDeviceRole role)
{
	return role == OT_DEVICE_ROLE_CHILD || role == OT_DEVICE_ROLE_ROUTER ||
	       role == OT_DEVICE_ROLE_LEADER;
}

/* Attach succeeded. Claims the pending outcome (no-op if the timeout already
 * did) so exactly one of success/failure is reported. Runs from the OpenThread
 * state-change callback (OT thread context).
 */
static void on_attached(void)
{
	if (!atomic_cas(&tc.pending, 1, 0)) {
		return;
	}
	tc.state = ThreadNetworkState_Attached;
	(void)k_work_cancel_delayable(&tc.attach_timeout);
	LOG_INF("Thread attached");
	network_prov_emit_event(NETWORK_PROV_CRED_SUCCESS, NULL);
}

/* No attach within the grace window: report failure (mirrors the Wi-Fi
 * final_failure path), unless the attach callback already claimed success. The
 * public reason enum is Wi-Fi-named; map "network not found" onto it.
 */
static void attach_timeout_fn(struct k_work *work)
{
	ARG_UNUSED(work);

	if (!atomic_cas(&tc.pending, 1, 0)) {
		return;
	}
	tc.state = ThreadNetworkState_AttachingFailed;
	tc.fail_reason = ThreadAttachFailedReason_ThreadNetworkNotFound;
	LOG_WRN("Thread attach timed out");

	enum network_prov_cred_fail_reason reason = NETWORK_PROV_WIFI_NETWORK_NOT_FOUND;

	network_prov_emit_event(NETWORK_PROV_CRED_FAIL, &reason);
}

static void ot_state_changed(otChangedFlags flags, void *context)
{
	ARG_UNUSED(context);

	if ((flags & OT_CHANGED_THREAD_ROLE) == 0) {
		return;
	}
	/* Invoked from the OpenThread thread; the getter is safe here without an
	 * extra lock (we are already in OT context).
	 */
	if (role_is_attached(otThreadGetDeviceRole(openthread_get_default_instance()))) {
		on_attached();
	}
}

int network_prov_thread_config_init(void)
{
	memset(&tc, 0, sizeof(tc));
	tc.state = ThreadNetworkState_Dettached; /* upstream spelling */
	k_work_init_delayable(&tc.attach_timeout, attach_timeout_fn);

	tc.ot_cb.otCallback = ot_state_changed;
	int ret = openthread_state_changed_callback_register(&tc.ot_cb);

	if (ret != 0) {
		LOG_ERR("Failed to register OpenThread state callback: %d", ret);
		return ret;
	}
	tc.cb_registered = true;
	return 0;
}

void network_prov_thread_config_deinit(void)
{
	(void)k_work_cancel_delayable(&tc.attach_timeout);
	if (tc.cb_registered) {
		(void)openthread_state_changed_callback_unregister(&tc.ot_cb);
		tc.cb_registered = false;
	}
}

void network_prov_thread_config_reset(void)
{
	(void)k_work_cancel_delayable(&tc.attach_timeout);
	tc.dataset_staged = false;
	atomic_set(&tc.pending, 0);
	tc.state = ThreadNetworkState_Dettached;
	memset(&tc.dataset, 0, sizeof(tc.dataset));

	openthread_mutex_lock();
	(void)otThreadSetEnabled(openthread_get_default_instance(), false);
	openthread_mutex_unlock();
}

int network_prov_thread_config_erase(void)
{
	otInstance *inst = openthread_get_default_instance();

	(void)k_work_cancel_delayable(&tc.attach_timeout);
	tc.dataset_staged = false;
	atomic_set(&tc.pending, 0);
	tc.state = ThreadNetworkState_Dettached;

	openthread_mutex_lock();
	(void)otThreadSetEnabled(inst, false);
	otError err = otInstanceErasePersistentInfo(inst);

	openthread_mutex_unlock();

	if (err != OT_ERROR_NONE) {
		LOG_ERR("Failed to erase Thread dataset: %d", err);
		return -EIO;
	}
	LOG_INF("Thread dataset erased");
	return 0;
}

bool network_prov_thread_is_commissioned(void)
{
	openthread_mutex_lock();
	bool committed = otDatasetIsCommissioned(openthread_get_default_instance());

	openthread_mutex_unlock();
	return committed;
}

/* Commit the staged dataset and bring Thread up. Shared by CmdApplyThreadConfig
 * and the programmatic set_and_apply path.
 */
static Status do_apply_config(void)
{
	otInstance *inst = openthread_get_default_instance();

	if (!tc.dataset_staged) {
		return Status_InvalidArgument;
	}

	openthread_mutex_lock();
	otError err = otDatasetSetActiveTlvs(inst, &tc.dataset);

	if (err == OT_ERROR_NONE) {
		(void)otIp6SetEnabled(inst, true);
		err = otThreadSetEnabled(inst, true);
	}
	openthread_mutex_unlock();

	if (err != OT_ERROR_NONE) {
		LOG_ERR("Failed to apply Thread dataset: %d", err);
		tc.state = ThreadNetworkState_AttachingFailed;
		tc.fail_reason = ThreadAttachFailedReason_DatasetInvalid;

		/* A bad/rejected dataset is a config error, not "network not
		 * found"; map it onto the generic auth/config failure reason.
		 */
		enum network_prov_cred_fail_reason reason = NETWORK_PROV_WIFI_AUTH_ERROR;

		network_prov_emit_event(NETWORK_PROV_CRED_RECV, NULL);
		network_prov_emit_event(NETWORK_PROV_CRED_FAIL, &reason);
		/* Still answer the Apply with success so the apps run their normal
		 * status-poll flow (mirrors the Wi-Fi sync-error handling).
		 */
		return Status_Success;
	}

	network_prov_emit_event(NETWORK_PROV_CRED_RECV, NULL);
	tc.state = ThreadNetworkState_Attaching;
	atomic_set(&tc.pending, 1);

	/* Already attached (e.g. re-apply of the same network)? Report now. */
	openthread_mutex_lock();
	bool attached = role_is_attached(otThreadGetDeviceRole(inst));

	openthread_mutex_unlock();
	if (attached) {
		on_attached();
	} else {
		k_work_reschedule(&tc.attach_timeout, ATTACH_TIMEOUT);
	}
	return Status_Success;
}

static Status do_set_config(const CmdSetThreadConfig *cmd)
{
	if (cmd->dataset.size == 0 || cmd->dataset.size > sizeof(tc.dataset.mTlvs)) {
		return Status_InvalidArgument;
	}
	memcpy(tc.dataset.mTlvs, cmd->dataset.bytes, cmd->dataset.size);
	tc.dataset.mLength = cmd->dataset.size;
	tc.dataset_staged = true;
	LOG_INF("Received Thread dataset (%u TLV bytes)", (unsigned int)cmd->dataset.size);
	return Status_Success;
}

int network_prov_thread_config_set_and_apply(const uint8_t *dataset, size_t len)
{
	if (dataset == NULL || len == 0 || len > sizeof(tc.dataset.mTlvs)) {
		return -EINVAL;
	}
	memcpy(tc.dataset.mTlvs, dataset, len);
	tc.dataset.mLength = len;
	tc.dataset_staged = true;
	return (do_apply_config() == Status_Success) ? 0 : -EIO;
}

static void fill_attached_state(ThreadAttachState *out)
{
	otInstance *inst = openthread_get_default_instance();

	openthread_mutex_lock();
	out->pan_id = otLinkGetPanId(inst);
	out->channel = otLinkGetChannel(inst);

	const otExtendedPanId *xpan = otThreadGetExtendedPanId(inst);

	out->ext_pan_id.size = sizeof(xpan->m8);
	memcpy(out->ext_pan_id.bytes, xpan->m8, sizeof(xpan->m8));

	const char *name = otThreadGetNetworkName(inst);

	strncpy(out->name, name, sizeof(out->name) - 1);
	out->name[sizeof(out->name) - 1] = '\0'; /* strncpy may not NUL-terminate */
	openthread_mutex_unlock();
}

static int encode_get_status(uint8_t **outbuf, size_t *outlen)
{
	NetworkConfigPayload resp = NetworkConfigPayload_init_default;

	resp.msg = NetworkConfigMsgType_TypeRespGetThreadStatus;
	resp.which_payload = NetworkConfigPayload_resp_get_thread_status_tag;
	resp.payload.resp_get_thread_status.status = Status_Success;
	resp.payload.resp_get_thread_status.thread_state = tc.state;

	if (tc.state == ThreadNetworkState_Attached) {
		resp.payload.resp_get_thread_status.which_state =
			RespGetThreadStatus_thread_attached_tag;
		fill_attached_state(&resp.payload.resp_get_thread_status.state.thread_attached);
	} else if (tc.state == ThreadNetworkState_AttachingFailed) {
		resp.payload.resp_get_thread_status.which_state =
			RespGetThreadStatus_thread_fail_reason_tag;
		resp.payload.resp_get_thread_status.state.thread_fail_reason = tc.fail_reason;
	}

	return network_prov_pb_encode(NetworkConfigPayload_fields, &resp, outbuf, outlen);
}

static int encode_simple(NetworkConfigMsgType type, Status status,
			 uint8_t **outbuf, size_t *outlen)
{
	NetworkConfigPayload resp = NetworkConfigPayload_init_default;

	resp.msg = type;
	if (type == NetworkConfigMsgType_TypeRespSetThreadConfig) {
		resp.which_payload = NetworkConfigPayload_resp_set_thread_config_tag;
		resp.payload.resp_set_thread_config.status = status;
	} else { /* TypeRespApplyThreadConfig */
		resp.which_payload = NetworkConfigPayload_resp_apply_thread_config_tag;
		resp.payload.resp_apply_thread_config.status = status;
	}
	return network_prov_pb_encode(NetworkConfigPayload_fields, &resp, outbuf, outlen);
}

int network_prov_thread_config_handler(void *priv, const uint8_t *inbuf, size_t inlen,
				       uint8_t **outbuf, size_t *outlen)
{
	ARG_UNUSED(priv);

	NetworkConfigPayload req = NetworkConfigPayload_init_default;
	pb_istream_t istream = pb_istream_from_buffer(inbuf, inlen);

	if (!pb_decode(&istream, NetworkConfigPayload_fields, &req)) {
		LOG_ERR("prov-config: decode failed");
		return -EINVAL;
	}

	switch (req.msg) {
	case NetworkConfigMsgType_TypeCmdSetThreadConfig: {
		Status s = do_set_config(&req.payload.cmd_set_thread_config);

		return encode_simple(NetworkConfigMsgType_TypeRespSetThreadConfig, s,
				     outbuf, outlen);
	}
	case NetworkConfigMsgType_TypeCmdApplyThreadConfig: {
		Status s = do_apply_config();

		return encode_simple(NetworkConfigMsgType_TypeRespApplyThreadConfig, s,
				     outbuf, outlen);
	}
	case NetworkConfigMsgType_TypeCmdGetThreadStatus:
		return encode_get_status(outbuf, outlen);
	default:
		LOG_WRN("prov-config: unsupported msg %d", req.msg);
		return -ENOTSUP;
	}
}
