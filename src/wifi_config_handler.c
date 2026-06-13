/*
 * prov-config endpoint: receive Wi-Fi credentials, persist them through the
 * native wifi_credentials store, drive the connection via net_mgmt, and report
 * status back to the app.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/wifi_credentials.h>
#include <string.h>
#include <errno.h>

#include <pb_encode.h>
#include <pb_decode.h>
#include "network_config.pb.h"

#include "network_prov_internal.h"
#include "security.h"

LOG_MODULE_DECLARE(network_prov, CONFIG_NETWORK_PROV_LOG_LEVEL);

#define SSID_MAX 32
#define PASS_MAX 63

static struct {
	/* Pending credentials staged by SetWifiConfig. */
	uint8_t ssid[SSID_MAX + 1];
	size_t ssid_len;
	uint8_t pass[PASS_MAX + 1];
	size_t pass_len;
	uint8_t bssid[WIFI_MAC_ADDR_LEN];
	bool has_bssid;
	uint8_t channel;

	/* Connect parameters of the attempt currently in flight. Snapshotted
	 * at apply time because wc.ssid/pass may be rewritten (a new
	 * Set/Apply) or cleared (CmdCtrlWifiReset) before the asynchronous
	 * connect result arrives; zero ssid length means no attempt is
	 * pending and a stale result event must be ignored. Retries reconnect
	 * from this snapshot, never from the staging fields.
	 */
	uint8_t inflight_ssid[SSID_MAX + 1];
	size_t inflight_ssid_len;
	uint8_t inflight_pass[PASS_MAX + 1];
	size_t inflight_pass_len;
	uint8_t inflight_bssid[WIFI_MAC_ADDR_LEN];
	bool inflight_has_bssid;
	uint8_t inflight_channel;

	/* Connection attempts: 0 max = single attempt, fail immediately
	 * (wifi_conn_attempts upstream parity).
	 */
	uint32_t attempts_max;
	uint32_t attempts_completed;
	bool attempt_failed; /* at least one attempt failed, retry running */
	int last_conn_status; /* failure cause of the most recent attempt */
	struct k_work_delayable retry_work;

	/* Reported connection state. */
	WifiStationState sta_state;
	WifiConnectFailedReason fail_reason;

	struct net_mgmt_event_callback mgmt_cb;
	bool cb_registered;
} wc;

static enum wifi_security_type security_from_pass(void)
{
	return (wc.pass_len > 0) ? WIFI_SECURITY_TYPE_PSK : WIFI_SECURITY_TYPE_NONE;
}

/* Drop the in-flight connect snapshot once no further attempt will use it.
 * Zeroing it also keeps the passphrase from lingering in RAM. A zero
 * inflight_ssid_len additionally tells on_connect_result()/retry_work_handler
 * to ignore a stale or already-queued event.
 */
static void clear_inflight(void)
{
	memset(wc.inflight_ssid, 0, sizeof(wc.inflight_ssid));
	wc.inflight_ssid_len = 0;
	memset(wc.inflight_pass, 0, sizeof(wc.inflight_pass));
	wc.inflight_pass_len = 0;
	wc.inflight_has_bssid = false;
	wc.inflight_channel = 0;
}

/* Issue NET_REQUEST_WIFI_CONNECT from the in-flight snapshot. Used for the
 * initial attempt and for retries, so a Set/Apply re-staging wc.ssid/pass
 * mid-flight cannot change what is being retried.
 */
static int connect_from_inflight(void)
{
	struct net_if *iface = net_if_get_wifi_sta();

	if (iface == NULL) {
		iface = net_if_get_first_wifi();
	}
	if (iface == NULL) {
		return -ENODEV;
	}

	struct wifi_connect_req_params params = {0};

	params.ssid = wc.inflight_ssid;
	params.ssid_length = wc.inflight_ssid_len;
	params.psk = (wc.inflight_pass_len > 0) ? wc.inflight_pass : NULL;
	params.psk_length = wc.inflight_pass_len;
	params.security = (wc.inflight_pass_len > 0) ? WIFI_SECURITY_TYPE_PSK
						     : WIFI_SECURITY_TYPE_NONE;
	params.channel = (wc.inflight_channel > 0) ? wc.inflight_channel
						   : WIFI_CHANNEL_ANY;
	params.band = WIFI_FREQ_BAND_UNKNOWN;
	params.mfp = WIFI_MFP_OPTIONAL;
	params.timeout = SYS_FOREVER_MS;
	if (wc.inflight_has_bssid) {
		memcpy(params.bssid, wc.inflight_bssid, WIFI_MAC_ADDR_LEN);
	}

	return net_mgmt(NET_REQUEST_WIFI_CONNECT, iface, &params, sizeof(params));
}

/* Report the final failure of the current credentials: map the cause, drop
 * the persisted credentials and notify the application.
 */
static void final_failure(void)
{
	wc.sta_state = WifiStationState_ConnectionFailed;
	wc.attempt_failed = false;

	enum network_prov_cred_fail_reason reason;

	if (wc.last_conn_status == WIFI_STATUS_CONN_AP_NOT_FOUND) {
		wc.fail_reason = WifiConnectFailedReason_WifiNetworkNotFound;
		reason = NETWORK_PROV_WIFI_NETWORK_NOT_FOUND;
	} else {
		/* WRONG_PASSWORD, TIMEOUT and generic failures all
		 * surface as an auth error — the two proto reasons are
		 * all the apps can display, and a bad passphrase is by
		 * far the most common cause of the rest.
		 */
		wc.fail_reason = WifiConnectFailedReason_AuthError;
		reason = NETWORK_PROV_WIFI_AUTH_ERROR;
	}

	/* Drop the credentials persisted by ApplyWifiConfig: they did
	 * not work, and keeping them would make the device boot
	 * "provisioned" (and not advertise) after a power cycle even
	 * though provisioning never succeeded. An in-session retry
	 * stores fresh credentials on the next apply. Deleting by the
	 * in-flight snapshot (not wc.ssid) keeps a quick retry's
	 * freshly staged credentials safe.
	 */
	(void)wifi_credentials_delete_by_ssid(
		(const char *)wc.inflight_ssid, wc.inflight_ssid_len);
	clear_inflight();

	network_prov_emit_event(NETWORK_PROV_CRED_FAIL, &reason);
}

/* Deferred retry: a connect request issued from inside the connect-result
 * event callback fails while the Wi-Fi state machine is still tearing down
 * the previous attempt, so retries run from the system workqueue after a
 * short settle delay.
 */
static void retry_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);

	if (wc.inflight_ssid_len == 0) {
		/* Reset arrived while the retry was queued. */
		return;
	}

	if (connect_from_inflight() != 0) {
		LOG_ERR("Retry connect request failed");
		final_failure();
	}
}

static void on_connect_result(struct net_mgmt_event_callback *cb)
{
	const struct wifi_status *status = (const struct wifi_status *)cb->info;

	if (wc.inflight_ssid_len == 0) {
		/* No attempt pending (e.g. CmdCtrlWifiReset arrived while the
		 * connect was in flight): don't let a stale result clobber the
		 * fresh state or someone else's stored credentials.
		 */
		LOG_DBG("ignoring stale connect result");
		return;
	}

	if (status->status == 0) {
		LOG_INF("Wi-Fi connected");
		wc.sta_state = WifiStationState_Connected;
		wc.attempt_failed = false;
		clear_inflight();
		network_prov_emit_event(NETWORK_PROV_CRED_SUCCESS, NULL);
		return;
	}

	LOG_WRN("Wi-Fi connect failed (conn_status %d)", status->conn_status);
	wc.last_conn_status = status->conn_status;

	/* Retry while attempts remain (wifi_conn_attempts upstream parity):
	 * the wire state stays Connecting, status polls carry the attempts
	 * remaining, and neither CRED_FAIL nor credential cleanup happens
	 * until the final attempt.
	 */
	if (wc.attempts_max > 0) {
		wc.attempts_completed++;
		if (wc.attempts_completed < wc.attempts_max) {
			wc.attempt_failed = true;
			wc.sta_state = WifiStationState_Connecting;
			LOG_INF("Retrying connect (%u attempt(s) remaining)",
				wc.attempts_max - wc.attempts_completed);
			k_work_schedule(&wc.retry_work, K_SECONDS(1));
			return;
		}
	}

	final_failure();
}

static void mgmt_event(struct net_mgmt_event_callback *cb, uint64_t event,
		       struct net_if *iface)
{
	ARG_UNUSED(iface);
	if (event == NET_EVENT_WIFI_CONNECT_RESULT) {
		on_connect_result(cb);
	}
}

int network_prov_wifi_config_init(uint32_t conn_attempts)
{
	wc.sta_state = WifiStationState_Disconnected;
	wc.attempts_max = conn_attempts;
	wc.attempts_completed = 0;
	wc.attempt_failed = false;
	k_work_init_delayable(&wc.retry_work, retry_work_handler);
	if (!wc.cb_registered) {
		net_mgmt_init_event_callback(&wc.mgmt_cb, mgmt_event,
					     NET_EVENT_WIFI_CONNECT_RESULT);
		net_mgmt_add_event_callback(&wc.mgmt_cb);
		wc.cb_registered = true;
	}
	return 0;
}

void network_prov_wifi_config_deinit(void)
{
	/* Drop the snapshot before cancelling so a retry already running on the
	 * workqueue sees inflight_ssid_len == 0 and bails instead of issuing a
	 * connect after teardown.
	 */
	clear_inflight();
	(void)k_work_cancel_delayable(&wc.retry_work);
	if (wc.cb_registered) {
		net_mgmt_del_event_callback(&wc.mgmt_cb);
		wc.cb_registered = false;
	}
}

void network_prov_wifi_config_reset(void)
{
	/* Drop staged credentials and clear the reported connection state so
	 * the app can retry provisioning after a failed attempt (prov-ctrl
	 * CmdCtrlWifiReset / CmdCtrlWifiReprov).
	 */
	clear_inflight();
	(void)k_work_cancel_delayable(&wc.retry_work);
	memset(wc.ssid, 0, sizeof(wc.ssid));
	wc.ssid_len = 0;
	memset(wc.pass, 0, sizeof(wc.pass));
	wc.pass_len = 0;
	wc.has_bssid = false;
	wc.channel = 0;
	/* Allow the full attempt budget again after an app-driven reset
	 * (upstream 1.2.2 parity).
	 */
	wc.attempts_completed = 0;
	wc.attempt_failed = false;
	wc.sta_state = WifiStationState_Disconnected;
	wc.fail_reason = WifiConnectFailedReason_AuthError;
}

uint32_t network_prov_wifi_config_remaining_attempts(void)
{
	if (wc.attempts_max <= wc.attempts_completed) {
		return 0;
	}
	return wc.attempts_max - wc.attempts_completed;
}

static Status do_set_config(const CmdSetWifiConfig *cmd)
{
	if (cmd->ssid.size == 0 || cmd->ssid.size > SSID_MAX) {
		return Status_InvalidArgument;
	}
	if (cmd->passphrase.size > PASS_MAX) {
		return Status_InvalidArgument;
	}

	memset(&wc.ssid, 0, sizeof(wc.ssid));
	wc.ssid_len = cmd->ssid.size;
	memcpy(wc.ssid, cmd->ssid.bytes, wc.ssid_len);

	memset(&wc.pass, 0, sizeof(wc.pass));
	wc.pass_len = cmd->passphrase.size;
	memcpy(wc.pass, cmd->passphrase.bytes, wc.pass_len);

	wc.has_bssid = (cmd->bssid.size == WIFI_MAC_ADDR_LEN);
	if (wc.has_bssid) {
		memcpy(wc.bssid, cmd->bssid.bytes, WIFI_MAC_ADDR_LEN);
	}
	wc.channel = (uint8_t)cmd->channel;

	LOG_INF("Received credentials for SSID '%s'", wc.ssid);
	return Status_Success;
}

static Status do_apply_config(void)
{
	struct net_if *iface = net_if_get_wifi_sta();

	if (iface == NULL) {
		iface = net_if_get_first_wifi();
	}
	if (iface == NULL) {
		LOG_ERR("No Wi-Fi interface available");
		return Status_InternalError;
	}

	/* Persist credentials in the native store so they survive reboot. */
	uint32_t flags = 0;
	const uint8_t *bssid = NULL;
	size_t bssid_len = 0;

	if (wc.has_bssid) {
		flags |= WIFI_CREDENTIALS_FLAG_BSSID;
		bssid = wc.bssid;
		bssid_len = WIFI_MAC_ADDR_LEN;
	}

	/* Replace any previous entry for this SSID. */
	(void)wifi_credentials_delete_by_ssid((const char *)wc.ssid, wc.ssid_len);

	int ret = wifi_credentials_set_personal((const char *)wc.ssid, wc.ssid_len,
						security_from_pass(), bssid, bssid_len,
						(const char *)wc.pass, wc.pass_len,
						flags, wc.channel, 0);
	if (ret != 0) {
		LOG_ERR("Failed to store credentials: %d", ret);
		return Status_InternalError;
	}

	network_prov_emit_event(NETWORK_PROV_CRED_RECV, NULL);

	wc.sta_state = WifiStationState_Connecting;

	/* Snapshot the connect parameters for this attempt (and its retries)
	 * and start a fresh attempt budget for the new credentials (upstream
	 * 1.2.2 parity). A retry still queued for the previous credentials
	 * must not fire against the new snapshot.
	 */
	(void)k_work_cancel_delayable(&wc.retry_work);
	memcpy(wc.inflight_ssid, wc.ssid, sizeof(wc.inflight_ssid));
	wc.inflight_ssid_len = wc.ssid_len;
	memcpy(wc.inflight_pass, wc.pass, sizeof(wc.inflight_pass));
	wc.inflight_pass_len = wc.pass_len;
	wc.inflight_has_bssid = wc.has_bssid;
	if (wc.has_bssid) {
		memcpy(wc.inflight_bssid, wc.bssid, WIFI_MAC_ADDR_LEN);
	}
	wc.inflight_channel = wc.channel;
	wc.attempts_completed = 0;
	wc.attempt_failed = false;

	ret = connect_from_inflight();
	if (ret != 0) {
		/* The request was rejected synchronously (e.g. -EINVAL for a
		 * PSK shorter than 8 characters), so no connect-result event
		 * will ever arrive. Surface it exactly like an asynchronous
		 * connect failure — failed state for the status polls, the
		 * CRED_FAIL application event and credential cleanup — and
		 * still answer the Apply request with success, so the apps go
		 * through their normal status-poll/retry flow instead of
		 * showing a generic error without a retry option.
		 */
		LOG_ERR("Connect request failed: %d", ret);
		wc.sta_state = WifiStationState_ConnectionFailed;
		wc.fail_reason = WifiConnectFailedReason_AuthError;
		clear_inflight();

		(void)wifi_credentials_delete_by_ssid((const char *)wc.ssid,
						      wc.ssid_len);

		enum network_prov_cred_fail_reason reason =
			NETWORK_PROV_WIFI_AUTH_ERROR;
		network_prov_emit_event(NETWORK_PROV_CRED_FAIL, &reason);
	}
	return Status_Success;
}

int network_prov_wifi_config_set_and_apply(const uint8_t *ssid, size_t ssid_len,
					   const uint8_t *psk, size_t psk_len)
{
	if (ssid == NULL || ssid_len == 0 || ssid_len > SSID_MAX ||
	    psk_len > PASS_MAX || (psk_len > 0 && psk == NULL)) {
		return -EINVAL;
	}

	/* Stage the credentials the same way SetWifiConfig does, then run the
	 * shared apply path (persist + connect + retry + events).
	 */
	memset(wc.ssid, 0, sizeof(wc.ssid));
	wc.ssid_len = ssid_len;
	memcpy(wc.ssid, ssid, ssid_len);

	memset(wc.pass, 0, sizeof(wc.pass));
	wc.pass_len = psk_len;
	if (psk_len > 0) {
		memcpy(wc.pass, psk, psk_len);
	}

	wc.has_bssid = false;
	wc.channel = 0;

	return (do_apply_config() == Status_Success) ? 0 : -EIO;
}

static void fill_connected_state(WifiConnectedState *out)
{
	struct net_if *iface = net_if_get_wifi_sta();
	struct wifi_iface_status status = {0};

	if (iface != NULL &&
	    net_mgmt(NET_REQUEST_WIFI_IFACE_STATUS, iface, &status,
		     sizeof(status)) == 0) {
		out->channel = status.channel;
		out->auth_mode = WifiAuthMode_WPA2_PSK;
		out->ssid.size = MIN(status.ssid_len, sizeof(out->ssid.bytes));
		memcpy(out->ssid.bytes, status.ssid, out->ssid.size);
		out->bssid.size = WIFI_MAC_ADDR_LEN;
		memcpy(out->bssid.bytes, status.bssid, WIFI_MAC_ADDR_LEN);
	} else {
		out->ssid.size = wc.ssid_len;
		memcpy(out->ssid.bytes, wc.ssid, wc.ssid_len);
	}

	if (iface != NULL) {
		struct in_addr *addr =
			net_if_ipv4_get_global_addr(iface, NET_ADDR_PREFERRED);

		if (addr != NULL) {
			net_addr_ntop(AF_INET, addr, out->ip4_addr,
				      sizeof(out->ip4_addr));
		}
	}
}

static int encode_get_status(uint8_t **outbuf, size_t *outlen)
{
	NetworkConfigPayload resp = NetworkConfigPayload_init_default;

	resp.msg = NetworkConfigMsgType_TypeRespGetWifiStatus;
	resp.which_payload = NetworkConfigPayload_resp_get_wifi_status_tag;
	resp.payload.resp_get_wifi_status.status = Status_Success;
	resp.payload.resp_get_wifi_status.wifi_sta_state = wc.sta_state;

	if (wc.sta_state == WifiStationState_Connected) {
		resp.payload.resp_get_wifi_status.which_state =
			RespGetWifiStatus_wifi_connected_tag;
		fill_connected_state(&resp.payload.resp_get_wifi_status.state.wifi_connected);
	} else if (wc.sta_state == WifiStationState_ConnectionFailed) {
		resp.payload.resp_get_wifi_status.which_state =
			RespGetWifiStatus_wifi_fail_reason_tag;
		resp.payload.resp_get_wifi_status.state.wifi_fail_reason = wc.fail_reason;
	} else if (wc.sta_state == WifiStationState_Connecting && wc.attempt_failed) {
		/* Mid-retry: the wire state stays Connecting and the payload
		 * carries the attempts remaining (upstream parity — the apps
		 * keep polling instead of reporting a failure).
		 */
		resp.payload.resp_get_wifi_status.which_state =
			RespGetWifiStatus_attempt_failed_tag;
		resp.payload.resp_get_wifi_status.state.attempt_failed.attempts_remaining =
			network_prov_wifi_config_remaining_attempts();
	}

	return network_prov_pb_encode(NetworkConfigPayload_fields, &resp, outbuf, outlen);
}

static int encode_simple(NetworkConfigMsgType type, Status status,
			 uint8_t **outbuf, size_t *outlen)
{
	NetworkConfigPayload resp = NetworkConfigPayload_init_default;

	resp.msg = type;
	if (type == NetworkConfigMsgType_TypeRespSetWifiConfig) {
		resp.which_payload = NetworkConfigPayload_resp_set_wifi_config_tag;
		resp.payload.resp_set_wifi_config.status = status;
	} else { /* TypeRespApplyWifiConfig */
		resp.which_payload = NetworkConfigPayload_resp_apply_wifi_config_tag;
		resp.payload.resp_apply_wifi_config.status = status;
	}
	return network_prov_pb_encode(NetworkConfigPayload_fields, &resp, outbuf, outlen);
}

int network_prov_wifi_config_handler(void *priv, const uint8_t *inbuf, size_t inlen,
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
	case NetworkConfigMsgType_TypeCmdSetWifiConfig: {
		Status s = do_set_config(&req.payload.cmd_set_wifi_config);

		return encode_simple(NetworkConfigMsgType_TypeRespSetWifiConfig, s,
				     outbuf, outlen);
	}
	case NetworkConfigMsgType_TypeCmdApplyWifiConfig: {
		Status s = do_apply_config();

		return encode_simple(NetworkConfigMsgType_TypeRespApplyWifiConfig, s,
				     outbuf, outlen);
	}
	case NetworkConfigMsgType_TypeCmdGetWifiStatus:
		return encode_get_status(outbuf, outlen);
	default:
		LOG_WRN("prov-config: unsupported msg %d", req.msg);
		return -ENOTSUP;
	}
}
