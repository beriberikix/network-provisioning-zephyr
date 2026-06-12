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

	/* SSID of the connect attempt currently in flight. Snapshotted at
	 * apply time because wc.ssid may be rewritten (a new Set/Apply) or
	 * cleared (CmdCtrlWifiReset) before the asynchronous connect result
	 * arrives; zero length means no attempt is pending and a stale result
	 * event must be ignored.
	 */
	uint8_t inflight_ssid[SSID_MAX + 1];
	size_t inflight_ssid_len;

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
		wc.inflight_ssid_len = 0;
		network_prov_emit_event(NETWORK_PROV_CRED_SUCCESS, NULL);
	} else {
		LOG_WRN("Wi-Fi connect failed (conn_status %d)", status->conn_status);
		wc.sta_state = WifiStationState_ConnectionFailed;

		enum network_prov_cred_fail_reason reason;

		if (status->conn_status == WIFI_STATUS_CONN_AP_NOT_FOUND) {
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
		wc.inflight_ssid_len = 0;

		network_prov_emit_event(NETWORK_PROV_CRED_FAIL, &reason);
	}
}

static void mgmt_event(struct net_mgmt_event_callback *cb, uint64_t event,
		       struct net_if *iface)
{
	ARG_UNUSED(iface);
	if (event == NET_EVENT_WIFI_CONNECT_RESULT) {
		on_connect_result(cb);
	}
}

int network_prov_wifi_config_init(void)
{
	wc.sta_state = WifiStationState_Disconnected;
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
	memset(wc.ssid, 0, sizeof(wc.ssid));
	wc.ssid_len = 0;
	memset(wc.pass, 0, sizeof(wc.pass));
	wc.pass_len = 0;
	wc.has_bssid = false;
	wc.channel = 0;
	memset(wc.inflight_ssid, 0, sizeof(wc.inflight_ssid));
	wc.inflight_ssid_len = 0;
	wc.sta_state = WifiStationState_Disconnected;
	wc.fail_reason = WifiConnectFailedReason_AuthError;
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

	struct wifi_connect_req_params params = {0};

	params.ssid = wc.ssid;
	params.ssid_length = wc.ssid_len;
	params.psk = (wc.pass_len > 0) ? wc.pass : NULL;
	params.psk_length = wc.pass_len;
	params.security = security_from_pass();
	params.channel = (wc.channel > 0) ? wc.channel : WIFI_CHANNEL_ANY;
	params.band = WIFI_FREQ_BAND_UNKNOWN;
	params.mfp = WIFI_MFP_OPTIONAL;
	params.timeout = SYS_FOREVER_MS;
	if (wc.has_bssid) {
		memcpy(params.bssid, wc.bssid, WIFI_MAC_ADDR_LEN);
	}

	wc.sta_state = WifiStationState_Connecting;
	memcpy(wc.inflight_ssid, wc.ssid, sizeof(wc.inflight_ssid));
	wc.inflight_ssid_len = wc.ssid_len;

	ret = net_mgmt(NET_REQUEST_WIFI_CONNECT, iface, &params, sizeof(params));
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
		wc.inflight_ssid_len = 0;

		(void)wifi_credentials_delete_by_ssid((const char *)wc.ssid,
						      wc.ssid_len);

		enum network_prov_cred_fail_reason reason =
			NETWORK_PROV_WIFI_AUTH_ERROR;
		network_prov_emit_event(NETWORK_PROV_CRED_FAIL, &reason);
	}
	return Status_Success;
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
