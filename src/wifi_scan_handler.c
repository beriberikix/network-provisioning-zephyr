/*
 * prov-scan endpoint: run a Wi-Fi scan via net_mgmt and return the access
 * point list to the app, paginated through start_index/count.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/wifi_mgmt.h>
#include <string.h>
#include <errno.h>

#include <pb_encode.h>
#include <pb_decode.h>
#include "network_scan.pb.h"

#include "network_prov_internal.h"
#include "security.h"

LOG_MODULE_DECLARE(network_prov, CONFIG_NETWORK_PROV_LOG_LEVEL);

#define SCAN_MAX_ENTRIES CONFIG_NETWORK_PROV_SCAN_MAX_ENTRIES

struct scan_entry {
	uint8_t ssid[WIFI_SSID_MAX_LEN];
	uint8_t ssid_len;
	uint8_t bssid[WIFI_MAC_ADDR_LEN];
	uint8_t channel;
	int8_t rssi;
	WifiAuthMode auth;
};

static struct {
	struct scan_entry entries[SCAN_MAX_ENTRIES];
	size_t count;
	bool finished;
	struct net_mgmt_event_callback cb;
	bool cb_registered;
} sc;

static WifiAuthMode auth_from_zephyr(enum wifi_security_type sec)
{
	switch (sec) {
	case WIFI_SECURITY_TYPE_NONE:
		return WifiAuthMode_Open;
	case WIFI_SECURITY_TYPE_WEP:
		return WifiAuthMode_WEP;
	case WIFI_SECURITY_TYPE_PSK:
		return WifiAuthMode_WPA2_PSK;
	case WIFI_SECURITY_TYPE_PSK_SHA256:
		return WifiAuthMode_WPA2_PSK;
	case WIFI_SECURITY_TYPE_SAE:
		return WifiAuthMode_WPA3_PSK;
	case WIFI_SECURITY_TYPE_WPA_PSK:
		return WifiAuthMode_WPA_PSK;
	default:
		return WifiAuthMode_WPA2_PSK;
	}
}

static void on_scan_result(struct net_mgmt_event_callback *cb)
{
	const struct wifi_scan_result *r =
		(const struct wifi_scan_result *)cb->info;

	if (sc.count >= SCAN_MAX_ENTRIES) {
		return;
	}
	struct scan_entry *e = &sc.entries[sc.count++];

	e->ssid_len = MIN(r->ssid_length, sizeof(e->ssid));
	memcpy(e->ssid, r->ssid, e->ssid_len);
	memcpy(e->bssid, r->mac, WIFI_MAC_ADDR_LEN);
	e->channel = r->channel;
	e->rssi = r->rssi;
	e->auth = auth_from_zephyr(r->security);
}

static void mgmt_event(struct net_mgmt_event_callback *cb, uint64_t event,
		       struct net_if *iface)
{
	ARG_UNUSED(iface);
	switch (event) {
	case NET_EVENT_WIFI_SCAN_RESULT:
		on_scan_result(cb);
		break;
	case NET_EVENT_WIFI_SCAN_DONE:
		sc.finished = true;
		LOG_INF("Scan done: %u AP(s)", (unsigned int)sc.count);
		break;
	default:
		break;
	}
}

int network_prov_wifi_scan_init(void)
{
	if (!sc.cb_registered) {
		net_mgmt_init_event_callback(&sc.cb, mgmt_event,
					     NET_EVENT_WIFI_SCAN_RESULT |
						     NET_EVENT_WIFI_SCAN_DONE);
		net_mgmt_add_event_callback(&sc.cb);
		sc.cb_registered = true;
	}
	return 0;
}

void network_prov_wifi_scan_deinit(void)
{
	if (sc.cb_registered) {
		net_mgmt_del_event_callback(&sc.cb);
		sc.cb_registered = false;
	}
}

static Status do_scan_start(void)
{
	struct net_if *iface = net_if_get_wifi_sta();

	if (iface == NULL) {
		iface = net_if_get_first_wifi();
	}
	if (iface == NULL) {
		return Status_InternalError;
	}

	sc.count = 0;
	sc.finished = false;

	if (net_mgmt(NET_REQUEST_WIFI_SCAN, iface, NULL, 0) != 0) {
		LOG_ERR("Scan request failed");
		sc.finished = true;
		return Status_InternalError;
	}
	return Status_Success;
}

static int encode_resp(NetworkScanPayload *resp, uint8_t **outbuf, size_t *outlen)
{
	resp->status = Status_Success;
	return network_prov_pb_encode(NetworkScanPayload_fields, resp, outbuf, outlen);
}

int network_prov_wifi_scan_handler(void *priv, const uint8_t *inbuf, size_t inlen,
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
	case NetworkScanMsgType_TypeCmdScanWifiStart: {
		Status s = do_scan_start();

		resp.msg = NetworkScanMsgType_TypeRespScanWifiStart;
		resp.which_payload = NetworkScanPayload_resp_scan_wifi_start_tag;
		resp.status = s;
		return network_prov_pb_encode(NetworkScanPayload_fields, &resp,
					      outbuf, outlen);
	}
	case NetworkScanMsgType_TypeCmdScanWifiStatus:
		resp.msg = NetworkScanMsgType_TypeRespScanWifiStatus;
		resp.which_payload = NetworkScanPayload_resp_scan_wifi_status_tag;
		resp.payload.resp_scan_wifi_status.scan_finished = sc.finished;
		resp.payload.resp_scan_wifi_status.result_count = sc.count;
		return encode_resp(&resp, outbuf, outlen);

	case NetworkScanMsgType_TypeCmdScanWifiResult: {
		uint32_t start = req.payload.cmd_scan_wifi_result.start_index;
		uint32_t want = req.payload.cmd_scan_wifi_result.count;

		resp.msg = NetworkScanMsgType_TypeRespScanWifiResult;
		resp.which_payload = NetworkScanPayload_resp_scan_wifi_result_tag;

		RespScanWifiResult *out = &resp.payload.resp_scan_wifi_result;
		size_t n = 0;

		for (uint32_t i = start;
		     i < sc.count && n < ARRAY_SIZE(out->entries) && n < want; i++) {
			struct scan_entry *e = &sc.entries[i];
			WiFiScanResult *w = &out->entries[n++];

			w->ssid.size = e->ssid_len;
			memcpy(w->ssid.bytes, e->ssid, e->ssid_len);
			w->channel = e->channel;
			w->rssi = e->rssi;
			w->bssid.size = WIFI_MAC_ADDR_LEN;
			memcpy(w->bssid.bytes, e->bssid, WIFI_MAC_ADDR_LEN);
			w->auth = e->auth;
		}
		out->entries_count = n;
		return encode_resp(&resp, outbuf, outlen);
	}
	default:
		LOG_WRN("prov-scan: unsupported msg %d", req.msg);
		return -ENOTSUP;
	}
}
