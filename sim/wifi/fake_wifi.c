/*
 * Fake (simulated) Wi-Fi offload backend for tests.
 *
 * Registers a WIFI-type offloaded net_if with no underlying hardware so the
 * full provisioning manager (which hard-depends on the Wi-Fi subsystem) builds
 * and runs on native_sim and nrf52_bsim. The wifi_mgmt operations answer with
 * programmable, deterministic results:
 *
 *   - scan:    reports a caller-supplied list of canned APs.
 *   - connect: raises NET_EVENT_WIFI_CONNECT_RESULT with a programmable
 *              conn_status (success / wrong-password / AP-not-found), or fails
 *              synchronously on request.
 *   - iface_status: reports the last successfully-connected network.
 *   - ap_enable / ap_disable / disconnect: succeed (no-op).
 *
 * Test control lives in include/network_provisioning/test/fake_wifi.h.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <errno.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/net/wifi.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/ethernet.h>

#include "network_provisioning/test/fake_wifi.h"

/* Stand-alone log module: the fake backend may be built without the
 * provisioning core (e.g. tests/fake_wifi), so it does not borrow the
 * network_prov log level.
 */
LOG_MODULE_REGISTER(fake_wifi, CONFIG_LOG_DEFAULT_LEVEL);

#define MAX_AP CONFIG_NETWORK_PROV_FAKE_WIFI_MAX_AP

struct fake_wifi_data {
	struct net_if *iface;

	/* Programmed scan list. */
	struct fake_wifi_ap aps[MAX_AP];
	size_t ap_count;

	/* Programmed connect outcome. */
	enum wifi_conn_status next_conn;
	int next_sync_err;

	/* Snapshot of the last connect target, echoed back by iface_status. */
	char conn_ssid[WIFI_SSID_MAX_LEN + 1];
	uint8_t conn_ssid_len;
	uint8_t conn_channel;
	bool connected;

	/* Results are delivered off the caller thread, mirroring real drivers:
	 * the config handler reschedules retries from the system workqueue
	 * because a connect issued inside the result callback is rejected.
	 */
	scan_result_cb_t scan_cb;
	struct k_work scan_work;
	struct k_work connect_work;
};

static struct fake_wifi_data fw_data = {
	.next_conn = WIFI_STATUS_CONN_SUCCESS,
};

/* --- Test-control API ----------------------------------------------------- */

void fake_wifi_set_scan_aps(const struct fake_wifi_ap *aps, size_t count)
{
	if (count > MAX_AP) {
		count = MAX_AP;
	}
	fw_data.ap_count = count;
	if (count > 0) {
		memcpy(fw_data.aps, aps, count * sizeof(*aps));
	}
}

void fake_wifi_set_next_connect_result(enum wifi_conn_status status)
{
	fw_data.next_conn = status;
}

void fake_wifi_set_next_connect_sync_error(int errnum)
{
	fw_data.next_sync_err = errnum;
}

void fake_wifi_reset(void)
{
	fw_data.ap_count = 0;
	fw_data.next_conn = WIFI_STATUS_CONN_SUCCESS;
	fw_data.next_sync_err = 0;
	fw_data.connected = false;
	fw_data.conn_ssid_len = 0;
}

/* --- Deferred work: emit scan results / connect result -------------------- */

static void scan_work_fn(struct k_work *work)
{
	struct fake_wifi_data *d = CONTAINER_OF(work, struct fake_wifi_data, scan_work);

	for (size_t i = 0; i < d->ap_count; i++) {
		const struct fake_wifi_ap *ap = &d->aps[i];
		struct wifi_scan_result entry = {0};

		entry.ssid_length = MIN(ap->ssid_len, (uint8_t)WIFI_SSID_MAX_LEN);
		memcpy(entry.ssid, ap->ssid, entry.ssid_length);
		memcpy(entry.mac, ap->bssid, WIFI_MAC_ADDR_LEN);
		entry.mac_length = WIFI_MAC_ADDR_LEN;
		entry.channel = ap->channel;
		entry.rssi = ap->rssi;
		entry.security = ap->security;
		entry.band = WIFI_FREQ_BAND_2_4_GHZ;

		d->scan_cb(d->iface, 0, &entry);
	}

	/* NULL entry => SCAN_DONE. */
	d->scan_cb(d->iface, 0, NULL);
}

static void connect_work_fn(struct k_work *work)
{
	struct fake_wifi_data *d = CONTAINER_OF(work, struct fake_wifi_data, connect_work);

	/* Track state deterministically: a failed connect after a successful one
	 * must leave iface_status reporting disconnected.
	 */
	d->connected = (d->next_conn == WIFI_STATUS_CONN_SUCCESS);
	wifi_mgmt_raise_connect_result_event(d->iface, (int)d->next_conn);
}

/* --- wifi_mgmt operations ------------------------------------------------- */

static int fake_scan(const struct device *dev, struct wifi_scan_params *params,
		     scan_result_cb_t cb)
{
	ARG_UNUSED(params);
	struct fake_wifi_data *d = dev->data;

	d->scan_cb = cb;
	k_work_submit(&d->scan_work);
	return 0;
}

static int fake_connect(const struct device *dev,
			struct wifi_connect_req_params *params)
{
	struct fake_wifi_data *d = dev->data;

	if (d->next_sync_err != 0) {
		int err = d->next_sync_err;

		d->next_sync_err = 0; /* one-shot */
		return -err;
	}

	d->conn_ssid_len = MIN(params->ssid_length, (uint8_t)WIFI_SSID_MAX_LEN);
	memcpy(d->conn_ssid, params->ssid, d->conn_ssid_len);
	d->conn_channel = (params->channel == WIFI_CHANNEL_ANY) ? 1 : params->channel;

	k_work_submit(&d->connect_work);
	return 0;
}

static int fake_disconnect(const struct device *dev)
{
	struct fake_wifi_data *d = dev->data;

	d->connected = false;
	wifi_mgmt_raise_disconnect_result_event(d->iface, 0);
	return 0;
}

static int fake_ap_enable(const struct device *dev,
			  struct wifi_connect_req_params *params)
{
	ARG_UNUSED(dev);
	ARG_UNUSED(params);
	return 0;
}

static int fake_ap_disable(const struct device *dev)
{
	ARG_UNUSED(dev);
	return 0;
}

static int fake_iface_status(const struct device *dev,
			     struct wifi_iface_status *status)
{
	struct fake_wifi_data *d = dev->data;

	if (!d->connected) {
		status->state = WIFI_STATE_DISCONNECTED;
		return 0;
	}

	status->state = WIFI_STATE_COMPLETED;
	status->ssid_len = d->conn_ssid_len;
	memcpy(status->ssid, d->conn_ssid, d->conn_ssid_len);
	memset(status->bssid, 0xAB, WIFI_MAC_ADDR_LEN);
	status->band = WIFI_FREQ_BAND_2_4_GHZ;
	status->channel = d->conn_channel;
	status->iface_mode = WIFI_MODE_INFRA;
	status->link_mode = WIFI_4;
	status->security = WIFI_SECURITY_TYPE_PSK;
	status->mfp = WIFI_MFP_OPTIONAL;
	return 0;
}

static const struct wifi_mgmt_ops fake_mgmt_ops = {
	.scan = fake_scan,
	.connect = fake_connect,
	.disconnect = fake_disconnect,
	.ap_enable = fake_ap_enable,
	.ap_disable = fake_ap_disable,
	.iface_status = fake_iface_status,
};

/* --- net_if / device registration ----------------------------------------
 *
 * Registered like the real Wi-Fi drivers (esp32, nrf_wifi): a native-networking
 * (CONFIG_WIFI_USE_NATIVE_NETWORKING) Ethernet-L2 device whose L2 context is
 * tagged L2_ETH_IF_TYPE_WIFI, which is how net_if_is_wifi() (hence
 * net_if_get_first_wifi()/net_if_get_wifi_sta()) recognises the interface.
 */

/* A fixed, locally-administered MAC for the fake station. */
static uint8_t fake_mac[WIFI_MAC_ADDR_LEN] = {0x02, 0x00, 0x5e, 0x00, 0x53, 0x01};

static void fake_iface_init(struct net_if *iface)
{
	struct ethernet_context *eth_ctx = net_if_l2_data(iface);

	fw_data.iface = iface;

	net_if_set_link_addr(iface, fake_mac, sizeof(fake_mac), NET_LINK_ETHERNET);
	eth_ctx->eth_if_type = L2_ETH_IF_TYPE_WIFI;
	ethernet_init(iface);

	/* Leave NET_IF_NO_AUTO_START clear: net_if_init() brings the interface
	 * administratively up after start-up, which is what the Wi-Fi L2 gates
	 * scan/connect on (wifi_scan() rejects with -ENETDOWN otherwise).
	 */
}

static enum ethernet_hw_caps fake_get_caps(const struct device *dev)
{
	ARG_UNUSED(dev);
	return 0;
}

static int fake_send(const struct device *dev, struct net_pkt *pkt)
{
	ARG_UNUSED(dev);
	ARG_UNUSED(pkt);
	/* No real link: silently drop. The provisioning flow never transmits
	 * data frames through this interface.
	 */
	return 0;
}

static const struct net_wifi_mgmt_offload fake_wifi_api = {
	.wifi_iface.iface_api.init = fake_iface_init,
	.wifi_iface.get_capabilities = fake_get_caps,
	.wifi_iface.send = fake_send,
	.wifi_mgmt_api = &fake_mgmt_ops,
};

static int fake_wifi_init(const struct device *dev)
{
	struct fake_wifi_data *d = dev->data;

	k_work_init(&d->scan_work, scan_work_fn);
	k_work_init(&d->connect_work, connect_work_fn);
	return 0;
}

ETH_NET_DEVICE_INIT(fake_wifi, "fake_wifi",
		    fake_wifi_init, NULL,
		    &fw_data, NULL,
		    CONFIG_ETH_INIT_PRIORITY,
		    &fake_wifi_api,
		    NET_ETH_MTU);
