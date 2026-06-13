/*
 * Unit test for the fake (simulated) Wi-Fi offload backend (sim/wifi/fake_wifi.c).
 *
 * Drives the backend through the public Wi-Fi management API exactly as the
 * provisioning Wi-Fi handlers do — net_if_get_first_wifi(), NET_REQUEST_WIFI_SCAN,
 * NET_REQUEST_WIFI_CONNECT, NET_REQUEST_WIFI_IFACE_STATUS — and asserts the
 * programmed canned results and failure injection come back through the
 * net_mgmt event layer. This guards the foundation the BabbleSim BLE E2E test
 * and the full manager build on.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/ztest.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/wifi_mgmt.h>

#include "network_provisioning/test/fake_wifi.h"

#define WIFI_MGMT_EVENTS                                                                   \
	(NET_EVENT_WIFI_SCAN_RESULT | NET_EVENT_WIFI_SCAN_DONE |                            \
	 NET_EVENT_WIFI_CONNECT_RESULT)

static struct net_mgmt_event_callback cb;

static struct {
	size_t scan_results;
	bool scan_done;
	int scan_done_status;
	bool connect_result;
	int connect_status;
	char last_ssid[WIFI_SSID_MAX_LEN + 1];
	uint8_t last_ssid_len;
	struct k_sem scan_done_sem;
	struct k_sem connect_sem;
} ev;

static void mgmt_handler(struct net_mgmt_event_callback *c, uint64_t event,
			 struct net_if *iface)
{
	ARG_UNUSED(iface);
	switch (event) {
	case NET_EVENT_WIFI_SCAN_RESULT: {
		const struct wifi_scan_result *r = c->info;

		ev.scan_results++;
		ev.last_ssid_len = MIN(r->ssid_length, (uint8_t)WIFI_SSID_MAX_LEN);
		memcpy(ev.last_ssid, r->ssid, ev.last_ssid_len);
		ev.last_ssid[ev.last_ssid_len] = '\0';
		break;
	}
	case NET_EVENT_WIFI_SCAN_DONE: {
		const struct wifi_status *s = c->info;

		ev.scan_done = true;
		ev.scan_done_status = s->status;
		k_sem_give(&ev.scan_done_sem);
		break;
	}
	case NET_EVENT_WIFI_CONNECT_RESULT: {
		const struct wifi_status *s = c->info;

		ev.connect_result = true;
		ev.connect_status = s->status;
		k_sem_give(&ev.connect_sem);
		break;
	}
	default:
		break;
	}
}

static struct net_if *wifi_iface(void)
{
	struct net_if *iface = net_if_get_first_wifi();

	zassert_not_null(iface, "fake Wi-Fi interface not registered");
	return iface;
}

static int do_connect(const char *ssid)
{
	struct wifi_connect_req_params params = {
		.ssid = (const uint8_t *)ssid,
		.ssid_length = strlen(ssid),
		.channel = WIFI_CHANNEL_ANY,
		.security = WIFI_SECURITY_TYPE_PSK,
		.psk = (const uint8_t *)"password123",
		.psk_length = 11,
		.band = WIFI_FREQ_BAND_UNKNOWN,
		.mfp = WIFI_MFP_OPTIONAL,
		.timeout = SYS_FOREVER_MS,
	};

	return net_mgmt(NET_REQUEST_WIFI_CONNECT, wifi_iface(), &params, sizeof(params));
}

static void before(void *unused)
{
	ARG_UNUSED(unused);
	memset(&ev, 0, sizeof(ev));
	k_sem_init(&ev.scan_done_sem, 0, 1);
	k_sem_init(&ev.connect_sem, 0, 1);
	fake_wifi_reset();
}

ZTEST(fake_wifi, test_scan_reports_canned_aps)
{
	const struct fake_wifi_ap aps[] = {
		{ .ssid = "HomeNet", .ssid_len = 7, .channel = 6, .rssi = -40,
		  .security = WIFI_SECURITY_TYPE_PSK,
		  .bssid = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55} },
		{ .ssid = "Cafe", .ssid_len = 4, .channel = 11, .rssi = -70,
		  .security = WIFI_SECURITY_TYPE_NONE,
		  .bssid = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff} },
	};

	fake_wifi_set_scan_aps(aps, ARRAY_SIZE(aps));

	zassert_equal(net_mgmt(NET_REQUEST_WIFI_SCAN, wifi_iface(), NULL, 0), 0,
		      "scan request rejected");
	zassert_equal(k_sem_take(&ev.scan_done_sem, K_SECONDS(2)), 0, "no SCAN_DONE");

	zassert_equal(ev.scan_results, ARRAY_SIZE(aps), "wrong number of scan results");
	zassert_equal(ev.scan_done_status, 0);
}

ZTEST(fake_wifi, test_empty_scan)
{
	zassert_equal(net_mgmt(NET_REQUEST_WIFI_SCAN, wifi_iface(), NULL, 0), 0);
	zassert_equal(k_sem_take(&ev.scan_done_sem, K_SECONDS(2)), 0, "no SCAN_DONE");
	zassert_equal(ev.scan_results, 0);
}

ZTEST(fake_wifi, test_connect_success)
{
	fake_wifi_set_next_connect_result(WIFI_STATUS_CONN_SUCCESS);

	zassert_equal(do_connect("HomeNet"), 0, "connect request rejected");
	zassert_equal(k_sem_take(&ev.connect_sem, K_SECONDS(2)), 0, "no CONNECT_RESULT");
	zassert_equal(ev.connect_status, 0, "connect should have succeeded");

	/* iface_status must now echo the connected SSID. */
	struct wifi_iface_status status = {0};

	zassert_equal(net_mgmt(NET_REQUEST_WIFI_IFACE_STATUS, wifi_iface(), &status,
			       sizeof(status)), 0);
	zassert_equal(status.state, WIFI_STATE_COMPLETED);
	zassert_equal(status.ssid_len, 7);
	zassert_mem_equal(status.ssid, "HomeNet", 7);
}

ZTEST(fake_wifi, test_connect_wrong_password)
{
	fake_wifi_set_next_connect_result(WIFI_STATUS_CONN_WRONG_PASSWORD);

	zassert_equal(do_connect("HomeNet"), 0);
	zassert_equal(k_sem_take(&ev.connect_sem, K_SECONDS(2)), 0, "no CONNECT_RESULT");
	zassert_equal(ev.connect_status, WIFI_STATUS_CONN_WRONG_PASSWORD,
		      "wrong-password conn_status not reported");
}

ZTEST(fake_wifi, test_connect_ap_not_found)
{
	fake_wifi_set_next_connect_result(WIFI_STATUS_CONN_AP_NOT_FOUND);

	zassert_equal(do_connect("Ghost"), 0);
	zassert_equal(k_sem_take(&ev.connect_sem, K_SECONDS(2)), 0, "no CONNECT_RESULT");
	zassert_equal(ev.connect_status, WIFI_STATUS_CONN_AP_NOT_FOUND);
}

ZTEST(fake_wifi, test_connect_sync_error)
{
	fake_wifi_set_next_connect_sync_error(EINVAL);

	/* The request must be rejected synchronously, with no async result. */
	zassert_equal(do_connect("HomeNet"), -EINVAL, "sync error not surfaced");
	zassert_equal(k_sem_take(&ev.connect_sem, K_MSEC(200)), -EAGAIN,
		      "unexpected async result after sync error");

	/* One-shot: the next attempt succeeds. */
	fake_wifi_set_next_connect_result(WIFI_STATUS_CONN_SUCCESS);
	zassert_equal(do_connect("HomeNet"), 0);
	zassert_equal(k_sem_take(&ev.connect_sem, K_SECONDS(2)), 0);
	zassert_equal(ev.connect_status, 0);
}

static void *suite_setup(void)
{
	net_mgmt_init_event_callback(&cb, mgmt_handler, WIFI_MGMT_EVENTS);
	net_mgmt_add_event_callback(&cb);
	return NULL;
}

ZTEST_SUITE(fake_wifi, NULL, suite_setup, before, NULL, NULL);
