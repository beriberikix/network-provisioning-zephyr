/*
 * DUT (device 0): the real provisioning manager + BLE GATT transport + fake
 * Wi-Fi backend. It programs the Wi-Fi outcome, starts BLE provisioning and
 * waits for the tester to drive it, passing when the manager reports the
 * expected credential result.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <errno.h>
#include <zephyr/kernel.h>
#include <zephyr/bluetooth/bluetooth.h>

#include "babblekit/testcase.h"

#include "network_provisioning/network_prov_mgr.h"
#include "network_provisioning/scheme_ble.h"
#include "network_provisioning/test/fake_wifi.h"

#include "common.h"

#define WAIT_TIME_S 30
#define WAIT_TIME   (WAIT_TIME_S * 1e6)

/* The credential event the DUT expects for the running scenario. */
static enum network_prov_cb_event expected_event;

static void prov_event(void *user_data, enum network_prov_cb_event event, void *event_data)
{
	ARG_UNUSED(user_data);
	ARG_UNUSED(event_data);

	switch (event) {
	case NETWORK_PROV_START:
		TEST_PRINT("DUT: provisioning started (advertising)");
		break;
	case NETWORK_PROV_CRED_RECV:
		TEST_PRINT("DUT: credentials received");
		break;
	case NETWORK_PROV_CRED_SUCCESS:
	case NETWORK_PROV_CRED_FAIL:
		if (event == expected_event) {
			TEST_PASS("DUT: got expected credential result (%d)", event);
		} else {
			TEST_FAIL("DUT: unexpected credential result %d (wanted %d)",
				  event, expected_event);
		}
		break;
	default:
		break;
	}
}

/* Echo handler for the custom endpoint: returns "echo:" + request. */
static int custom_echo(void *ctx, const uint8_t *inbuf, size_t inlen,
		       uint8_t **outbuf, size_t *outlen)
{
	ARG_UNUSED(ctx);
	static const char prefix[] = "echo:";
	size_t plen = sizeof(prefix) - 1;
	uint8_t *out = k_malloc(plen + inlen);

	if (out == NULL) {
		return -ENOMEM;
	}
	memcpy(out, prefix, plen);
	memcpy(out + plen, inbuf, inlen);
	*outbuf = out;
	*outlen = plen + inlen;
	return 0;
}

static void canned_scan_list(void)
{
	const struct fake_wifi_ap aps[] = {
		{ .ssid = PROV_TEST_SSID, .ssid_len = sizeof(PROV_TEST_SSID) - 1,
		  .channel = 6, .rssi = -42, .security = WIFI_SECURITY_TYPE_PSK,
		  .bssid = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55} },
		{ .ssid = "OpenCafe", .ssid_len = 8, .channel = 11, .rssi = -75,
		  .security = WIFI_SECURITY_TYPE_NONE,
		  .bssid = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff} },
	};

	fake_wifi_set_scan_aps(aps, ARRAY_SIZE(aps));
}

static void dut_run(enum wifi_conn_status connect_outcome,
		    enum network_prov_cb_event want)
{
	struct network_prov_mgr_config cfg = {
		.scheme = NETWORK_PROV_SCHEME_BLE,
		.app_event_handler = { .event_cb = prov_event },
		.wifi_conn_attempts = 0, /* single attempt: failures reported at once */
	};

	expected_event = want;

	fake_wifi_reset();
	canned_scan_list();
	fake_wifi_set_next_connect_result(connect_outcome);

	TEST_ASSERT(network_prov_mgr_init(cfg) == 0, "manager init failed");

	/* Tier-1 parity APIs under test: a custom BLE service UUID + mfg data
	 * (the tester verifies both) and an app-info section in proto-ver.
	 */
	static const uint8_t svc_uuid[16] = {PROV_TEST_SVC_UUID};
	static const uint8_t mfg[] = PROV_TEST_MFG_DATA;
	static const char *const app_caps[] = {PROV_TEST_APP_CAP};

	TEST_ASSERT(network_prov_scheme_ble_set_service_uuid(svc_uuid) == 0,
		    "set_service_uuid failed");
	TEST_ASSERT(network_prov_scheme_ble_set_mfg_data(mfg, sizeof(mfg)) == 0,
		    "set_mfg_data failed");
	TEST_ASSERT(network_prov_mgr_set_app_info(PROV_TEST_APP_LABEL, PROV_TEST_APP_VER,
						  app_caps, ARRAY_SIZE(app_caps)) == 0,
		    "set_app_info failed");

	/* Custom application endpoint (D1): created before start so it gets a
	 * GATT characteristic, handler registered after start.
	 */
	TEST_ASSERT(network_prov_mgr_endpoint_create(PROV_TEST_CUSTOM_EP) == 0,
		    "endpoint_create failed");

	TEST_ASSERT(network_prov_mgr_start_provisioning(NETWORK_PROV_SECURITY_1, PROV_TEST_POP,
							PROV_TEST_NAME, NULL) == 0,
		    "start_provisioning failed");

	TEST_ASSERT(network_prov_mgr_endpoint_register(PROV_TEST_CUSTOM_EP, custom_echo,
						       NULL) == 0,
		    "endpoint_register failed");

	/* The credential result arrives via prov_event(); keep the device (and
	 * the GATT link) alive so the tester can finish polling status.
	 */
	while (true) {
		k_sleep(K_SECONDS(1));
	}
}

static void dut_main_success(void)
{
	dut_run(WIFI_STATUS_CONN_SUCCESS, NETWORK_PROV_CRED_SUCCESS);
}

static void dut_main_wrong_password(void)
{
	dut_run(WIFI_STATUS_CONN_WRONG_PASSWORD, NETWORK_PROV_CRED_FAIL);
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
		.test_id = "dut_success",
		.test_descr = "Provision the DUT successfully over BLE",
		.test_pre_init_f = dut_init,
		.test_tick_f = dut_tick,
		.test_main_f = dut_main_success,
	},
	{
		.test_id = "dut_wrong_password",
		.test_descr = "DUT reports failure when the Wi-Fi password is wrong",
		.test_pre_init_f = dut_init,
		.test_tick_f = dut_tick,
		.test_main_f = dut_main_wrong_password,
	},
	BSTEST_END_MARKER,
};

struct bst_test_list *dut_install(struct bst_test_list *tests)
{
	return bst_add_tests(tests, dut_tests);
}
