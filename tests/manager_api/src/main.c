/*
 * Manager C-API tests for the Tier-1 parity additions: auto-stop /
 * disable_auto_stop / is_sm_idle (E1) and the programmatic
 * configure_wifi_sta + state-reset wrappers (E2).
 *
 * Runs the real manager over the SoftAP transport on native_sim, backed by the
 * fake Wi-Fi driver (credential-matching mode), so the connect/retry/event path
 * runs without hardware or a network client. CONFIG_NETWORK_PROV_AUTOSTOP_TIMEOUT_MS
 * is set very short by the test prj.conf so the auto-stop fires promptly.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <errno.h>
#include <zephyr/kernel.h>
#include <zephyr/ztest.h>

#include "network_provisioning/network_prov_mgr.h"
#include "network_provisioning/test/fake_wifi.h"

#define GOOD_SSID "HomeNet"
#define GOOD_PASS "goodpassword"

static struct {
	bool recv, success, fail, end;
	struct k_sem ev;
} t;

static void evt(void *user_data, enum network_prov_cb_event event, void *event_data)
{
	ARG_UNUSED(user_data);
	ARG_UNUSED(event_data);

	switch (event) {
	case NETWORK_PROV_CRED_RECV:
		t.recv = true;
		break;
	case NETWORK_PROV_CRED_SUCCESS:
		t.success = true;
		k_sem_give(&t.ev);
		break;
	case NETWORK_PROV_CRED_FAIL:
		t.fail = true;
		k_sem_give(&t.ev);
		break;
	case NETWORK_PROV_END:
		t.end = true;
		k_sem_give(&t.ev);
		break;
	default:
		break;
	}
}

static void program_network(void)
{
	const struct fake_wifi_ap aps[] = {
		{ .ssid = GOOD_SSID, .ssid_len = sizeof(GOOD_SSID) - 1, .channel = 6,
		  .rssi = -40, .security = WIFI_SECURITY_TYPE_PSK,
		  .bssid = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55} },
	};

	fake_wifi_set_scan_aps(aps, ARRAY_SIZE(aps));
	fake_wifi_set_expected_credentials(GOOD_SSID, GOOD_PASS);
}

static void start_mgr(void)
{
	struct network_prov_mgr_config cfg = {
		.scheme = NETWORK_PROV_SCHEME_SOFTAP,
		.app_event_handler = { .event_cb = evt },
		.wifi_conn_attempts = 0,
	};

	memset(&t, 0, sizeof(t));
	t.ev = (struct k_sem){0};
	k_sem_init(&t.ev, 0, 4);
	fake_wifi_reset();
	program_network();

	zassert_equal(network_prov_mgr_init(cfg), 0, "init failed");
	zassert_equal(network_prov_mgr_start_provisioning(NETWORK_PROV_SECURITY_1,
							  "abcd1234", "PROV_T", NULL),
		      0, "start failed");
}

ZTEST(manager_api, test_configure_wifi_sta_success_then_auto_stop)
{
	start_mgr();
	zassert_false(network_prov_mgr_is_sm_idle(), "should be active after start");

	zassert_equal(network_prov_mgr_configure_wifi_sta(GOOD_SSID, GOOD_PASS), 0,
		      "configure_wifi_sta failed");
	zassert_equal(k_sem_take(&t.ev, K_SECONDS(2)), 0, "no result event");
	zassert_true(t.success, "expected CRED_SUCCESS");
	zassert_true(t.recv, "expected CRED_RECV before success");

	/* Auto-stop (default on) tears the service down after the short grace
	 * window configured for the test; END fires and the SM goes idle.
	 */
	zassert_equal(k_sem_take(&t.ev, K_SECONDS(2)), 0, "auto-stop END not seen");
	zassert_true(t.end, "expected NETWORK_PROV_END from auto-stop");
	zassert_true(network_prov_mgr_is_sm_idle(), "SM should be idle after auto-stop");

	network_prov_mgr_deinit();
}

ZTEST(manager_api, test_configure_wifi_sta_wrong_password)
{
	start_mgr();

	zassert_equal(network_prov_mgr_configure_wifi_sta(GOOD_SSID, "wrongpassword"), 0,
		      "configure_wifi_sta failed");
	zassert_equal(k_sem_take(&t.ev, K_SECONDS(2)), 0, "no result event");
	zassert_true(t.fail, "expected CRED_FAIL for a wrong password");
	zassert_false(t.success, "must not report success");

	network_prov_mgr_stop_provisioning();
	network_prov_mgr_deinit();
}

ZTEST(manager_api, test_disable_auto_stop_keeps_service_up)
{
	struct network_prov_mgr_config cfg = {
		.scheme = NETWORK_PROV_SCHEME_SOFTAP,
		.app_event_handler = { .event_cb = evt },
		.wifi_conn_attempts = 0,
	};

	memset(&t, 0, sizeof(t));
	k_sem_init(&t.ev, 0, 4);
	fake_wifi_reset();
	program_network();

	zassert_equal(network_prov_mgr_init(cfg), 0);
	zassert_equal(network_prov_mgr_disable_auto_stop(0), 0, "disable_auto_stop failed");
	zassert_equal(network_prov_mgr_start_provisioning(NETWORK_PROV_SECURITY_1,
							  "abcd1234", "PROV_T", NULL), 0);

	zassert_equal(network_prov_mgr_configure_wifi_sta(GOOD_SSID, GOOD_PASS), 0);
	zassert_equal(k_sem_take(&t.ev, K_SECONDS(2)), 0, "no result event");
	zassert_true(t.success);

	/* Past the auto-stop window: with auto-stop disabled it must NOT fire. */
	k_sleep(K_MSEC(600));
	zassert_false(t.end, "auto-stop should be disabled");
	zassert_false(network_prov_mgr_is_sm_idle(), "service should still be up");

	network_prov_mgr_stop_provisioning();
	zassert_true(network_prov_mgr_is_sm_idle(), "idle after explicit stop");
	network_prov_mgr_deinit();
}

ZTEST(manager_api, test_reset_wrappers_require_active)
{
	/* Not started yet. */
	zassert_equal(network_prov_mgr_reset_wifi_sm_state_on_failure(), -EPERM);
	zassert_equal(network_prov_mgr_reset_wifi_sm_state_for_reprovision(), -EPERM);
	zassert_equal(network_prov_mgr_configure_wifi_sta(GOOD_SSID, GOOD_PASS), -EPERM);

	start_mgr();
	zassert_equal(network_prov_mgr_reset_wifi_sm_state_on_failure(), 0);
	zassert_equal(network_prov_mgr_reset_wifi_sm_state_for_reprovision(), 0);
	zassert_equal(network_prov_mgr_configure_wifi_sta(NULL, NULL), -EINVAL);

	network_prov_mgr_stop_provisioning();
	network_prov_mgr_deinit();
}

ZTEST_SUITE(manager_api, NULL, NULL, NULL, NULL, NULL);
