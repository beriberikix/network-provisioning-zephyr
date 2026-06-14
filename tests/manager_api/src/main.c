/*
 * Manager C-API tests for the Tier-1 parity additions: auto-stop /
 * disable_auto_stop / is_sm_idle (E1) and the programmatic
 * configure_wifi_sta + state-reset wrappers (E2). Also covers the
 * credential-store and synchronisation helpers: is_provisioned /
 * reset_wifi_provisioning, get_wifi_remaining_conn_attempts and wait().
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
#include "network_provisioning/scheme_softap.h"
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
		.scheme = &network_prov_scheme_softap,
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
		.scheme = &network_prov_scheme_softap,
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

static int dummy_handler(void *ctx, const uint8_t *in, size_t inlen,
			 uint8_t **out, size_t *outlen)
{
	ARG_UNUSED(ctx);
	ARG_UNUSED(in);
	ARG_UNUSED(inlen);
	ARG_UNUSED(out);
	ARG_UNUSED(outlen);
	return 0;
}

ZTEST(manager_api, test_custom_endpoint_api)
{
	struct network_prov_mgr_config cfg = {
		.scheme = &network_prov_scheme_softap,
		.app_event_handler = { .event_cb = evt },
		.wifi_conn_attempts = 0,
	};

	memset(&t, 0, sizeof(t));
	k_sem_init(&t.ev, 0, 4);
	fake_wifi_reset();
	program_network();
	zassert_equal(network_prov_mgr_init(cfg), 0);

	/* Before start: create succeeds; duplicates, built-in collisions and
	 * over-long names are rejected; register requires the service started.
	 */
	zassert_equal(network_prov_mgr_endpoint_create("my-ep"), 0);
	zassert_equal(network_prov_mgr_endpoint_create("my-ep"), -EALREADY);
	zassert_equal(network_prov_mgr_endpoint_create("prov-scan"), -EALREADY);
	zassert_equal(network_prov_mgr_endpoint_create("0123456789abcdef"), -EINVAL);
	zassert_equal(network_prov_mgr_endpoint_register("my-ep", dummy_handler, NULL),
		      -EPERM);

	zassert_equal(network_prov_mgr_start_provisioning(NETWORK_PROV_SECURITY_1,
							  "abcd1234", "PROV_T", NULL), 0);

	/* After start: no new endpoints; register the created one; unknown name
	 * and unregister report as expected.
	 */
	zassert_equal(network_prov_mgr_endpoint_create("late"), -EPERM);
	zassert_equal(network_prov_mgr_endpoint_register("my-ep", dummy_handler, NULL), 0);
	zassert_equal(network_prov_mgr_endpoint_register("nope", dummy_handler, NULL),
		      -ENOENT);
	zassert_equal(network_prov_mgr_endpoint_unregister("my-ep"), 0);
	zassert_equal(network_prov_mgr_endpoint_unregister("nope"), -ENOENT);

	network_prov_mgr_stop_provisioning();
	network_prov_mgr_deinit();
}

ZTEST(manager_api, test_is_provisioned_and_reset)
{
	bool prov = true;

	/* Guards: NULL arg is rejected; reset requires an initialised manager. */
	zassert_equal(network_prov_mgr_is_provisioned(NULL), -EINVAL);
	zassert_equal(network_prov_mgr_reset_wifi_provisioning(), -EPERM,
		      "reset must require an initialised manager");

	start_mgr();

	/* Clean baseline: an earlier test may have left credentials in the
	 * native_sim flash-backed wifi_credentials store.
	 */
	zassert_equal(network_prov_mgr_reset_wifi_provisioning(), 0);
	zassert_equal(network_prov_mgr_is_provisioned(&prov), 0);
	zassert_false(prov, "should be unprovisioned after erase");

	/* A successful credential apply persists to the wifi_credentials store. */
	zassert_equal(network_prov_mgr_configure_wifi_sta(GOOD_SSID, GOOD_PASS), 0);
	zassert_equal(k_sem_take(&t.ev, K_SECONDS(2)), 0, "no result event");
	zassert_true(t.success, "expected CRED_SUCCESS");
	zassert_equal(network_prov_mgr_is_provisioned(&prov), 0);
	zassert_true(prov, "should report provisioned after success");

	/* The explicit factory-reset path erases them again. */
	zassert_equal(network_prov_mgr_reset_wifi_provisioning(), 0);
	zassert_equal(network_prov_mgr_is_provisioned(&prov), 0);
	zassert_false(prov, "should be unprovisioned after factory reset");

	network_prov_mgr_stop_provisioning();
	network_prov_mgr_deinit();
}

ZTEST(manager_api, test_remaining_conn_attempts)
{
	struct network_prov_mgr_config cfg = {
		.scheme = &network_prov_scheme_softap,
		.app_event_handler = { .event_cb = evt },
		.wifi_conn_attempts = 2,
	};
	uint32_t remaining = 0;

	/* Not started yet: the query is rejected. */
	zassert_equal(network_prov_mgr_get_wifi_remaining_conn_attempts(&remaining),
		      -EINVAL, "query must require an active service");

	memset(&t, 0, sizeof(t));
	k_sem_init(&t.ev, 0, 4);
	fake_wifi_reset();
	program_network();

	zassert_equal(network_prov_mgr_init(cfg), 0);
	zassert_equal(network_prov_mgr_start_provisioning(NETWORK_PROV_SECURITY_1,
							  "abcd1234", "PROV_T", NULL), 0);

	/* NULL out-pointer is rejected even when active. */
	zassert_equal(network_prov_mgr_get_wifi_remaining_conn_attempts(NULL), -EINVAL);

	/* Before any connect attempt: the full budget is available. */
	zassert_equal(network_prov_mgr_get_wifi_remaining_conn_attempts(&remaining), 0);
	zassert_equal(remaining, 2, "expected the full attempt budget");

	/* A wrong password burns both attempts (one initial + one retry) before
	 * the final CRED_FAIL, leaving zero remaining.
	 */
	zassert_equal(network_prov_mgr_configure_wifi_sta(GOOD_SSID, "wrongpassword"), 0);
	zassert_equal(k_sem_take(&t.ev, K_SECONDS(5)), 0, "no CRED_FAIL after retries");
	zassert_true(t.fail, "expected CRED_FAIL");
	zassert_equal(network_prov_mgr_get_wifi_remaining_conn_attempts(&remaining), 0);
	zassert_equal(remaining, 0, "attempts must be exhausted after final failure");

	network_prov_mgr_stop_provisioning();
	network_prov_mgr_deinit();
}

/* Applies good credentials from a separate thread so the main test thread can
 * block in network_prov_mgr_wait() first.
 */
K_THREAD_STACK_DEFINE(apply_stack, 2048);
static struct k_thread apply_thread;

static void apply_creds_fn(void *a, void *b, void *c)
{
	ARG_UNUSED(a);
	ARG_UNUSED(b);
	ARG_UNUSED(c);
	k_sleep(K_MSEC(100));
	(void)network_prov_mgr_configure_wifi_sta(GOOD_SSID, GOOD_PASS);
}

ZTEST(manager_api, test_wait_unblocks_on_success)
{
	start_mgr();

	k_thread_create(&apply_thread, apply_stack, K_THREAD_STACK_SIZEOF(apply_stack),
			apply_creds_fn, NULL, NULL, NULL,
			K_PRIO_PREEMPT(5), 0, K_NO_WAIT);

	/* Blocks until the apply path emits NETWORK_PROV_CRED_SUCCESS. */
	network_prov_mgr_wait();
	zassert_true(t.success, "wait() returned before CRED_SUCCESS");

	zassert_equal(k_thread_join(&apply_thread, K_SECONDS(2)), 0);
	network_prov_mgr_stop_provisioning();
	network_prov_mgr_deinit();
}

ZTEST_SUITE(manager_api, NULL, NULL, NULL, NULL, NULL);
