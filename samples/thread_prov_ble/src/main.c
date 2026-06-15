/*
 * Thread provisioning over BLE sample.
 *
 * Advertises a "PROV_..." BLE peripheral that the stock ESP provisioning apps
 * connect to in order to hand over a Thread Active Operational Dataset. The
 * dataset is applied through OpenThread and persists in its settings store, so
 * on reboot the device attaches with the stored dataset instead of advertising.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <openthread.h> /* openthread_run() — start with the stored dataset */

#include <network_provisioning/network_prov_mgr.h>
#include <network_provisioning/scheme_ble.h>

LOG_MODULE_REGISTER(app, LOG_LEVEL_INF);

/* Proof-of-possession the app must enter to complete the security-1 handshake.
 * Set to an empty string to advertise the "no_pop" capability instead.
 */
#define PROV_POP         "abcd1234"
#define PROV_DEVICE_NAME CONFIG_BT_DEVICE_NAME

static void prov_event(void *user_data, enum network_prov_cb_event event,
		       void *event_data)
{
	ARG_UNUSED(user_data);
	ARG_UNUSED(event_data);

	switch (event) {
	case NETWORK_PROV_START:
		LOG_INF("Provisioning started; connect with the ESP provisioning app");
		LOG_INF("  device name : %s", PROV_DEVICE_NAME);
		LOG_INF("  proof-of-pos: %s", PROV_POP[0] ? PROV_POP : "(none)");
		break;
	case NETWORK_PROV_CRED_RECV:
		LOG_INF("Thread dataset received, attaching...");
		break;
	case NETWORK_PROV_CRED_FAIL:
		LOG_ERR("Provisioning failed; check the dataset and retry");
		break;
	case NETWORK_PROV_CRED_SUCCESS:
		LOG_INF("Provisioning successful, Thread attached");
		break;
	case NETWORK_PROV_END:
		LOG_INF("Provisioning finished");
		break;
	default:
		break;
	}
}

/* Run one full provisioning cycle: advertise, wait for the dataset and a
 * successful attach, give the app time to read the final status, then stop.
 */
static int run_provisioning(void)
{
	int ret = network_prov_mgr_start_provisioning(NETWORK_PROV_SECURITY_1,
						      PROV_POP, PROV_DEVICE_NAME,
						      NULL);
	if (ret != 0) {
		LOG_ERR("Failed to start provisioning: %d", ret);
		return ret;
	}

	/* Block until the device attaches with the supplied dataset. The manager
	 * auto-stops the BLE service a grace period after success
	 * (CONFIG_NETWORK_PROV_AUTOSTOP_TIMEOUT_MS) so the app can still poll
	 * GetThreadStatus before the GATT service goes away.
	 */
	network_prov_mgr_wait();
	LOG_INF("Provisioning complete");
	return 0;
}

int main(void)
{
	struct network_prov_mgr_config config = {
		.scheme = &network_prov_scheme_ble,
		.app_event_handler = {
			.event_cb = prov_event,
			.user_data = NULL,
		},
	};

	int ret = network_prov_mgr_init(config);

	if (ret != 0) {
		LOG_ERR("Manager init failed: %d", ret);
		return 0;
	}

	static const char *const app_caps[] = {"sample"};

	(void)network_prov_mgr_set_app_info("thread_prov_ble", "1.0", app_caps,
					    ARRAY_SIZE(app_caps));

	bool provisioned = false;

	network_prov_mgr_is_provisioned(&provisioned);

	if (provisioned) {
		/* A dataset is already committed: bring Thread up with it
		 * (CONFIG_OPENTHREAD_MANUAL_START leaves the start to us).
		 */
		LOG_INF("Device already provisioned, attaching with the stored dataset");
		(void)openthread_run();
		return 0;
	}

	LOG_INF("Device not provisioned, starting BLE provisioning for Thread");
	(void)run_provisioning();
	return 0;
}
