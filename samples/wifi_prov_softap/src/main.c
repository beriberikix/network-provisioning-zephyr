/*
 * Wi-Fi provisioning over SoftAP (HTTP) sample.
 *
 * Hosts a "PROV_..." access point; the stock ESP SoftAP Provisioning apps
 * (or esp_prov.py --transport softap) join it and configure Wi-Fi credentials
 * over HTTP at 192.168.4.1. On reboot, if credentials are already stored, it
 * connects with them instead — retrying with backoff and falling back to
 * provisioning mode (credentials kept) if the network stays unreachable.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/wifi_credentials.h>

#include <network_provisioning/network_prov_mgr.h>

LOG_MODULE_REGISTER(app, LOG_LEVEL_INF);

/* Proof-of-possession the app must enter to complete the security-1 handshake.
 * Set to an empty string to advertise the "no_pop" capability instead.
 */
#define PROV_POP          "abcd1234"
/* SSID of the provisioning access point. The stock apps filter on "PROV_". */
#define PROV_SERVICE_NAME "PROV_ZEPHYR"
/* AP password (8..64 characters for WPA2-PSK) or NULL for an open AP. */
#define PROV_SERVICE_KEY  NULL

/* Stored-credential reconnect policy (reboot path); see the BLE sample. */
#define SAVED_CONN_ATTEMPTS    5
#define SAVED_CONN_TIMEOUT     K_SECONDS(45)
#define SAVED_CONN_BACKOFF_MAX 16 /* seconds */

static void prov_event(void *user_data, enum network_prov_cb_event event,
		       void *event_data)
{
	ARG_UNUSED(user_data);

	switch (event) {
	case NETWORK_PROV_START:
		LOG_INF("Provisioning started; join the AP and open the ESP "
			"SoftAP Provisioning app");
		LOG_INF("  AP SSID     : %s", PROV_SERVICE_NAME);
		LOG_INF("  proof-of-pos: %s", PROV_POP[0] ? PROV_POP : "(none)");
		break;
	case NETWORK_PROV_CRED_RECV:
		LOG_INF("Wi-Fi credentials received, connecting...");
		break;
	case NETWORK_PROV_CRED_FAIL:
		LOG_ERR("Provisioning failed; check the SSID/passphrase and retry");
		break;
	case NETWORK_PROV_CRED_SUCCESS:
		LOG_INF("Provisioning successful, Wi-Fi connected");
		break;
	case NETWORK_PROV_END:
		LOG_INF("Provisioning finished");
		break;
	default:
		break;
	}
}

/* Connect-result plumbing for the stored-credential (reboot) path. */
static K_SEM_DEFINE(conn_result_sem, 0, 1);
static int conn_result_status;
static struct net_mgmt_event_callback conn_cb;

static void conn_mgmt_event(struct net_mgmt_event_callback *cb, uint64_t event,
			    struct net_if *iface)
{
	ARG_UNUSED(iface);

	if (event == NET_EVENT_WIFI_CONNECT_RESULT) {
		const struct wifi_status *status =
			(const struct wifi_status *)cb->info;

		/* status and conn_status alias each other in the wifi_status
		 * union: 0 means success, nonzero is the failure reason.
		 */
		conn_result_status = status->status;
		k_sem_give(&conn_result_sem);
	}
}

struct saved_ssid {
	char ssid[WIFI_SSID_MAX_LEN + 1];
	size_t len;
	bool found;
};

static void pick_ssid(void *arg, const char *ssid, size_t ssid_len)
{
	struct saved_ssid *s = arg;

	if (s->found) {
		return;
	}
	s->len = MIN(ssid_len, sizeof(s->ssid) - 1);
	memcpy(s->ssid, ssid, s->len);
	s->ssid[s->len] = '\0';
	s->found = true;
}

static int connect_saved_once(void)
{
	struct saved_ssid s = {0};

	wifi_credentials_for_each_ssid(pick_ssid, &s);
	if (!s.found) {
		return -ENOENT;
	}

	enum wifi_security_type type;
	uint8_t bssid[WIFI_MAC_ADDR_LEN];
	char password[WIFI_CREDENTIALS_MAX_PASSWORD_LEN];
	size_t password_len = 0;
	uint32_t flags = 0;
	uint8_t channel = 0;
	uint32_t timeout = 0;

	int ret = wifi_credentials_get_by_ssid_personal(
		s.ssid, s.len, &type, bssid, sizeof(bssid), password,
		sizeof(password), &password_len, &flags, &channel, &timeout);
	if (ret != 0) {
		LOG_ERR("Failed to read stored credentials: %d", ret);
		return ret;
	}

	struct net_if *iface = net_if_get_wifi_sta();

	if (iface == NULL) {
		iface = net_if_get_first_wifi();
	}

	struct wifi_connect_req_params params = {0};

	params.ssid = (const uint8_t *)s.ssid;
	params.ssid_length = s.len;
	params.psk = (password_len > 0) ? (const uint8_t *)password : NULL;
	params.psk_length = password_len;
	params.security = type;
	params.channel = (channel > 0) ? channel : WIFI_CHANNEL_ANY;
	params.band = WIFI_FREQ_BAND_UNKNOWN;
	params.mfp = WIFI_MFP_OPTIONAL;
	params.timeout = SYS_FOREVER_MS;
	if (flags & WIFI_CREDENTIALS_FLAG_BSSID) {
		memcpy(params.bssid, bssid, WIFI_MAC_ADDR_LEN);
	}

	k_sem_reset(&conn_result_sem);

	ret = net_mgmt(NET_REQUEST_WIFI_CONNECT, iface, &params, sizeof(params));
	if (ret != 0) {
		LOG_ERR("Connect request failed: %d", ret);
		return ret;
	}

	if (k_sem_take(&conn_result_sem, SAVED_CONN_TIMEOUT) != 0) {
		LOG_WRN("Connect attempt timed out");
		return -ETIMEDOUT;
	}
	if (conn_result_status != 0) {
		LOG_WRN("Connect failed (conn_status %d)", conn_result_status);
		return -EIO;
	}
	return 0;
}

static bool connect_saved(void)
{
	bool connected = false;
	int backoff = 2;

	net_mgmt_init_event_callback(&conn_cb, conn_mgmt_event,
				     NET_EVENT_WIFI_CONNECT_RESULT);
	net_mgmt_add_event_callback(&conn_cb);

	for (int attempt = 1; attempt <= SAVED_CONN_ATTEMPTS; attempt++) {
		LOG_INF("Connecting with stored credentials (attempt %d/%d)",
			attempt, SAVED_CONN_ATTEMPTS);

		int ret = connect_saved_once();

		if (ret == 0) {
			LOG_INF("Wi-Fi connected (stored credentials)");
			connected = true;
			break;
		}
		if (ret == -ENOENT) {
			LOG_ERR("Stored credentials disappeared");
			break;
		}
		if (attempt < SAVED_CONN_ATTEMPTS) {
			LOG_INF("Retrying in %d s", backoff);
			k_sleep(K_SECONDS(backoff));
			backoff = MIN(backoff * 2, SAVED_CONN_BACKOFF_MAX);
		}
	}

	net_mgmt_del_event_callback(&conn_cb);
	return connected;
}

static int run_provisioning(void)
{
	int ret = network_prov_mgr_start_provisioning(NETWORK_PROV_SECURITY_1,
						      PROV_POP, PROV_SERVICE_NAME,
						      PROV_SERVICE_KEY);
	if (ret != 0) {
		LOG_ERR("Failed to start provisioning: %d", ret);
		return ret;
	}

	/* Block until the device connects with the supplied credentials. */
	network_prov_mgr_wait();

	/* The manager auto-stops the service a grace period after success
	 * (CONFIG_NETWORK_PROV_AUTOSTOP_TIMEOUT_MS), so the app still has time
	 * to poll GetWifiStatus over the AP before it is torn down.
	 */
	LOG_INF("Provisioning complete");
	return 0;
}

int main(void)
{
	struct network_prov_mgr_config config = {
		.scheme = NETWORK_PROV_SCHEME_SOFTAP,
		.app_event_handler = {
			.event_cb = prov_event,
			.user_data = NULL,
		},
		/* Retry transient connect failures before reporting back to
		 * the app (upstream example default).
		 */
		.wifi_conn_attempts = 5,
	};

	int ret = network_prov_mgr_init(config);

	if (ret != 0) {
		LOG_ERR("Manager init failed: %d", ret);
		return 0;
	}

	bool provisioned = false;

	network_prov_mgr_is_provisioned(&provisioned);

	if (provisioned) {
		LOG_INF("Device already provisioned");
		if (connect_saved()) {
			return 0;
		}
		LOG_WRN("Stored credentials did not connect; starting "
			"provisioning (credentials kept for next boot)");
	} else {
		LOG_INF("Device not provisioned, starting SoftAP provisioning");
	}

	(void)run_provisioning();
	return 0;
}
