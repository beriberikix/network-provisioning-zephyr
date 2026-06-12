/*
 * Wi-Fi provisioning over BLE sample.
 *
 * Advertises a "PROV_..." BLE peripheral that the stock ESP BLE Provisioning
 * apps can connect to in order to configure Wi-Fi credentials. On reboot, if
 * credentials are already stored, it connects with them instead of advertising.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/wifi_credentials.h>

#include <network_provisioning/network_prov_mgr.h>

LOG_MODULE_REGISTER(app, LOG_LEVEL_INF);

/* Proof-of-possession the app must enter to complete the security-1 handshake.
 * Set to an empty string to advertise the "no_pop" capability instead.
 */
#define PROV_POP          "abcd1234"
#define PROV_DEVICE_NAME  CONFIG_BT_DEVICE_NAME

static void prov_event(void *user_data, enum network_prov_cb_event event,
		       void *event_data)
{
	ARG_UNUSED(user_data);

	switch (event) {
	case NETWORK_PROV_START:
		LOG_INF("Provisioning started; connect with the ESP provisioning app");
		LOG_INF("  device name : %s", PROV_DEVICE_NAME);
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

static void connect_saved(void)
{
	struct saved_ssid s = {0};

	wifi_credentials_for_each_ssid(pick_ssid, &s);
	if (!s.found) {
		return;
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
		return;
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

	LOG_INF("Connecting with stored credentials for '%s'", s.ssid);
	ret = net_mgmt(NET_REQUEST_WIFI_CONNECT, iface, &params, sizeof(params));
	if (ret != 0) {
		LOG_ERR("Connect request failed: %d", ret);
	}
}

int main(void)
{
	struct network_prov_mgr_config config = {
		.scheme = NETWORK_PROV_SCHEME_BLE,
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

	bool provisioned = false;

	network_prov_mgr_is_provisioned(&provisioned);

	if (provisioned) {
		LOG_INF("Device already provisioned");
		connect_saved();
		return 0;
	}

	LOG_INF("Device not provisioned, starting BLE provisioning");
	ret = network_prov_mgr_start_provisioning(NETWORK_PROV_SECURITY_1,
						  PROV_POP, PROV_DEVICE_NAME);
	if (ret != 0) {
		LOG_ERR("Failed to start provisioning: %d", ret);
		return 0;
	}

	/* Block until the device connects with the supplied credentials. */
	network_prov_mgr_wait();

	/* Keep the provisioning service alive briefly: the app is still
	 * connected over BLE and polls GetWifiStatus to learn the result.
	 * Tearing the GATT service down immediately makes the app report
	 * "failed to provision" even though Wi-Fi connected (ESP-IDF keeps
	 * the service up after success for the same reason).
	 */
	k_sleep(K_SECONDS(30));
	network_prov_mgr_stop_provisioning();

	LOG_INF("Provisioning complete");
	return 0;
}
