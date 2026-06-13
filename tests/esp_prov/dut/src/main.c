/*
 * native_sim DUT for the esp_prov SoftAP integration test.
 *
 * Runs the real provisioning manager over the SoftAP (HTTP) transport, backed
 * by the fake Wi-Fi driver, and stays in provisioning mode so the host-side
 * esp_prov tool can drive multiple scenarios. The HTTP server binds to all
 * interfaces, so it is reachable from the host over the native_sim "zeth"
 * Ethernet TAP at a fixed IP.
 *
 * The fake Wi-Fi backend runs in credential-matching mode: esp_prov drives the
 * outcome purely through the SSID/passphrase it sends — the right passphrase
 * for HOST_SSID succeeds, a wrong one reports WRONG_PASSWORD, and an SSID that
 * is not in the canned scan list reports AP_NOT_FOUND.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/ethernet.h>
#include <zephyr/net/wifi.h>

#include "network_provisioning/network_prov_mgr.h"
#include "network_provisioning/test/fake_wifi.h"

LOG_MODULE_REGISTER(esp_prov_dut, LOG_LEVEL_INF);

#define PROV_POP   "abcd1234"
#define AP_NAME    "PROV_ZEPHYR"

/* The one "real" network esp_prov can successfully provision. */
#define HOST_SSID  "HomeNet"
#define HOST_PASS  "correct-horse-battery"

/* Device address on the host-facing Ethernet TAP (host side is 192.0.2.2,
 * configured by net-tools' net-setup.sh).
 */
#define DUT_IP     "192.0.2.1"
#define DUT_NETMASK "255.255.255.0"

/* Assign the fixed device IP to the host-facing Ethernet interface — the one
 * that is Ethernet-L2 but NOT the fake Wi-Fi interface (which also uses
 * Ethernet L2). esp_prov connects to this address.
 */
static void assign_host_ip(struct net_if *iface, void *user_data)
{
	struct net_if **out = user_data;
	struct in_addr addr;
	struct in_addr netmask;

	if (*out != NULL || net_if_is_wifi(iface)) {
		return;
	}
	if (net_if_l2(iface) != &NET_L2_GET_NAME(ETHERNET)) {
		return;
	}

	if (net_addr_pton(AF_INET, DUT_IP, &addr) != 0 ||
	    net_addr_pton(AF_INET, DUT_NETMASK, &netmask) != 0) {
		return;
	}
	if (net_if_ipv4_addr_add(iface, &addr, NET_ADDR_MANUAL, 0) == NULL) {
		LOG_WRN("could not add %s to the host interface", DUT_IP);
	}
	net_if_ipv4_set_netmask_by_addr(iface, &addr, &netmask);
	net_if_up(iface);
	*out = iface;
}

static void program_fake_wifi(void)
{
	const struct fake_wifi_ap aps[] = {
		{ .ssid = HOST_SSID, .ssid_len = sizeof(HOST_SSID) - 1,
		  .channel = 6, .rssi = -42, .security = WIFI_SECURITY_TYPE_PSK,
		  .bssid = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55} },
		{ .ssid = "OpenCafe", .ssid_len = 8, .channel = 11, .rssi = -75,
		  .security = WIFI_SECURITY_TYPE_NONE,
		  .bssid = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff} },
	};

	fake_wifi_set_scan_aps(aps, ARRAY_SIZE(aps));
	fake_wifi_set_expected_credentials(HOST_SSID, HOST_PASS);
}

int main(void)
{
	struct net_if *host = NULL;

	net_if_foreach(assign_host_ip, &host);
	if (host != NULL) {
		LOG_INF("host interface up at %s", DUT_IP);
	} else {
		LOG_WRN("no host Ethernet interface found");
	}

	program_fake_wifi();

	struct network_prov_mgr_config cfg = {
		.scheme = NETWORK_PROV_SCHEME_SOFTAP,
		.wifi_conn_attempts = 0, /* single attempt: report failures at once */
	};

	if (network_prov_mgr_init(cfg) != 0) {
		LOG_ERR("manager init failed");
		return 1;
	}
	/* Keep the service up across all esp_prov scenarios (the test drives
	 * success and several failures against one long-running instance).
	 */
	(void)network_prov_mgr_disable_auto_stop(0);
	if (network_prov_mgr_start_provisioning(NETWORK_PROV_SECURITY_1, PROV_POP,
						AP_NAME, NULL) != 0) {
		LOG_ERR("start_provisioning failed");
		return 1;
	}

	LOG_INF("esp_prov DUT ready: provisioning over HTTP at %s:80", DUT_IP);

	/* Stay up so esp_prov can run the success and failure scenarios. */
	while (true) {
		k_sleep(K_SECONDS(1));
	}
	return 0;
}
