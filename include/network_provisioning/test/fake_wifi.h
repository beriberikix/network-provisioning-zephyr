/*
 * Test-control API for the fake (simulated) Wi-Fi offload backend
 * (sim/wifi/fake_wifi.c). Lets a test or a BabbleSim tester program the canned
 * scan results and the outcome of the next connect attempt, so the full
 * provisioning manager can run headless on a board with no Wi-Fi hardware
 * (native_sim / nrf52_bsim) and exercise both the success and failure paths
 * deterministically.
 *
 * Only available when CONFIG_NETWORK_PROV_FAKE_WIFI is enabled; never built
 * into the real samples.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef NETWORK_PROVISIONING_TEST_FAKE_WIFI_H_
#define NETWORK_PROVISIONING_TEST_FAKE_WIFI_H_

#include <stddef.h>
#include <stdint.h>
#include <zephyr/net/wifi.h>
#include <zephyr/net/wifi_mgmt.h>

/** A canned access point the fake backend reports from a scan. */
struct fake_wifi_ap {
	char ssid[WIFI_SSID_MAX_LEN + 1];
	uint8_t ssid_len;
	uint8_t bssid[WIFI_MAC_ADDR_LEN];
	uint8_t channel;
	int8_t rssi;
	enum wifi_security_type security;
};

/**
 * Replace the canned AP list returned by subsequent NET_REQUEST_WIFI_SCAN
 * requests. @p aps is copied (up to CONFIG_NETWORK_PROV_FAKE_WIFI_MAX_AP).
 */
void fake_wifi_set_scan_aps(const struct fake_wifi_ap *aps, size_t count);

/**
 * Program the conn_status reported for the next NET_REQUEST_WIFI_CONNECT.
 * Use WIFI_STATUS_CONN_SUCCESS, WIFI_STATUS_CONN_WRONG_PASSWORD,
 * WIFI_STATUS_CONN_AP_NOT_FOUND, etc. The setting persists across attempts
 * until changed (so the manager's retry loop sees a consistent failure).
 */
void fake_wifi_set_next_connect_result(enum wifi_conn_status status);

/**
 * Make the next NET_REQUEST_WIFI_CONNECT fail synchronously with -@p errnum
 * (e.g. EINVAL) instead of raising an async result, to exercise the config
 * handler's synchronous-rejection path. One-shot: cleared after it fires.
 */
void fake_wifi_set_next_connect_sync_error(int errnum);

/**
 * Switch the backend to credential-matching mode: the outcome of each connect
 * is derived from the requested credentials rather than a pre-programmed
 * status. With @p ssid / @p pass configured as the one "real" network:
 *   - requested SSID not among the canned scan APs -> AP_NOT_FOUND;
 *   - SSID matches a canned AP but the passphrase differs -> WRONG_PASSWORD;
 *   - SSID and passphrase both match -> SUCCESS.
 * This lets a host-side client (esp_prov) drive every outcome purely through
 * the credentials it sends. Pass NULL/empty @p ssid to leave this mode.
 */
void fake_wifi_set_expected_credentials(const char *ssid, const char *pass);

/** Reset all programmed state: empty scan list, connect succeeds, no sync error. */
void fake_wifi_reset(void);

#endif /* NETWORK_PROVISIONING_TEST_FAKE_WIFI_H_ */
