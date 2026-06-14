/*
 * Shared constants for the BLE provisioning BabbleSim test.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef NETWORK_PROV_BSIM_BLE_E2E_COMMON_H_
#define NETWORK_PROV_BSIM_BLE_E2E_COMMON_H_

#include <zephyr/bluetooth/uuid.h> /* BT_UUID_128_ENCODE for PROV_TEST_SVC_UUID */

/* BLE device name the DUT advertises and the tester scans for. */
#define PROV_TEST_NAME "PROV_BSIM"

/* Proof-of-possession both sides use for the security-1 handshake. */
#define PROV_TEST_POP "abcd1234"

/* The SSID the tester provisions; matches a canned AP the DUT advertises. */
#define PROV_TEST_SSID "HomeNet"
#define PROV_TEST_PASS "supersecret123"

/* Custom 128-bit GATT service UUID the DUT installs via
 * network_prov_scheme_ble_set_service_uuid(); the tester discovers by it, so a
 * successful discovery proves the override took effect.
 */
#define PROV_TEST_SVC_UUID \
	BT_UUID_128_ENCODE(0x1234abcd, 0x1111, 0x2222, 0x3333, 0x444455556666)

/* Manufacturer-specific data the DUT advertises (company id 0x02E5 + payload);
 * the tester verifies it appears in the scan response.
 */
#define PROV_TEST_MFG_DATA {0xE5, 0x02, 0xCA, 0xFE}

/* Application section the DUT injects into proto-ver via set_app_info(). */
#define PROV_TEST_APP_LABEL "bsimapp"
#define PROV_TEST_APP_VER   "9.9"
#define PROV_TEST_APP_CAP   "feat_x"

/* Custom application endpoint (network_prov_mgr_endpoint_create/register): the
 * DUT echoes "echo:<msg>"; the tester verifies the round-trip over the secure
 * session.
 */
#define PROV_TEST_CUSTOM_EP  "custom-data"
#define PROV_TEST_CUSTOM_MSG "ping123"

#endif /* NETWORK_PROV_BSIM_BLE_E2E_COMMON_H_ */
