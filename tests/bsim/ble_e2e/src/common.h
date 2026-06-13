/*
 * Shared constants for the BLE provisioning BabbleSim test.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef NETWORK_PROV_BSIM_BLE_E2E_COMMON_H_
#define NETWORK_PROV_BSIM_BLE_E2E_COMMON_H_

/* BLE device name the DUT advertises and the tester scans for. */
#define PROV_TEST_NAME "PROV_BSIM"

/* Proof-of-possession both sides use for the security-1 handshake. */
#define PROV_TEST_POP "abcd1234"

/* The SSID the tester provisions; matches a canned AP the DUT advertises. */
#define PROV_TEST_SSID "HomeNet"
#define PROV_TEST_PASS "supersecret123"

#endif /* NETWORK_PROV_BSIM_BLE_E2E_COMMON_H_ */
