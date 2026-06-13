/*
 * BLE provisioning scheme customization.
 *
 * Optional knobs for the BLE (GATT) transport, mirroring upstream Espressif's
 * scheme_ble.h. Call these after the manager is initialised and before
 * network_prov_mgr_start_provisioning() — the values are applied when the
 * advertising payload and GATT service are built at start.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef NETWORK_PROVISIONING_SCHEME_BLE_H_
#define NETWORK_PROVISIONING_SCHEME_BLE_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Override the 128-bit GATT service UUID the device advertises and serves.
 *
 * Per-endpoint characteristic UUIDs are still derived from this base, and the
 * apps map endpoints via the characteristic user-description descriptors, so
 * any unique base works. Mirrors network_prov_scheme_ble_set_service_uuid().
 *
 * @param uuid128 16-byte UUID, little-endian (as produced by
 *                BT_UUID_128_ENCODE).
 * @return 0 on success, -EINVAL if @p uuid128 is NULL.
 */
int network_prov_scheme_ble_set_service_uuid(const uint8_t uuid128[16]);

/**
 * Set manufacturer-specific data added to the BLE scan response, so a client
 * can match the device on it. Mirrors network_prov_scheme_ble_set_mfg_data().
 *
 * @param data Manufacturer data bytes (typically a 2-byte company ID followed
 *             by a payload); copied internally. Pass len 0 to clear.
 * @param len  Length in bytes; must fit one advertising AD structure.
 * @return 0 on success, -EINVAL on bad args, -ENOMEM if @p len is too large.
 */
int network_prov_scheme_ble_set_mfg_data(const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* NETWORK_PROVISIONING_SCHEME_BLE_H_ */
