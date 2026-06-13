/*
 * Internal glue between the manager, transport and protocol handlers.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef NETWORK_PROVISIONING_INTERNAL_H_
#define NETWORK_PROVISIONING_INTERNAL_H_

#include "network_provisioning/network_prov_mgr.h"
#include "protocomm.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Emit a lifecycle event to the registered application handler. */
void network_prov_emit_event(enum network_prov_cb_event event, void *event_data);

/* prov-config endpoint (Wi-Fi credentials + connection state machine).
 * conn_attempts: max connection attempts per provisioning try (0 = single
 * attempt, fail immediately).
 */
int network_prov_wifi_config_init(uint32_t conn_attempts);
void network_prov_wifi_config_deinit(void);
void network_prov_wifi_config_reset(void);
uint32_t network_prov_wifi_config_remaining_attempts(void);
/* Stage @p ssid / @p psk and run the shared apply path (persist + connect +
 * retry + events) — backs network_prov_mgr_configure_wifi_sta().
 */
int network_prov_wifi_config_set_and_apply(const uint8_t *ssid, size_t ssid_len,
					   const uint8_t *psk, size_t psk_len);
int network_prov_wifi_config_handler(void *priv, const uint8_t *inbuf, size_t inlen,
				     uint8_t **outbuf, size_t *outlen);

/* prov-ctrl endpoint (Wi-Fi state-machine reset / re-provision). */
int network_prov_wifi_ctrl_handler(void *priv, const uint8_t *inbuf, size_t inlen,
				   uint8_t **outbuf, size_t *outlen);

/* prov-scan endpoint (Wi-Fi scanning). */
int network_prov_wifi_scan_init(void);
void network_prov_wifi_scan_deinit(void);
int network_prov_wifi_scan_handler(void *priv, const uint8_t *inbuf, size_t inlen,
				   uint8_t **outbuf, size_t *outlen);

/* BLE transport. */
int network_prov_ble_start(struct protocomm *pc, const char *device_name);
void network_prov_ble_stop(void);

/* SoftAP transport (protocomm over HTTP on a device-hosted AP). */
int network_prov_softap_start(struct protocomm *pc, const char *service_name,
			      const char *service_key);
void network_prov_softap_stop(void);
/* HTTP/protocomm glue only (no AP bring-up) — split out so the loopback
 * integration test can exercise it on native_sim.
 */
int network_prov_softap_http_start(struct protocomm *pc);
void network_prov_softap_http_stop(void);

#ifdef __cplusplus
}
#endif

#endif /* NETWORK_PROVISIONING_INTERNAL_H_ */
