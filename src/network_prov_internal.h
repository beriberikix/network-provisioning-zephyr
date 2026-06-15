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

/** Emit a lifecycle event to the registered application handler (no-op if none). */
void network_prov_emit_event(enum network_prov_cb_event event, void *event_data);

/*
 * prov-config endpoint: Wi-Fi credentials + connection state machine.
 */

/**
 * Initialise the Wi-Fi config handler and its connection state machine.
 *
 * @param conn_attempts Max connection attempts per provisioning try (0 = a
 *                      single attempt whose failure is reported immediately).
 * @return 0 on success, negative errno otherwise.
 */
int network_prov_wifi_config_init(uint32_t conn_attempts);
/** Tear down the Wi-Fi config handler and release its net_mgmt callbacks. */
void network_prov_wifi_config_deinit(void);
/** Reset the connection state machine (clears in-flight creds and attempt counters). */
void network_prov_wifi_config_reset(void);
/** Connection attempts left for the credentials currently being tried. */
uint32_t network_prov_wifi_config_remaining_attempts(void);
/**
 * Stage @p ssid / @p psk and run the shared apply path (persist + connect +
 * retry + events) — backs network_prov_mgr_configure_wifi_sta().
 *
 * @return 0 on success, negative errno on failure.
 */
int network_prov_wifi_config_set_and_apply(const uint8_t *ssid, size_t ssid_len,
					   const uint8_t *psk, size_t psk_len);
/** protocomm handler for the prov-config endpoint (NetworkConfigPayload). */
int network_prov_wifi_config_handler(void *priv, const uint8_t *inbuf, size_t inlen,
				     uint8_t **outbuf, size_t *outlen);

/*
 * prov-ctrl endpoint: Wi-Fi state-machine reset / re-provision.
 */

/** protocomm handler for the prov-ctrl endpoint (NetworkCtrlPayload). */
int network_prov_wifi_ctrl_handler(void *priv, const uint8_t *inbuf, size_t inlen,
				   uint8_t **outbuf, size_t *outlen);

/*
 * prov-scan endpoint: Wi-Fi scanning.
 */

/** Initialise the scan handler. @return 0 on success, negative errno otherwise. */
int network_prov_wifi_scan_init(void);
/** Tear down the scan handler. */
void network_prov_wifi_scan_deinit(void);
/** protocomm handler for the prov-scan endpoint (NetworkScanPayload). */
int network_prov_wifi_scan_handler(void *priv, const uint8_t *inbuf, size_t inlen,
				   uint8_t **outbuf, size_t *outlen);

/*
 * Thread provisioning (CONFIG_NETWORK_PROV_NETWORK_TYPE_THREAD). The shared
 * prov-config and prov-ctrl endpoints carry the Thread message types instead of
 * the Wi-Fi ones; the manager registers whichever set matches the configured
 * network type. Thread scan (prov-scan) is not yet implemented.
 */

/** Initialise the Thread config handler (registers the OpenThread state callback). */
int network_prov_thread_config_init(void);
/** Tear down the Thread config handler. */
void network_prov_thread_config_deinit(void);
/** Reset Thread provisioning state: disable Thread and drop the staged dataset. */
void network_prov_thread_config_reset(void);
/**
 * Erase the persisted Thread dataset (the device reverts to uncommissioned).
 * @return 0 on success, negative errno otherwise.
 */
int network_prov_thread_config_erase(void);
/** True if an Active Operational Dataset is committed (otDatasetIsCommissioned). */
bool network_prov_thread_is_commissioned(void);
/**
 * Apply a raw Active Operational Dataset (TLVs) and bring Thread up — backs a
 * programmatic apply mirroring network_prov_wifi_config_set_and_apply().
 * @return 0 on success, negative errno on failure.
 */
int network_prov_thread_config_set_and_apply(const uint8_t *dataset, size_t len);
/** protocomm handler for the prov-config endpoint (Thread NetworkConfigPayload). */
int network_prov_thread_config_handler(void *priv, const uint8_t *inbuf, size_t inlen,
				       uint8_t **outbuf, size_t *outlen);
/** protocomm handler for the prov-ctrl endpoint (Thread NetworkCtrlPayload). */
int network_prov_thread_ctrl_handler(void *priv, const uint8_t *inbuf, size_t inlen,
				     uint8_t **outbuf, size_t *outlen);

/*
 * Transport back-ends. Each is fronted by a network_prov_scheme vtable; the
 * start() call registers the protocomm endpoints with the transport and brings
 * it up (returns 0 or a negative errno), and the void stop() tears it down.
 */

/**
 * Start the BLE (GATT) transport: register the dynamic GATT service and
 * advertise @p device_name.
 */
int network_prov_ble_start(struct protocomm *pc, const char *device_name);
/** Stop the BLE transport (unregister the GATT service, stop advertising). */
void network_prov_ble_stop(void);

/**
 * Start the SoftAP transport: bring up the access point and DHCPv4 server, then
 * serve protocomm over HTTP. @p service_name is the AP SSID; @p service_key the
 * WPA2-PSK password (NULL/empty for an open AP).
 */
int network_prov_softap_start(struct protocomm *pc, const char *service_name,
			      const char *service_key);
/** Stop the SoftAP transport (HTTP server + access point + DHCP server). */
void network_prov_softap_stop(void);
/**
 * Start only the HTTP/protocomm glue, without bringing up an access point —
 * split out so the loopback integration test can exercise it on native_sim.
 */
int network_prov_softap_http_start(struct protocomm *pc);
/** Stop the HTTP/protocomm glue started by network_prov_softap_http_start(). */
void network_prov_softap_http_stop(void);

/** Start the console transport (protocomm over the device shell). */
int network_prov_console_start(struct protocomm *pc);
/** Stop the console transport. */
void network_prov_console_stop(void);

#ifdef __cplusplus
}
#endif

#endif /* NETWORK_PROVISIONING_INTERNAL_H_ */
