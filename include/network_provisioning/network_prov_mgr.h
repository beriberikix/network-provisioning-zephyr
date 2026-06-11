/*
 * Network provisioning manager for Zephyr (Wi-Fi over BLE).
 *
 * Implements the Espressif "network provisioning" wire protocol so that the
 * stock ESP BLE Provisioning apps (Android/iOS) can configure a Zephyr
 * device's Wi-Fi credentials over a secure protocomm session.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef NETWORK_PROVISIONING_NETWORK_PROV_MGR_H_
#define NETWORK_PROVISIONING_NETWORK_PROV_MGR_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Security scheme used for the protocomm session. */
enum network_prov_security {
	/** No security: payloads exchanged in plaintext (bring-up/testing only). */
	NETWORK_PROV_SECURITY_0 = 0,
	/** Curve25519 key exchange + AES-256-CTR + optional proof-of-possession. */
	NETWORK_PROV_SECURITY_1 = 1,
};

/** Events emitted by the manager over the application event handler. */
enum network_prov_cb_event {
	NETWORK_PROV_INIT,         /**< Manager initialised. */
	NETWORK_PROV_START,        /**< Provisioning started, transport advertising. */
	NETWORK_PROV_CRED_RECV,    /**< Wi-Fi credentials received from the app. */
	NETWORK_PROV_CRED_FAIL,    /**< Failed to connect with the received credentials. */
	NETWORK_PROV_CRED_SUCCESS, /**< Connected successfully with the credentials. */
	NETWORK_PROV_END,          /**< Provisioning stopped. */
	NETWORK_PROV_DEINIT,       /**< Manager de-initialised. */
};

/** Reason reported alongside NETWORK_PROV_CRED_FAIL. */
enum network_prov_cred_fail_reason {
	NETWORK_PROV_WIFI_AUTH_ERROR,        /**< Authentication failed (bad passphrase). */
	NETWORK_PROV_WIFI_NETWORK_NOT_FOUND, /**< Requested SSID not found. */
};

/**
 * Application event callback.
 *
 * @param user_data  Opaque pointer supplied in @ref network_prov_event_handler.
 * @param event      Event being delivered.
 * @param event_data Event-specific payload (e.g. pointer to
 *                   @ref network_prov_cred_fail_reason for CRED_FAIL), or NULL.
 */
typedef void (*network_prov_cb_t)(void *user_data,
				  enum network_prov_cb_event event,
				  void *event_data);

/** Registration of an application event handler. */
struct network_prov_event_handler {
	network_prov_cb_t event_cb;
	void *user_data;
};

/** Provisioning scheme. Only BLE is currently supported. */
enum network_prov_scheme {
	NETWORK_PROV_SCHEME_BLE = 0,
};

/** Manager configuration passed to @ref network_prov_mgr_init. */
struct network_prov_mgr_config {
	/** Transport scheme. */
	enum network_prov_scheme scheme;
	/** Application event handler (may have a NULL callback). */
	struct network_prov_event_handler app_event_handler;
};

/**
 * Initialise the provisioning manager.
 *
 * Loads the settings subsystem and the Wi-Fi credentials store, but does not
 * start advertising. Call exactly once before any other manager API.
 *
 * @return 0 on success, negative errno otherwise.
 */
int network_prov_mgr_init(struct network_prov_mgr_config config);

/** Tear down the manager and free its resources. */
void network_prov_mgr_deinit(void);

/**
 * Report whether the device already has stored Wi-Fi credentials.
 *
 * @param provisioned Set to true if at least one credential is stored.
 * @return 0 on success, negative errno otherwise.
 */
int network_prov_mgr_is_provisioned(bool *provisioned);

/**
 * Start the provisioning service (initialise BLE, register the GATT service
 * and begin advertising).
 *
 * @param security     Security scheme to advertise and enforce.
 * @param pop          Proof-of-possession string for NETWORK_PROV_SECURITY_1,
 *                     or NULL to disable PoP (advertises the "no_pop" cap).
 *                     Ignored for NETWORK_PROV_SECURITY_0.
 * @param service_name BLE device name (e.g. "PROV_1234"). If NULL, a name is
 *                     derived from the Bluetooth address.
 * @return 0 on success, negative errno otherwise.
 */
int network_prov_mgr_start_provisioning(enum network_prov_security security,
					const char *pop,
					const char *service_name);

/** Stop advertising and tear down the transport (keeps the manager init'd). */
void network_prov_mgr_stop_provisioning(void);

/** Block until provisioning completes (NETWORK_PROV_CRED_SUCCESS). */
void network_prov_mgr_wait(void);

#ifdef __cplusplus
}
#endif

#endif /* NETWORK_PROVISIONING_NETWORK_PROV_MGR_H_ */
