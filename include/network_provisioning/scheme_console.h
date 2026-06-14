/*
 * Console provisioning scheme object.
 *
 * Mirrors upstream Espressif's scheme_console.h: exposes the transport vtable to
 * pass as the @c scheme of network_prov_mgr_config.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef NETWORK_PROVISIONING_SCHEME_CONSOLE_H_
#define NETWORK_PROVISIONING_SCHEME_CONSOLE_H_

#include "network_provisioning/network_prov_mgr.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Console (shell) transport scheme object. Pass &network_prov_scheme_console as
 * the @c scheme of @ref network_prov_mgr_config. Requires
 * CONFIG_NETWORK_PROV_CONSOLE (otherwise referencing it is a link error).
 *
 * @note The protocol is carried by a single shell command,
 *       @c "net_prov <endpoint> <session_id> <hex-request>", which dispatches the
 *       hex-decoded request to the named protocomm endpoint and prints the
 *       response as lowercase hex. Changing @c session_id opens a fresh
 *       protocomm session (resetting the security handshake), mirroring a BLE
 *       reconnect or a new HTTP cookie. The @c service_name / @c service_key
 *       passed to @ref network_prov_mgr_start_provisioning are unused for this
 *       scheme. This is the transport @c "esp_prov --transport console" speaks.
 */
extern const struct network_prov_scheme network_prov_scheme_console;

#ifdef __cplusplus
}
#endif

#endif /* NETWORK_PROVISIONING_SCHEME_CONSOLE_H_ */
