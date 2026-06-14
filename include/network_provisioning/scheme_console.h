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
 */
extern const struct network_prov_scheme network_prov_scheme_console;

#ifdef __cplusplus
}
#endif

#endif /* NETWORK_PROVISIONING_SCHEME_CONSOLE_H_ */
