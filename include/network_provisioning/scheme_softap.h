/*
 * SoftAP provisioning scheme object.
 *
 * Mirrors upstream Espressif's scheme_softap.h: exposes the transport vtable to
 * pass as the @c scheme of network_prov_mgr_config.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef NETWORK_PROVISIONING_SCHEME_SOFTAP_H_
#define NETWORK_PROVISIONING_SCHEME_SOFTAP_H_

#include "network_provisioning/network_prov_mgr.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * SoftAP (HTTP) transport scheme object. Pass &network_prov_scheme_softap as the
 * @c scheme of @ref network_prov_mgr_config. Requires CONFIG_NETWORK_PROV_SOFTAP
 * (otherwise referencing it is a link error).
 */
extern const struct network_prov_scheme network_prov_scheme_softap;

#ifdef __cplusplus
}
#endif

#endif /* NETWORK_PROVISIONING_SCHEME_SOFTAP_H_ */
