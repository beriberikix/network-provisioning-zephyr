/*
 * Network provisioning manager: lifecycle, endpoint wiring, version/capability
 * advertisement and application event delivery.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/wifi_credentials.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#if defined(CONFIG_SETTINGS)
#include <zephyr/settings/settings.h>
#endif

#include "network_provisioning/network_prov_mgr.h"
#include "network_prov_internal.h"
#include "protocomm.h"
#include "security.h"

LOG_MODULE_DECLARE(network_prov, CONFIG_NETWORK_PROV_LOG_LEVEL); /* registered in security0.c */

/* Kconfig cannot express "at least one transport" without a recursive
 * dependency (the transports depend on NETWORK_PROV_CORE, which the manager
 * selects), so enforce it here.
 */
#if !defined(CONFIG_NETWORK_PROV_BLE) && !defined(CONFIG_NETWORK_PROV_SOFTAP)
#error "NETWORK_PROV_MGR needs at least one transport: enable CONFIG_NETWORK_PROV_BLE and/or CONFIG_NETWORK_PROV_SOFTAP"
#endif

#define EP_VERSION  "proto-ver"
#define EP_SESSION  "prov-session"
#define EP_SCAN     "prov-scan"
#define EP_CONFIG   "prov-config"
#define EP_CTRL     "prov-ctrl"

static struct {
	bool inited;
	bool started;
	enum network_prov_scheme scheme;
	struct network_prov_event_handler app;
	struct protocomm *pc;
	char version_json[160];
	struct k_sem done;
} mgr;

void network_prov_emit_event(enum network_prov_cb_event event, void *event_data)
{
	if (mgr.app.event_cb != NULL) {
		mgr.app.event_cb(mgr.app.user_data, event, event_data);
	}
	if (event == NETWORK_PROV_CRED_SUCCESS) {
		k_sem_give(&mgr.done);
	}
}

int network_prov_mgr_init(struct network_prov_mgr_config config)
{
	if (mgr.inited) {
		return -EALREADY;
	}
	if (config.scheme != NETWORK_PROV_SCHEME_BLE &&
	    config.scheme != NETWORK_PROV_SCHEME_SOFTAP) {
		LOG_ERR("Unknown provisioning scheme %d", config.scheme);
		return -EINVAL;
	}
	if ((config.scheme == NETWORK_PROV_SCHEME_BLE &&
	     !IS_ENABLED(CONFIG_NETWORK_PROV_BLE)) ||
	    (config.scheme == NETWORK_PROV_SCHEME_SOFTAP &&
	     !IS_ENABLED(CONFIG_NETWORK_PROV_SOFTAP))) {
		LOG_ERR("Transport for scheme %d not enabled", config.scheme);
		return -ENOTSUP;
	}

	mgr.scheme = config.scheme;
	mgr.app = config.app_event_handler;
	k_sem_init(&mgr.done, 0, 1);

#if defined(CONFIG_SETTINGS)
	int ret = settings_subsys_init();

	if (ret != 0) {
		LOG_ERR("settings_subsys_init failed: %d", ret);
		return ret;
	}
	ret = settings_load();
	if (ret != 0) {
		LOG_WRN("settings_load failed: %d", ret);
	}
#endif

	mgr.inited = true;
	network_prov_emit_event(NETWORK_PROV_INIT, NULL);
	return 0;
}

void network_prov_mgr_deinit(void)
{
	if (!mgr.inited) {
		return;
	}
	if (mgr.started) {
		network_prov_mgr_stop_provisioning();
	}
	mgr.inited = false;
	network_prov_emit_event(NETWORK_PROV_DEINIT, NULL);
}

int network_prov_mgr_is_provisioned(bool *provisioned)
{
	if (provisioned == NULL) {
		return -EINVAL;
	}
	*provisioned = !wifi_credentials_is_empty();
	return 0;
}

int network_prov_mgr_reset_wifi_provisioning(void)
{
	if (!mgr.inited) {
		return -EPERM;
	}

	int ret = wifi_credentials_delete_all();

	if (ret != 0) {
		LOG_ERR("Failed to erase stored credentials: %d", ret);
		return ret;
	}
	LOG_INF("Stored Wi-Fi credentials erased");
	return 0;
}

static void build_version_json(enum network_prov_security security, const char *pop)
{
	int sec_ver = (security == NETWORK_PROV_SECURITY_1) ? 1 : 0;
	bool no_pop = (security == NETWORK_PROV_SECURITY_1) &&
		      (pop == NULL || pop[0] == '\0');

	snprintf(mgr.version_json, sizeof(mgr.version_json),
		 "{\"prov\":{\"ver\":\"v1.1\",\"sec_ver\":%d,"
		 "\"cap\":[\"wifi_prov\",\"wifi_scan\"%s]}}",
		 sec_ver, no_pop ? ",\"no_pop\"" : "");
}

int network_prov_mgr_start_provisioning(enum network_prov_security security,
					const char *pop, const char *service_name,
					const char *service_key)
{
	int ret;

	if (!mgr.inited) {
		return -EPERM;
	}
	if (mgr.started) {
		return -EALREADY;
	}

	const struct protocomm_security *sec =
		(security == NETWORK_PROV_SECURITY_1) ? &network_prov_security1
						      : &network_prov_security0;

	mgr.pc = protocomm_new();
	if (mgr.pc == NULL) {
		return -ENOMEM;
	}

	build_version_json(security, pop);

	ret = protocomm_set_version(mgr.pc, EP_VERSION, mgr.version_json);
	if (ret) {
		goto err;
	}
	ret = protocomm_set_security(mgr.pc, EP_SESSION, sec,
				     (security == NETWORK_PROV_SECURITY_1) ? pop : NULL);
	if (ret) {
		goto err;
	}

	ret = network_prov_wifi_scan_init();
	if (ret) {
		goto err;
	}
	ret = protocomm_add_endpoint(mgr.pc, EP_SCAN,
				     network_prov_wifi_scan_handler, NULL);
	if (ret) {
		goto err;
	}

	ret = network_prov_wifi_config_init();
	if (ret) {
		goto err;
	}
	ret = protocomm_add_endpoint(mgr.pc, EP_CONFIG,
				     network_prov_wifi_config_handler, NULL);
	if (ret) {
		goto err;
	}

	ret = protocomm_add_endpoint(mgr.pc, EP_CTRL,
				     network_prov_wifi_ctrl_handler, NULL);
	if (ret) {
		goto err;
	}

	switch (mgr.scheme) {
#if defined(CONFIG_NETWORK_PROV_BLE)
	case NETWORK_PROV_SCHEME_BLE:
		ARG_UNUSED(service_key);
		ret = network_prov_ble_start(mgr.pc, service_name);
		break;
#endif
#if defined(CONFIG_NETWORK_PROV_SOFTAP)
	case NETWORK_PROV_SCHEME_SOFTAP:
		ret = network_prov_softap_start(mgr.pc, service_name, service_key);
		break;
#endif
	default:
		ret = -ENOTSUP;
		break;
	}
	if (ret) {
		goto err;
	}

	mgr.started = true;
	LOG_INF("Provisioning started (security %d)", sec->version);
	network_prov_emit_event(NETWORK_PROV_START, NULL);
	return 0;

err:
	network_prov_wifi_scan_deinit();
	network_prov_wifi_config_deinit();
	protocomm_delete(mgr.pc);
	mgr.pc = NULL;
	return ret;
}

void network_prov_mgr_stop_provisioning(void)
{
	if (!mgr.started) {
		return;
	}
#if defined(CONFIG_NETWORK_PROV_BLE)
	if (mgr.scheme == NETWORK_PROV_SCHEME_BLE) {
		network_prov_ble_stop();
	}
#endif
#if defined(CONFIG_NETWORK_PROV_SOFTAP)
	if (mgr.scheme == NETWORK_PROV_SCHEME_SOFTAP) {
		network_prov_softap_stop();
	}
#endif
	network_prov_wifi_scan_deinit();
	network_prov_wifi_config_deinit();
	protocomm_delete(mgr.pc);
	mgr.pc = NULL;
	mgr.started = false;
	network_prov_emit_event(NETWORK_PROV_END, NULL);
}

void network_prov_mgr_wait(void)
{
	k_sem_take(&mgr.done, K_FOREVER);
}
