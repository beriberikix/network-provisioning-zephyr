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
	uint32_t wifi_conn_attempts;
	struct protocomm *pc;
	/* Optional application section injected into the proto-ver JSON by
	 * network_prov_mgr_set_app_info(), pre-rendered as
	 * "<label>":{"ver":"..","cap":[..]}, (note the trailing comma) or "".
	 */
	char app_info_json[256];
	char version_json[448];
	struct k_sem done;
	/* Auto-stop: tear the service down a grace period after success unless
	 * the app opted out via network_prov_mgr_disable_auto_stop().
	 */
	bool auto_stop;
	uint32_t cleanup_delay_ms;
	struct k_work_delayable teardown_work;
	/* Application-defined custom endpoints (network_prov_mgr_endpoint_*). */
	struct custom_ep {
		char name[PROTOCOMM_EP_NAME_MAX];
		network_prov_endpoint_handler_t handler;
		void *ctx;
		bool created;
	} custom[CONFIG_NETWORK_PROV_MAX_CUSTOM_ENDPOINTS];
} mgr;

static void do_teardown(void);
static void teardown_work_fn(struct k_work *work);

void network_prov_emit_event(enum network_prov_cb_event event, void *event_data)
{
	if (mgr.app.event_cb != NULL) {
		mgr.app.event_cb(mgr.app.user_data, event, event_data);
	}
	if (event == NETWORK_PROV_CRED_SUCCESS) {
		k_sem_give(&mgr.done);
		/* Auto-stop: after success, give the app its status-poll grace
		 * window, then tear the service down (upstream parity). The app
		 * can opt out with network_prov_mgr_disable_auto_stop().
		 */
		if (mgr.started && mgr.auto_stop) {
			k_work_schedule(&mgr.teardown_work,
					K_MSEC(CONFIG_NETWORK_PROV_AUTOSTOP_TIMEOUT_MS));
		}
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
	mgr.wifi_conn_attempts = config.wifi_conn_attempts;
	mgr.auto_stop = true;
	mgr.cleanup_delay_ms = 0;
	mgr.app_info_json[0] = '\0'; /* don't leak a prior cycle's app-info */
	memset(mgr.custom, 0, sizeof(mgr.custom)); /* nor custom endpoints */
	k_sem_init(&mgr.done, 0, 1);
	k_work_init_delayable(&mgr.teardown_work, teardown_work_fn);

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
	struct k_work_sync sync;

	/* _sync so a teardown_work already running cannot race do_teardown(). */
	(void)k_work_cancel_delayable_sync(&mgr.teardown_work, &sync);
	if (mgr.started) {
		do_teardown();
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

/* Reject characters that would break out of a JSON string literal, so the
 * concatenated proto-ver JSON stays well-formed regardless of caller input.
 */
static bool json_token_ok(const char *s)
{
	for (; *s != '\0'; s++) {
		unsigned char c = (unsigned char)*s;

		if (c < 0x20 || c == '"' || c == '\\') {
			return false;
		}
	}
	return true;
}

int network_prov_mgr_set_app_info(const char *label, const char *version,
				  const char *const *capabilities,
				  size_t capabilities_count)
{
	if (label == NULL || label[0] == '\0' || version == NULL) {
		return -EINVAL;
	}
	if (capabilities_count > 0 && capabilities == NULL) {
		return -EINVAL;
	}
	if (!mgr.inited) {
		return -EPERM;
	}
	if (mgr.started) {
		/* The version JSON is rendered at start_provisioning() time. */
		return -EPERM;
	}
	if (!json_token_ok(label) || !json_token_ok(version)) {
		return -EINVAL;
	}
	for (size_t i = 0; i < capabilities_count; i++) {
		if (capabilities[i] == NULL || !json_token_ok(capabilities[i])) {
			return -EINVAL;
		}
	}

	/* Render "<label>":{"ver":"<version>","cap":["c0","c1",...]}, — the
	 * trailing comma lets build_version_json() splice it before "prov".
	 */
	int n = snprintf(mgr.app_info_json, sizeof(mgr.app_info_json),
			 "\"%s\":{\"ver\":\"%s\",\"cap\":[", label, version);

	if (n < 0 || (size_t)n >= sizeof(mgr.app_info_json)) {
		goto overflow;
	}
	size_t off = n;

	for (size_t i = 0; i < capabilities_count; i++) {
		n = snprintf(mgr.app_info_json + off, sizeof(mgr.app_info_json) - off,
			     "%s\"%s\"", (i == 0) ? "" : ",", capabilities[i]);
		if (n < 0 || (size_t)n >= sizeof(mgr.app_info_json) - off) {
			goto overflow;
		}
		off += n;
	}

	n = snprintf(mgr.app_info_json + off, sizeof(mgr.app_info_json) - off, "]},");
	if (n < 0 || (size_t)n >= sizeof(mgr.app_info_json) - off) {
		goto overflow;
	}
	return 0;

overflow:
	mgr.app_info_json[0] = '\0';
	return -ENOMEM;
}

static bool is_builtin_ep(const char *name)
{
	return strcmp(name, EP_VERSION) == 0 || strcmp(name, EP_SESSION) == 0 ||
	       strcmp(name, EP_SCAN) == 0 || strcmp(name, EP_CONFIG) == 0 ||
	       strcmp(name, EP_CTRL) == 0;
}

static struct custom_ep *find_custom_ep(const char *name)
{
	for (size_t i = 0; i < ARRAY_SIZE(mgr.custom); i++) {
		if (mgr.custom[i].created && strcmp(mgr.custom[i].name, name) == 0) {
			return &mgr.custom[i];
		}
	}
	return NULL;
}

/* protocomm handler installed for every created custom endpoint; forwards to
 * the application handler once registered, otherwise reports unsupported.
 */
static int custom_trampoline(void *priv, const uint8_t *inbuf, size_t inlen,
			     uint8_t **outbuf, size_t *outlen)
{
	struct custom_ep *e = priv;

	if (e->handler == NULL) {
		return -ENOTSUP;
	}
	return e->handler(e->ctx, inbuf, inlen, outbuf, outlen);
}

int network_prov_mgr_endpoint_create(const char *ep_name)
{
	if (ep_name == NULL || ep_name[0] == '\0' ||
	    strlen(ep_name) >= PROTOCOMM_EP_NAME_MAX) {
		return -EINVAL;
	}
	if (!mgr.inited) {
		return -EPERM;
	}
	if (mgr.started) {
		/* Endpoints are added to protocomm (and the transport's service)
		 * at start; creating one afterwards would not be advertised.
		 */
		return -EPERM;
	}
	if (is_builtin_ep(ep_name) || find_custom_ep(ep_name) != NULL) {
		return -EALREADY;
	}

	for (size_t i = 0; i < ARRAY_SIZE(mgr.custom); i++) {
		if (!mgr.custom[i].created) {
			strncpy(mgr.custom[i].name, ep_name, sizeof(mgr.custom[i].name) - 1);
			mgr.custom[i].name[sizeof(mgr.custom[i].name) - 1] = '\0';
			mgr.custom[i].handler = NULL;
			mgr.custom[i].ctx = NULL;
			mgr.custom[i].created = true;
			return 0;
		}
	}
	return -ENOSPC;
}

int network_prov_mgr_endpoint_register(const char *ep_name,
				       network_prov_endpoint_handler_t handler,
				       void *user_ctx)
{
	if (ep_name == NULL || handler == NULL) {
		return -EINVAL;
	}
	if (!mgr.started) {
		return -EPERM;
	}

	struct custom_ep *e = find_custom_ep(ep_name);

	if (e == NULL) {
		return -ENOENT;
	}
	e->handler = handler;
	e->ctx = user_ctx;
	return 0;
}

int network_prov_mgr_endpoint_unregister(const char *ep_name)
{
	if (ep_name == NULL) {
		return -EINVAL;
	}

	struct custom_ep *e = find_custom_ep(ep_name);

	if (e == NULL) {
		return -ENOENT;
	}
	e->handler = NULL;
	e->ctx = NULL;
	return 0;
}

static void build_version_json(enum network_prov_security security, const char *pop)
{
	int sec_ver = (security == NETWORK_PROV_SECURITY_1) ? 1 : 0;
	bool no_pop = (security == NETWORK_PROV_SECURITY_1) &&
		      (pop == NULL || pop[0] == '\0');

	snprintf(mgr.version_json, sizeof(mgr.version_json),
		 "{%s\"prov\":{\"ver\":\"v1.1\",\"sec_ver\":%d,"
		 "\"cap\":[\"wifi_prov\",\"wifi_scan\"%s]}}",
		 mgr.app_info_json, sec_ver, no_pop ? ",\"no_pop\"" : "");
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

	ret = network_prov_wifi_config_init(mgr.wifi_conn_attempts);
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

	/* Add application-defined custom endpoints before the transport builds
	 * its service, so each gets a BLE characteristic / HTTP route. The
	 * trampoline forwards to the app handler once it is registered.
	 */
	for (size_t i = 0; i < ARRAY_SIZE(mgr.custom); i++) {
		if (!mgr.custom[i].created) {
			continue;
		}
		ret = protocomm_add_endpoint(mgr.pc, mgr.custom[i].name,
					     custom_trampoline, &mgr.custom[i]);
		if (ret) {
			goto err;
		}
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

static void do_teardown(void)
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

static void teardown_work_fn(struct k_work *work)
{
	ARG_UNUSED(work);
	do_teardown();
}

void network_prov_mgr_stop_provisioning(void)
{
	if (!mgr.started) {
		return;
	}
	struct k_work_sync sync;

	/* _sync so a teardown_work already running cannot race do_teardown(). */
	(void)k_work_cancel_delayable_sync(&mgr.teardown_work, &sync);
	if (mgr.cleanup_delay_ms > 0) {
		/* Defer teardown so the final response can flush to the client
		 * before the transport goes away (upstream cleanup_delay).
		 */
		k_work_schedule(&mgr.teardown_work, K_MSEC(mgr.cleanup_delay_ms));
		return;
	}
	do_teardown();
}

int network_prov_mgr_disable_auto_stop(uint32_t cleanup_delay_ms)
{
	if (!mgr.inited) {
		return -EPERM;
	}
	mgr.auto_stop = false;
	mgr.cleanup_delay_ms = cleanup_delay_ms;
	/* Drop any auto-stop already scheduled by an earlier success. */
	(void)k_work_cancel_delayable(&mgr.teardown_work);
	return 0;
}

bool network_prov_mgr_is_sm_idle(void)
{
	return !mgr.started;
}

int network_prov_mgr_reset_wifi_sm_state_on_failure(void)
{
	if (!mgr.started) {
		return -EPERM;
	}
	network_prov_wifi_config_reset();
	return 0;
}

int network_prov_mgr_reset_wifi_sm_state_for_reprovision(void)
{
	if (!mgr.started) {
		return -EPERM;
	}
	network_prov_wifi_config_reset();
	return 0;
}

int network_prov_mgr_configure_wifi_sta(const char *ssid, const char *psk)
{
	if (!mgr.started) {
		return -EPERM;
	}
	if (ssid == NULL || ssid[0] == '\0') {
		return -EINVAL;
	}
	return network_prov_wifi_config_set_and_apply(
		(const uint8_t *)ssid, strlen(ssid),
		(const uint8_t *)(psk != NULL ? psk : ""),
		psk != NULL ? strlen(psk) : 0);
}

int network_prov_mgr_get_wifi_remaining_conn_attempts(uint32_t *attempts_remaining)
{
	if (attempts_remaining == NULL || !mgr.started) {
		return -EINVAL;
	}
	*attempts_remaining = network_prov_wifi_config_remaining_attempts();
	return 0;
}

void network_prov_mgr_wait(void)
{
	k_sem_take(&mgr.done, K_FOREVER);
}
