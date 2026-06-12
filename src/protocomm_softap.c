/*
 * SoftAP (HTTP) transport for protocomm.
 *
 * Mirrors ESP-IDF's protocomm_httpd + scheme_softap: each protocomm endpoint
 * is an HTTP POST URI ("/proto-ver", "/prov-session", ...) on a device-hosted
 * access point at 192.168.4.1:80. Request and response bodies are the raw
 * protobuf bytes. Session continuity — which security scheme 1 needs to keep
 * its AES-CTR keystream in lock-step — is tracked with a "session=<id>"
 * cookie: a request carrying no/another session's cookie resets the protocomm
 * session and is answered with a fresh Set-Cookie.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/random/random.h>
#include <zephyr/net/http/server.h>
#include <zephyr/net/http/service.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#if defined(CONFIG_WIFI)
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/wifi_mgmt.h>
#endif
#if defined(CONFIG_NET_DHCPV4_SERVER)
#include <zephyr/net/dhcpv4_server.h>
#endif

#include "protocomm.h"
#include "network_prov_internal.h"

LOG_MODULE_DECLARE(network_prov, CONFIG_NETWORK_PROV_LOG_LEVEL);

#define SOFTAP_IP_ADDR     "192.168.4.1"
#define SOFTAP_NETMASK     "255.255.255.0"
#define SOFTAP_DHCP_BASE   "192.168.4.10"
#define SOFTAP_KEY_MIN_LEN 8
#define SOFTAP_KEY_MAX_LEN 64

#define REQ_BUF_LEN  4096
#define RESP_BUF_LEN 4096

static struct protocomm *g_pc;

/* One request/response in flight at a time (the apps talk sequentially; the
 * sample limits CONFIG_HTTP_SERVER_MAX_CLIENTS accordingly).
 */
static uint8_t req_buf[REQ_BUF_LEN];
static size_t req_len;
static uint8_t resp_buf[RESP_BUF_LEN];
static char cookie_value[24];
static struct http_header resp_headers[1];

/* Current transport session, identified solely by the "session=<id>" cookie:
 * a request without a matching cookie always starts a fresh protocomm session
 * so an unknown client can never inherit another client's security state.
 * Both stock clients (esp_prov and the phone apps) echo cookies.
 */
static bool session_valid;
static uint32_t session_id;

static void start_new_session(void)
{
	protocomm_open_session(g_pc); /* resets any previous session */
	session_id = sys_rand32_get();
	session_valid = true;
	LOG_DBG("new HTTP provisioning session");
}

/* Case-insensitive ASCII compare (strcasecmp is hidden behind POSIX feature
 * macros by the host libc on native_sim).
 */
static bool str_ieq(const char *a, const char *b)
{
	while (*a != '\0' && *b != '\0') {
		char ca = (*a >= 'A' && *a <= 'Z') ? *a + ('a' - 'A') : *a;
		char cb = (*b >= 'A' && *b <= 'Z') ? *b + ('a' - 'A') : *b;

		if (ca != cb) {
			return false;
		}
		a++;
		b++;
	}
	return *a == *b;
}

/* Extract "session=<id>" from a captured Cookie header; false if absent. */
static bool get_cookie_session(const struct http_request_ctx *request_ctx,
			       uint32_t *out_id)
{
	if (request_ctx->headers_status != HTTP_HEADER_STATUS_OK) {
		return false;
	}

	for (size_t i = 0; i < request_ctx->header_count; i++) {
		const struct http_header *h = &request_ctx->headers[i];

		if (h->name == NULL || h->value == NULL ||
		    !str_ieq(h->name, "Cookie")) {
			continue;
		}

		const char *p = strstr(h->value, "session=");

		if (p == NULL) {
			return false;
		}
		*out_id = (uint32_t)strtoul(p + strlen("session="), NULL, 10);
		return true;
	}
	return false;
}

/* Cookie of the in-flight request. The server exposes captured headers only
 * in the FIRST callback for a request (it sets the capture status to NONE
 * afterwards), while the body may complete in a later callback — so remember
 * the cookie until the FINAL callback. The single dynamic-resource holder
 * serializes requests, so one slot suffices.
 */
static bool req_cookie_present;
static uint32_t req_cookie_id;

static void ensure_session(void)
{
	if (req_cookie_present && session_valid && req_cookie_id == session_id) {
		return; /* same session continues */
	}
	start_new_session();
}

static int prov_http_handler(struct http_client_ctx *client,
			     enum http_transaction_status status,
			     const struct http_request_ctx *request_ctx,
			     struct http_response_ctx *response_ctx,
			     void *user_data)
{
	const char *ep_name = user_data;

	if (status == HTTP_SERVER_TRANSACTION_ABORTED ||
	    status == HTTP_SERVER_TRANSACTION_COMPLETE) {
		req_len = 0;
		req_cookie_present = false;
		return 0;
	}

	if (request_ctx->headers_status == HTTP_HEADER_STATUS_OK) {
		/* First callback of this request: capture the cookie. */
		req_cookie_present = get_cookie_session(request_ctx,
							&req_cookie_id);
	}

	/* Accumulate the (possibly chunked) request body. */
	if (request_ctx->data_len + req_len > sizeof(req_buf)) {
		LOG_ERR("request for '%s' exceeds %d bytes", ep_name, REQ_BUF_LEN);
		req_len = 0;
		return -ENOMEM;
	}
	memcpy(req_buf + req_len, request_ctx->data, request_ctx->data_len);
	req_len += request_ctx->data_len;

	if (status != HTTP_SERVER_REQUEST_DATA_FINAL) {
		return 0;
	}

	ensure_session();
	req_cookie_present = false;

	uint8_t *out = NULL;
	size_t outlen = 0;
	int ret = protocomm_req_handle(g_pc, ep_name, req_buf, req_len,
				       &out, &outlen);

	req_len = 0;
	if (ret != 0) {
		LOG_WRN("endpoint '%s' failed: %d", ep_name, ret);
		k_free(out);
		response_ctx->status = HTTP_500_INTERNAL_SERVER_ERROR;
		response_ctx->final_chunk = true;
		return 0;
	}

	if (outlen > sizeof(resp_buf)) {
		LOG_ERR("response for '%s' exceeds %d bytes", ep_name, RESP_BUF_LEN);
		k_free(out);
		response_ctx->status = HTTP_500_INTERNAL_SERVER_ERROR;
		response_ctx->final_chunk = true;
		return 0;
	}

	/* Copy into static storage: the response is transmitted after this
	 * callback returns, so the k_malloc'd buffer cannot be handed over.
	 */
	if (outlen > 0) {
		memcpy(resp_buf, out, outlen);
	}
	k_free(out);

	snprintf(cookie_value, sizeof(cookie_value), "session=%u", session_id);
	resp_headers[0].name = "Set-Cookie";
	resp_headers[0].value = cookie_value;

	response_ctx->headers = resp_headers;
	response_ctx->header_count = 1;
	response_ctx->body = resp_buf;
	response_ctx->body_len = outlen;
	response_ctx->final_chunk = true;
	return 0;
}

#if defined(CONFIG_HTTP_SERVER_CAPTURE_HEADERS)
HTTP_SERVER_REGISTER_HEADER_CAPTURE(prov_capture_cookie, "Cookie");
#endif

static uint16_t prov_http_port = 80;

HTTP_SERVICE_DEFINE(network_prov_http_service, NULL, &prov_http_port,
		    CONFIG_HTTP_SERVER_MAX_CLIENTS, 4, NULL, NULL, NULL);

/* The manager's endpoint set is fixed, so the URI table is static. */
#define PROV_HTTP_RESOURCE(_sym, _uri)                                         \
	static struct http_resource_detail_dynamic _sym##_detail = {           \
		.common = {                                                    \
			.type = HTTP_RESOURCE_TYPE_DYNAMIC,                    \
			.bitmask_of_supported_http_methods = BIT(HTTP_POST),   \
		},                                                             \
		.cb = prov_http_handler,                                       \
		.user_data = (void *)&_uri[1], /* endpoint name = URI sans '/' */ \
	};                                                                     \
	HTTP_RESOURCE_DEFINE(_sym, network_prov_http_service, _uri, &_sym##_detail)

static const char uri_proto_ver[] = "/proto-ver";
static const char uri_session[] = "/prov-session";
static const char uri_scan[] = "/prov-scan";
static const char uri_config[] = "/prov-config";
static const char uri_ctrl[] = "/prov-ctrl";

PROV_HTTP_RESOURCE(prov_res_proto_ver, uri_proto_ver);
PROV_HTTP_RESOURCE(prov_res_session, uri_session);
PROV_HTTP_RESOURCE(prov_res_scan, uri_scan);
PROV_HTTP_RESOURCE(prov_res_config, uri_config);
PROV_HTTP_RESOURCE(prov_res_ctrl, uri_ctrl);

int network_prov_softap_http_start(struct protocomm *pc)
{
	g_pc = pc;
	req_len = 0;
	session_valid = false;

	int ret = http_server_start();

	if (ret < 0 && ret != -EALREADY) {
		LOG_ERR("http_server_start failed: %d", ret);
		return ret;
	}
	return 0;
}

void network_prov_softap_http_stop(void)
{
	(void)http_server_stop();
	session_valid = false;
	g_pc = NULL;
}

#if defined(CONFIG_WIFI)
static int softap_ap_start(const char *service_name, const char *service_key)
{
	struct net_if *iface = net_if_get_wifi_sap();

	if (iface == NULL) {
		LOG_ERR("No Wi-Fi AP interface (enable AP/STA mode)");
		return -ENODEV;
	}

	size_t key_len = (service_key != NULL) ? strlen(service_key) : 0;

	if (key_len > 0 &&
	    (key_len < SOFTAP_KEY_MIN_LEN || key_len > SOFTAP_KEY_MAX_LEN)) {
		LOG_ERR("service_key must be %d..%d characters (or empty)",
			SOFTAP_KEY_MIN_LEN, SOFTAP_KEY_MAX_LEN);
		return -EINVAL;
	}

	struct in_addr addr;
	struct in_addr netmask;

	if (net_addr_pton(AF_INET, SOFTAP_IP_ADDR, &addr) != 0 ||
	    net_addr_pton(AF_INET, SOFTAP_NETMASK, &netmask) != 0) {
		return -EINVAL;
	}

	net_if_ipv4_set_gw(iface, &addr);
	if (net_if_ipv4_addr_add(iface, &addr, NET_ADDR_MANUAL, 0) == NULL) {
		LOG_WRN("AP address already configured");
	}
	net_if_ipv4_set_netmask_by_addr(iface, &addr, &netmask);

#if defined(CONFIG_NET_DHCPV4_SERVER)
	struct in_addr pool;

	if (net_addr_pton(AF_INET, SOFTAP_DHCP_BASE, &pool) != 0) {
		return -EINVAL;
	}

	int dret = net_dhcpv4_server_start(iface, &pool);

	if (dret != 0 && dret != -EALREADY) {
		LOG_ERR("DHCPv4 server start failed: %d", dret);
		return dret;
	}
#endif

	struct wifi_connect_req_params params = {0};

	params.ssid = (const uint8_t *)service_name;
	params.ssid_length = strlen(service_name);
	params.psk = (key_len > 0) ? (const uint8_t *)service_key : NULL;
	params.psk_length = key_len;
	params.security = (key_len > 0) ? WIFI_SECURITY_TYPE_PSK
					: WIFI_SECURITY_TYPE_NONE;
	params.channel = WIFI_CHANNEL_ANY;
	params.band = WIFI_FREQ_BAND_2_4_GHZ;

	int ret = net_mgmt(NET_REQUEST_WIFI_AP_ENABLE, iface, &params,
			   sizeof(params));

	if (ret != 0) {
		LOG_ERR("AP enable failed: %d", ret);
		return ret;
	}

	LOG_INF("SoftAP '%s' up (%s), provisioning at http://%s",
		service_name, (key_len > 0) ? "WPA2-PSK" : "open",
		SOFTAP_IP_ADDR);
	return 0;
}

static void softap_ap_stop(void)
{
	struct net_if *iface = net_if_get_wifi_sap();

	if (iface == NULL) {
		return;
	}
#if defined(CONFIG_NET_DHCPV4_SERVER)
	(void)net_dhcpv4_server_stop(iface);
#endif
	(void)net_mgmt(NET_REQUEST_WIFI_AP_DISABLE, iface, NULL, 0);
}
#endif /* CONFIG_WIFI */

int network_prov_softap_start(struct protocomm *pc, const char *service_name,
			      const char *service_key)
{
	if (service_name == NULL || service_name[0] == '\0') {
		return -EINVAL;
	}

#if defined(CONFIG_WIFI)
	int ret = softap_ap_start(service_name, service_key);

	if (ret != 0) {
		return ret;
	}
#else
	ARG_UNUSED(service_key);
#endif

	return network_prov_softap_http_start(pc);
}

void network_prov_softap_stop(void)
{
	network_prov_softap_http_stop();
#if defined(CONFIG_WIFI)
	softap_ap_stop();
#endif
}
