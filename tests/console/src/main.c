/*
 * Integration test for the console (shell) transport.
 *
 * Runs the real provisioning manager with the console scheme on
 * native_sim, backed by the fake Wi-Fi driver, and drives it through the
 * `net_prov` shell command over the dummy shell backend — exactly the way
 * esp_prov's console transport feeds (endpoint, session_id, hex) lines to the
 * device. The shared security-1 client runs the full handshake and an
 * encrypted GetWifiStatus round-trip, so the console transport, the manager
 * SCHEME_CONSOLE wiring and the sec1 framing are all exercised together.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <zephyr/kernel.h>
#include <zephyr/ztest.h>
#include <zephyr/shell/shell.h>
#include <zephyr/shell/shell_dummy.h>
#include <zephyr/sys/util.h>

#include <pb_encode.h>
#include <pb_decode.h>
#include "constants.pb.h"
#include "network_config.pb.h"

#include "network_provisioning/network_prov_mgr.h"
#include "network_provisioning/scheme_console.h"
#include "network_provisioning/test/fake_wifi.h"
#include "prov_client.h"

#define POP        "abcd1234"
#define GOOD_SSID  "HomeNet"
#define GOOD_PASS  "correct-horse-battery"

/* Carries the dummy shell and the per-session id into the prov_client transport
 * callback. One esp_prov console session == one constant session_id.
 */
struct console_ctx {
	const struct shell *sh;
	uint32_t sid;
};

/*
 * prov_client transport adapter: hex-encode the request, run
 * "net_prov <ep> <sid> <hex>" on the dummy shell, and return the device's hex
 * response decoded into a k_malloc()'d buffer (freed by the caller). This is
 * the device side of esp_prov's human-in-the-loop console bridging.
 */
static int console_xport(void *ctx, const char *ep, const uint8_t *in, size_t inlen,
			 uint8_t **out, size_t *outlen)
{
	struct console_ctx *cc = ctx;
	static char hexin[1024];
	static char cmd[1152];

	if (inlen == 0 || inlen * 2 + 1 > sizeof(hexin)) {
		return -EINVAL;
	}
	(void)bin2hex(in, inlen, hexin, sizeof(hexin));

	int n = snprintf(cmd, sizeof(cmd), "net_prov %s %u %s", ep, cc->sid, hexin);

	if (n < 0 || n >= (int)sizeof(cmd)) {
		return -E2BIG;
	}

	shell_backend_dummy_clear_output(cc->sh);
	int ret = shell_execute_cmd(cc->sh, cmd);

	if (ret != 0) {
		return -EIO;
	}

	size_t raw_len = 0;
	const char *raw = shell_backend_dummy_get_output(cc->sh, &raw_len);

	/* The response line is lowercase hex; skip the shell's surrounding
	 * whitespace/newlines and read the contiguous run of hex digits.
	 */
	const char *p = raw;

	while (*p != '\0' && !isxdigit((unsigned char)*p)) {
		p++;
	}
	size_t hlen = 0;

	while (isxdigit((unsigned char)p[hlen])) {
		hlen++;
	}
	if ((hlen & 1) != 0) {
		return -EILSEQ;
	}

	size_t blen = hlen / 2;
	uint8_t *buf = k_malloc(blen > 0 ? blen : 1);

	if (buf == NULL) {
		return -ENOMEM;
	}
	if (blen > 0 && hex2bin(p, hlen, buf, blen) != blen) {
		k_free(buf);
		return -EILSEQ;
	}
	*out = buf;
	*outlen = blen;
	return 0;
}

static void program_network(void)
{
	const struct fake_wifi_ap aps[] = {
		{ .ssid = GOOD_SSID, .ssid_len = sizeof(GOOD_SSID) - 1, .channel = 6,
		  .rssi = -40, .security = WIFI_SECURITY_TYPE_PSK,
		  .bssid = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55} },
	};

	fake_wifi_set_scan_aps(aps, ARRAY_SIZE(aps));
	fake_wifi_set_expected_credentials(GOOD_SSID, GOOD_PASS);
}

static void *suite_setup(void)
{
	struct network_prov_mgr_config cfg = {
		.scheme = &network_prov_scheme_console,
		.wifi_conn_attempts = 0,
	};

	fake_wifi_reset();
	program_network();

	zassert_equal(network_prov_mgr_init(cfg), 0, "manager init failed");
	/* Stay up across all sub-tests; the console transport has no teardown
	 * grace to worry about, but be explicit.
	 */
	zassert_equal(network_prov_mgr_disable_auto_stop(0), 0);
	zassert_equal(network_prov_mgr_start_provisioning(NETWORK_PROV_SECURITY_1,
							  POP, "PROV_CON", NULL),
		      0, "start_provisioning failed");

	/* Let the shell backend become active before issuing commands. */
	k_sleep(K_MSEC(100));
	return NULL;
}

static void suite_teardown(void *fixture)
{
	ARG_UNUSED(fixture);
	network_prov_mgr_stop_provisioning();
	network_prov_mgr_deinit();
}

ZTEST(console, test_proto_ver)
{
	struct console_ctx cc = { .sh = shell_backend_dummy_get_ptr(), .sid = 0 };
	uint8_t req = 0; /* proto-ver ignores its request body */
	uint8_t *resp = NULL;
	size_t rlen = 0;

	zassert_equal(console_xport(&cc, "proto-ver", &req, 1, &resp, &rlen), 0,
		      "proto-ver request failed");
	zassert_true(rlen > 0, "empty proto-ver response");

	char json[256];

	zassert_true(rlen < sizeof(json), "proto-ver response too large");
	memcpy(json, resp, rlen);
	json[rlen] = '\0';
	k_free(resp);

	zassert_not_null(strstr(json, "\"sec_ver\":1"),
			 "proto-ver JSON missing sec_ver: %s", json);
	zassert_not_null(strstr(json, "wifi_prov"), "proto-ver JSON missing caps");
}

ZTEST(console, test_handshake_then_get_wifi_status)
{
	struct console_ctx cc = { .sh = shell_backend_dummy_get_ptr(), .sid = 0 };
	struct prov_client c;

	prov_client_init(&c, console_xport, &cc);
	zassert_equal(prov_client_handshake(&c, POP), 0,
		      "security-1 handshake over the console failed");

	/* Encrypted GetWifiStatus through the prov-config data endpoint: the
	 * shared CTR keystream must be in lock-step or the reply decodes to
	 * garbage.
	 */
	NetworkConfigPayload cmd = NetworkConfigPayload_init_default;

	cmd.msg = NetworkConfigMsgType_TypeCmdGetWifiStatus;
	cmd.which_payload = NetworkConfigPayload_cmd_get_wifi_status_tag;

	uint8_t plain[64];
	pb_ostream_t os = pb_ostream_from_buffer(plain, sizeof(plain));

	zassert_true(pb_encode(&os, NetworkConfigPayload_fields, &cmd),
		     "encode CmdGetWifiStatus failed");

	uint8_t enc[64];

	zassert_equal(prov_client_xform(&c, plain, os.bytes_written, enc), 0,
		      "request encrypt failed");

	uint8_t *resp = NULL;
	size_t rlen = 0;

	zassert_equal(console_xport(&cc, "prov-config", enc, os.bytes_written,
				    &resp, &rlen), 0,
		      "prov-config request failed");
	zassert_true(rlen > 0 && rlen <= sizeof(plain), "bad response length %zu", rlen);

	uint8_t dec[64];

	zassert_equal(prov_client_xform(&c, resp, rlen, dec), 0,
		      "response decrypt failed");
	k_free(resp);

	NetworkConfigPayload r = NetworkConfigPayload_init_default;
	pb_istream_t is = pb_istream_from_buffer(dec, rlen);

	zassert_true(pb_decode(&is, NetworkConfigPayload_fields, &r),
		     "decode RespGetWifiStatus failed (keystream desync?)");
	zassert_equal(r.msg, NetworkConfigMsgType_TypeRespGetWifiStatus,
		      "unexpected response msg type %d", r.msg);
	zassert_equal(r.payload.resp_get_wifi_status.status, Status_Success,
		      "GetWifiStatus reported status %d",
		      r.payload.resp_get_wifi_status.status);

	prov_client_destroy(&c);
}

ZTEST(console, test_session_reset_on_new_session_id)
{
	struct console_ctx cc = { .sh = shell_backend_dummy_get_ptr(), .sid = 1 };
	struct prov_client c;

	/* Handshake under session id 1. */
	prov_client_init(&c, console_xport, &cc);
	zassert_equal(prov_client_handshake(&c, POP), 0, "handshake (sid 1) failed");

	/* A new session_id must reset the protocomm session: the old keystream
	 * is dead, so an encrypted request decodes to a protobuf the device
	 * cannot parse and the endpoint handler fails (non-zero shell return ->
	 * -EIO from the adapter).
	 */
	cc.sid = 2;

	uint8_t msg[8] = { 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04 };
	uint8_t enc[8];

	zassert_equal(prov_client_xform(&c, msg, sizeof(msg), enc), 0);

	uint8_t *resp = NULL;
	size_t rlen = 0;

	zassert_true(console_xport(&cc, "prov-config", enc, sizeof(enc), &resp, &rlen) < 0,
		     "stale-keystream request should fail after a session reset");

	prov_client_destroy(&c);
}

ZTEST_SUITE(console, NULL, suite_setup, NULL, NULL, suite_teardown);
