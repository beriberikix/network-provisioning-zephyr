/*
 * Tester (device 1): a GATT central that drives a full provisioning flow
 * against the DUT over the real BLE transport, the way the stock ESP BLE
 * provisioning apps and esp_prov do:
 *
 *   scan/connect -> discover the provisioning service -> map endpoints by their
 *   CUD descriptors -> read proto-ver -> run the security-1 handshake (shared
 *   prov_client) -> prov-scan -> prov-config (set + apply) -> poll status.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <errno.h>
#include <zephyr/kernel.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/bluetooth/att.h>
#include <zephyr/net_buf.h>

#include "testlib/conn.h"
#include "testlib/scan.h"
#include "testlib/att.h"
#include "testlib/att_read.h"
#include "testlib/att_write.h"
#include "babblekit/testcase.h"

#include <pb_encode.h>
#include <pb_decode.h>
#include "network_scan.pb.h"
#include "network_config.pb.h"
#include "network_constants.pb.h"
#include "constants.pb.h"

#include "protocomm.h"
#include "prov_client.h"
#include "common.h"

#define WAIT_TIME_S 30
#define WAIT_TIME   (WAIT_TIME_S * 1e6)

/* The DUT overrides the service UUID via network_prov_scheme_ble_set_service_uuid();
 * discovering by it proves the override took effect.
 */
#define PROV_SERVICE_UUID_VAL PROV_TEST_SVC_UUID

static struct bt_conn *g_conn;

/* endpoint name -> GATT value handle, discovered from the CUD descriptors. */
struct ep_entry {
	char name[PROTOCOMM_EP_NAME_MAX];
	uint16_t handle;
};
static struct ep_entry eps[PROTOCOMM_MAX_ENDPOINTS];
static size_t ep_count;

/* --- low-level GATT helpers ----------------------------------------------- */

static int gatt_write(uint16_t handle, const uint8_t *data, uint16_t len)
{
	return bt_testlib_att_write(g_conn, BT_ATT_CHAN_OPT_NONE, handle, data, len);
}

static int gatt_read(uint16_t handle, uint8_t *out, size_t cap, size_t *outlen)
{
	NET_BUF_SIMPLE_DEFINE(buf, 600);
	uint16_t size = 0, mtu = 0;
	int err = bt_testlib_att_read_by_handle_sync(&buf, &size, &mtu, g_conn,
						     BT_ATT_CHAN_OPT_NONE, handle, 0);

	if (err) {
		return -EIO;
	}
	if (buf.len > cap) {
		return -ENOMEM;
	}
	memcpy(out, buf.data, buf.len);
	*outlen = buf.len;
	return 0;
}

static uint16_t ep_handle(const char *name)
{
	for (size_t i = 0; i < ep_count; i++) {
		if (strcmp(eps[i].name, name) == 0) {
			return eps[i].handle;
		}
	}
	return 0;
}

/* --- prov_client transport adapter (plaintext session endpoint) ----------- */

static int gatt_xport(void *ctx, const char *ep, const uint8_t *in, size_t inlen,
		      uint8_t **out, size_t *outlen)
{
	ARG_UNUSED(ctx);
	uint16_t h = ep_handle(ep);

	if (h == 0) {
		return -ENOENT;
	}

	int err = gatt_write(h, in, inlen);

	if (err) {
		return err;
	}

	uint8_t tmp[256];
	size_t n = 0;

	err = gatt_read(h, tmp, sizeof(tmp), &n);
	if (err) {
		return err;
	}

	uint8_t *buf = k_malloc(n > 0 ? n : 1);

	if (buf == NULL) {
		return -ENOMEM;
	}
	memcpy(buf, tmp, n);
	*out = buf;
	*outlen = n;
	return 0;
}

/* --- encrypted endpoint round trip (post-handshake) ----------------------- */

static int secure_exchange(struct prov_client *c, const char *ep,
			   const uint8_t *plain, size_t plen,
			   uint8_t *out, size_t cap, size_t *outlen)
{
	uint16_t h = ep_handle(ep);
	uint8_t enc[256];

	if (h == 0) {
		return -ENOENT;
	}
	if (plen > sizeof(enc)) {
		return -ENOMEM;
	}

	int err = prov_client_xform(c, plain, plen, enc);

	if (err) {
		return err;
	}
	err = gatt_write(h, enc, plen);
	if (err) {
		return err;
	}

	uint8_t resp[256];
	size_t rn = 0;

	err = gatt_read(h, resp, sizeof(resp), &rn);
	if (err) {
		return err;
	}
	if (rn > cap) {
		return -ENOMEM;
	}

	err = prov_client_xform(c, resp, rn, out);
	if (err) {
		return err;
	}
	*outlen = rn;
	return 0;
}

/* --- service / endpoint discovery ----------------------------------------- */

static void read_cud(uint16_t value_handle, char *name, size_t cap)
{
	uint8_t tmp[PROTOCOMM_EP_NAME_MAX + 1];
	size_t n = 0;

	name[0] = '\0';
	/* The CUD descriptor immediately follows the characteristic value. */
	if (gatt_read(value_handle + 1, tmp, sizeof(tmp) - 1, &n) == 0) {
		n = MIN(n, cap - 1);
		memcpy(name, tmp, n);
		name[n] = '\0';
	}
}

static void discover_endpoints(void)
{
	struct bt_uuid_128 svc_uuid = BT_UUID_INIT_128(PROV_SERVICE_UUID_VAL);
	uint16_t svc_start = 0, svc_end = 0;

	int err = bt_testlib_gatt_discover_primary(&svc_start, &svc_end, g_conn,
						   &svc_uuid.uuid, BT_ATT_FIRST_ATTRIBUTE_HANDLE,
						   BT_ATT_LAST_ATTRIBUTE_HANDLE);

	TEST_ASSERT(err == 0, "provisioning service not found (err %d)", err);
	TEST_PRINT("tester: service handles %u..%u", svc_start, svc_end);

	/* Per-endpoint characteristic UUIDs derive from the base with the low
	 * byte varied (protocomm_ble.c). Walk them, then read each CUD to learn
	 * the endpoint name, exactly as the stock apps map endpoints.
	 */
	for (size_t i = 0; i < PROTOCOMM_MAX_ENDPOINTS; i++) {
		struct bt_uuid_128 cuuid = BT_UUID_INIT_128(PROV_SERVICE_UUID_VAL);
		uint16_t vh = 0, end = 0, def = 0;

		cuuid.val[12] = 0xF0 + (uint8_t)i;

		if (bt_testlib_gatt_discover_characteristic(&vh, &end, &def, g_conn,
							    &cuuid.uuid, svc_start,
							    svc_end) != 0) {
			continue;
		}

		read_cud(vh, eps[ep_count].name, sizeof(eps[ep_count].name));
		eps[ep_count].handle = vh;
		TEST_PRINT("tester: endpoint '%s' -> handle %u", eps[ep_count].name, vh);
		ep_count++;
	}

	TEST_ASSERT(ep_handle("prov-session") != 0, "prov-session endpoint missing");
	TEST_ASSERT(ep_handle("prov-scan") != 0, "prov-scan endpoint missing");
	TEST_ASSERT(ep_handle("prov-config") != 0, "prov-config endpoint missing");
}

/* --- provisioning flow ---------------------------------------------------- */

static void check_proto_ver(void)
{
	uint16_t h = ep_handle("proto-ver");
	uint8_t resp[192];
	size_t n = 0;

	TEST_ASSERT(h != 0, "proto-ver endpoint missing");

	/* A protocomm request is a write (which runs the handler and caches the
	 * response) followed by a read of the same characteristic.
	 */
	TEST_ASSERT(gatt_write(h, (const uint8_t *)"---", 3) == 0, "proto-ver write failed");
	TEST_ASSERT(gatt_read(h, resp, sizeof(resp) - 1, &n) == 0, "proto-ver read failed");
	resp[n] = '\0';
	TEST_PRINT("tester: proto-ver = %s", resp);
	TEST_ASSERT(strstr((char *)resp, "sec_ver") != NULL,
		    "proto-ver capabilities missing sec_ver");
	/* The app-info section set by the DUT must be present (set_app_info). */
	TEST_ASSERT(strstr((char *)resp, "\"" PROV_TEST_APP_LABEL "\"") != NULL,
		    "proto-ver missing app-info label");
	TEST_ASSERT(strstr((char *)resp, "\"" PROV_TEST_APP_CAP "\"") != NULL,
		    "proto-ver missing app-info capability");
}

static void do_scan(struct prov_client *c)
{
	uint8_t plain[64], resp[256];
	size_t rn;
	pb_ostream_t os;
	pb_istream_t is;

	/* CmdScanWifiStart(blocking=true): like the stock apps, ask the device to
	 * hold the response until the scan completes. The status poll below is
	 * then satisfied on its first iteration.
	 */
	NetworkScanPayload req = NetworkScanPayload_init_default;

	req.msg = NetworkScanMsgType_TypeCmdScanWifiStart;
	req.which_payload = NetworkScanPayload_cmd_scan_wifi_start_tag;
	req.payload.cmd_scan_wifi_start.blocking = true;

	os = pb_ostream_from_buffer(plain, sizeof(plain));
	TEST_ASSERT(pb_encode(&os, NetworkScanPayload_fields, &req), "scan-start encode");
	TEST_ASSERT(secure_exchange(c, "prov-scan", plain, os.bytes_written, resp,
				    sizeof(resp), &rn) == 0, "scan-start exchange");

	NetworkScanPayload sresp = NetworkScanPayload_init_default;

	is = pb_istream_from_buffer(resp, rn);
	TEST_ASSERT(pb_decode(&is, NetworkScanPayload_fields, &sresp), "scan-start decode");
	TEST_ASSERT(sresp.msg == NetworkScanMsgType_TypeRespScanWifiStart,
		    "scan-start unexpected msg %d (keystream desync?)", sresp.msg);
	TEST_ASSERT(sresp.status == Status_Success, "scan-start status %d", sresp.status);

	/* CmdScanWifiStatus, polled until the scan reports finished (a blocking
	 * start already waits, but poll anyway to be robust to async timing).
	 */
	uint32_t count = 0;
	bool finished = false;

	for (int i = 0; i < 25 && !finished; i++) {
		req = (NetworkScanPayload)NetworkScanPayload_init_default;
		req.msg = NetworkScanMsgType_TypeCmdScanWifiStatus;
		req.which_payload = NetworkScanPayload_cmd_scan_wifi_status_tag;

		os = pb_ostream_from_buffer(plain, sizeof(plain));
		TEST_ASSERT(pb_encode(&os, NetworkScanPayload_fields, &req), "scan-status encode");
		TEST_ASSERT(secure_exchange(c, "prov-scan", plain, os.bytes_written, resp,
					    sizeof(resp), &rn) == 0, "scan-status exchange");

		sresp = (NetworkScanPayload)NetworkScanPayload_init_default;
		is = pb_istream_from_buffer(resp, rn);
		TEST_ASSERT(pb_decode(&is, NetworkScanPayload_fields, &sresp), "scan-status decode");

		finished = sresp.payload.resp_scan_wifi_status.scan_finished;
		count = sresp.payload.resp_scan_wifi_status.result_count;
		if (!finished) {
			k_sleep(K_MSEC(100));
		}
	}

	TEST_ASSERT(finished, "scan never finished");

	TEST_PRINT("tester: scan reported %u AP(s)", count);
	TEST_ASSERT(count == 2, "expected 2 canned APs, got %u", count);
}

static void do_config(struct prov_client *c)
{
	uint8_t plain[96], resp[256];
	size_t rn = 0;
	pb_ostream_t os;
	pb_istream_t is;

	/* CmdSetWifiConfig(ssid, passphrase). */
	NetworkConfigPayload req = NetworkConfigPayload_init_default;

	req.msg = NetworkConfigMsgType_TypeCmdSetWifiConfig;
	req.which_payload = NetworkConfigPayload_cmd_set_wifi_config_tag;
	req.payload.cmd_set_wifi_config.ssid.size = sizeof(PROV_TEST_SSID) - 1;
	memcpy(req.payload.cmd_set_wifi_config.ssid.bytes, PROV_TEST_SSID,
	       sizeof(PROV_TEST_SSID) - 1);
	req.payload.cmd_set_wifi_config.passphrase.size = sizeof(PROV_TEST_PASS) - 1;
	memcpy(req.payload.cmd_set_wifi_config.passphrase.bytes, PROV_TEST_PASS,
	       sizeof(PROV_TEST_PASS) - 1);

	os = pb_ostream_from_buffer(plain, sizeof(plain));
	TEST_ASSERT(pb_encode(&os, NetworkConfigPayload_fields, &req), "set-config encode");
	TEST_ASSERT(secure_exchange(c, "prov-config", plain, os.bytes_written, resp,
				    sizeof(resp), &rn) == 0, "set-config exchange");

	NetworkConfigPayload cresp = NetworkConfigPayload_init_default;

	is = pb_istream_from_buffer(resp, rn);
	TEST_ASSERT(pb_decode(&is, NetworkConfigPayload_fields, &cresp), "set-config decode");
	TEST_ASSERT(cresp.payload.resp_set_wifi_config.status == Status_Success,
		    "set-config rejected");

	/* CmdApplyWifiConfig. */
	req = (NetworkConfigPayload)NetworkConfigPayload_init_default;
	req.msg = NetworkConfigMsgType_TypeCmdApplyWifiConfig;
	req.which_payload = NetworkConfigPayload_cmd_apply_wifi_config_tag;

	os = pb_ostream_from_buffer(plain, sizeof(plain));
	TEST_ASSERT(pb_encode(&os, NetworkConfigPayload_fields, &req), "apply-config encode");
	TEST_ASSERT(secure_exchange(c, "prov-config", plain, os.bytes_written, resp,
				    sizeof(resp), &rn) == 0, "apply-config exchange");

	cresp = (NetworkConfigPayload)NetworkConfigPayload_init_default;
	is = pb_istream_from_buffer(resp, rn);
	TEST_ASSERT(pb_decode(&is, NetworkConfigPayload_fields, &cresp), "apply-config decode");
	TEST_ASSERT(cresp.payload.resp_apply_wifi_config.status == Status_Success,
		    "apply-config rejected");
}

/* Poll GetWifiStatus until it leaves the Connecting state; returns the final
 * WifiStationState.
 */
static int poll_status(struct prov_client *c)
{
	for (int i = 0; i < 50; i++) {
		uint8_t plain[16], resp[256];
		size_t rn;

		NetworkConfigPayload req = NetworkConfigPayload_init_default;

		req.msg = NetworkConfigMsgType_TypeCmdGetWifiStatus;
		req.which_payload = NetworkConfigPayload_cmd_get_wifi_status_tag;

		pb_ostream_t os = pb_ostream_from_buffer(plain, sizeof(plain));

		TEST_ASSERT(pb_encode(&os, NetworkConfigPayload_fields, &req), "status encode");
		TEST_ASSERT(secure_exchange(c, "prov-config", plain, os.bytes_written, resp,
					    sizeof(resp), &rn) == 0, "status exchange");

		NetworkConfigPayload sresp = NetworkConfigPayload_init_default;
		pb_istream_t is = pb_istream_from_buffer(resp, rn);

		TEST_ASSERT(pb_decode(&is, NetworkConfigPayload_fields, &sresp), "status decode");

		int state = sresp.payload.resp_get_wifi_status.wifi_sta_state;

		if (state != WifiStationState_Connecting) {
			return state;
		}
		k_sleep(K_MSEC(200));
	}
	return WifiStationState_Connecting;
}

/* Round-trip through the application custom endpoint over the secure session
 * (network_prov_mgr_endpoint_create/register on the DUT). The DUT echoes
 * "echo:<msg>".
 */
static void verify_custom_endpoint(struct prov_client *c)
{
	uint8_t resp[64];
	size_t rn = 0;
	char expect[64];
	int n = snprintf(expect, sizeof(expect), "echo:%s", PROV_TEST_CUSTOM_MSG);

	TEST_ASSERT(secure_exchange(c, PROV_TEST_CUSTOM_EP,
				    (const uint8_t *)PROV_TEST_CUSTOM_MSG,
				    strlen(PROV_TEST_CUSTOM_MSG), resp, sizeof(resp),
				    &rn) == 0, "custom endpoint exchange failed");
	TEST_ASSERT(rn == (size_t)n && memcmp(resp, expect, n) == 0,
		    "custom endpoint echo mismatch");
	TEST_PRINT("tester: custom endpoint echo OK");
}

static bool mfg_seen;

static bool mfg_ad_cb(struct bt_data *data, void *user_data)
{
	static const uint8_t want[] = PROV_TEST_MFG_DATA;

	ARG_UNUSED(user_data);
	if (data->type == BT_DATA_MANUFACTURER_DATA &&
	    data->data_len == sizeof(want) &&
	    memcmp(data->data, want, sizeof(want)) == 0) {
		mfg_seen = true;
		return false;
	}
	return true;
}

static void mfg_scan_cb(const bt_addr_le_t *addr, int8_t rssi, uint8_t type,
			struct net_buf_simple *ad)
{
	ARG_UNUSED(addr);
	ARG_UNUSED(rssi);
	ARG_UNUSED(type);
	bt_data_parse(ad, mfg_ad_cb, NULL);
}

/* Active-scan and confirm the DUT advertises the manufacturer data set via
 * network_prov_scheme_ble_set_mfg_data() (carried in the scan response).
 */
static void verify_mfg_data(void)
{
	struct bt_le_scan_param param = {
		.type = BT_LE_SCAN_TYPE_ACTIVE,
		.options = BT_LE_SCAN_OPT_NONE,
		.interval = BT_GAP_SCAN_FAST_INTERVAL,
		.window = BT_GAP_SCAN_FAST_WINDOW,
	};

	mfg_seen = false;
	TEST_ASSERT(bt_le_scan_start(&param, mfg_scan_cb) == 0, "mfg scan start failed");
	for (int i = 0; i < 50 && !mfg_seen; i++) {
		k_sleep(K_MSEC(100));
	}
	(void)bt_le_scan_stop();
	TEST_ASSERT(mfg_seen, "manufacturer data not found in scan response");
}

static void tester_run(bool expect_success)
{
	bt_addr_le_t addr;
	int err;

	TEST_ASSERT(bt_enable(NULL) == 0, "bt_enable failed");

	verify_mfg_data();

	err = bt_testlib_scan_find_name(&addr, PROV_TEST_NAME);
	TEST_ASSERT(err == 0, "could not find '%s' (err %d)", PROV_TEST_NAME, err);

	err = bt_testlib_connect(&addr, &g_conn);
	TEST_ASSERT(err == 0, "connect failed (err %d)", err);

	(void)bt_testlib_att_exchange_mtu(g_conn);

	discover_endpoints();
	check_proto_ver();

	struct prov_client c;

	prov_client_init(&c, gatt_xport, NULL);
	TEST_ASSERT(prov_client_handshake(&c, PROV_TEST_POP) == 0,
		    "security-1 handshake failed");
	TEST_PRINT("tester: secure session established");

	verify_custom_endpoint(&c);
	do_scan(&c);
	do_config(&c);

	int state = poll_status(&c);

	if (expect_success) {
		TEST_ASSERT(state == WifiStationState_Connected,
			    "expected Connected, got state %d", state);
	} else {
		TEST_ASSERT(state == WifiStationState_ConnectionFailed,
			    "expected ConnectionFailed, got state %d", state);
	}

	prov_client_destroy(&c);
	TEST_PASS("tester: provisioning flow completed (state %d)", state);
}

static void tester_main_success(void)
{
	tester_run(true);
}

static void tester_main_wrong_password(void)
{
	tester_run(false);
}

static void tester_tick(bs_time_t HW_device_time)
{
	ARG_UNUSED(HW_device_time);
	if (bst_result != Passed) {
		TEST_FAIL("tester: did not pass within %d seconds", WAIT_TIME_S);
	}
}

static void tester_init(void)
{
	bst_ticker_set_next_tick_absolute(WAIT_TIME);
	bst_result = In_progress;
}

static const struct bst_test_instance tester_tests[] = {
	{
		.test_id = "tester_success",
		.test_descr = "Drive a successful provisioning flow over BLE",
		.test_pre_init_f = tester_init,
		.test_tick_f = tester_tick,
		.test_main_f = tester_main_success,
	},
	{
		.test_id = "tester_wrong_password",
		.test_descr = "Drive provisioning and expect a connection failure",
		.test_pre_init_f = tester_init,
		.test_tick_f = tester_tick,
		.test_main_f = tester_main_wrong_password,
	},
	BSTEST_END_MARKER,
};

struct bst_test_list *tester_install(struct bst_test_list *tests)
{
	return bst_add_tests(tests, tester_tests);
}
