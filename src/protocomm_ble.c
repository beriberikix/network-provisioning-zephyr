/*
 * BLE (GATT) transport for protocomm.
 *
 * Builds a single primary service with one characteristic per protocomm
 * endpoint. Each characteristic carries a 0x2901 Characteristic User
 * Description descriptor holding the endpoint name; the provisioning apps read
 * those descriptors to map endpoint names to characteristics. A request is a
 * GATT write of the protobuf payload; the response is fetched with a GATT read
 * of the same characteristic.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/att.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/uuid.h>
#include <string.h>
#include <errno.h>

#include "protocomm.h"
#include "network_prov_internal.h"

LOG_MODULE_DECLARE(network_prov, CONFIG_NETWORK_PROV_LOG_LEVEL);

#define MAX_EP        PROTOCOMM_MAX_ENDPOINTS
#define MAX_RESP_LEN  CONFIG_NETWORK_PROV_BLE_MAX_RESP_LEN

/* Base 128-bit service UUID (021a9004-0382-4aea-bff4-6b3f1c5adfb4). Per-endpoint
 * characteristic UUIDs are derived by varying the low bytes; the apps discover
 * the actual endpoint mapping through the CUD descriptors, so only uniqueness
 * matters here.
 */
#define PROV_SERVICE_UUID_VAL \
	BT_UUID_128_ENCODE(0x021a9004, 0x0382, 0x4aea, 0xbff4, 0x6b3f1c5adfb4)

static struct bt_uuid_128 service_uuid = BT_UUID_INIT_128(PROV_SERVICE_UUID_VAL);

/* Optional manufacturer-specific data added to the scan response (set via
 * network_prov_scheme_ble_set_mfg_data); apps often match devices on it.
 */
#define MFG_DATA_MAX 29 /* fits one AD structure (type + payload) in a 31 B PDU */
static uint8_t mfg_data[MFG_DATA_MAX];
static size_t mfg_data_len;

int network_prov_scheme_ble_set_service_uuid(const uint8_t uuid128[16])
{
	if (uuid128 == NULL) {
		return -EINVAL;
	}
	memcpy(service_uuid.val, uuid128, sizeof(service_uuid.val));
	return 0;
}

int network_prov_scheme_ble_set_mfg_data(const uint8_t *data, size_t len)
{
	if (len > MFG_DATA_MAX) {
		return -ENOMEM;
	}
	if (len > 0 && data == NULL) {
		return -EINVAL;
	}
	mfg_data_len = len;
	if (len > 0) {
		memcpy(mfg_data, data, len);
	}
	return 0;
}

/* The BT_UUID_GATT_* helper macros expand to compound literals, which only
 * have static storage duration at file scope. This table is built inside
 * build_service(), so using them there would leave the registered service
 * pointing at dead stack memory. Give the declaration UUIDs real storage.
 */
static const struct bt_uuid_16 uuid_gatt_primary = BT_UUID_INIT_16(BT_UUID_GATT_PRIMARY_VAL);
static const struct bt_uuid_16 uuid_gatt_chrc = BT_UUID_INIT_16(BT_UUID_GATT_CHRC_VAL);
static const struct bt_uuid_16 uuid_gatt_cud = BT_UUID_INIT_16(BT_UUID_GATT_CUD_VAL);

struct ep_io {
	char name[PROTOCOMM_EP_NAME_MAX];
	uint8_t resp[MAX_RESP_LEN];
	size_t resp_len;
};

static struct protocomm *g_pc;

/* Backing storage for the dynamically built GATT service. */
static struct bt_uuid_128 ep_uuid[MAX_EP];
static struct bt_gatt_chrc ep_chrc[MAX_EP];
static struct ep_io ep_io[MAX_EP];
static struct bt_gatt_attr attrs[1 + 3 * MAX_EP];
static struct bt_gatt_service prov_svc;
static bool svc_registered;

/* Advertising payload is filled in at start() with the runtime device name so
 * the apps can match the configured "PROV_" name prefix.
 */
static const uint8_t ad_flags = BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR;
static char adv_name[32];
static struct bt_data ad[2];
static struct bt_data sd[2];
static size_t sd_len;

static void build_adv(const char *name)
{
	if (name == NULL || name[0] == '\0') {
		name = bt_get_name();
	}
	strncpy(adv_name, name, sizeof(adv_name) - 1);
	adv_name[sizeof(adv_name) - 1] = '\0';

	ad[0].type = BT_DATA_FLAGS;
	ad[0].data_len = sizeof(ad_flags);
	ad[0].data = &ad_flags;
	ad[1].type = BT_DATA_NAME_COMPLETE;
	ad[1].data_len = strlen(adv_name);
	ad[1].data = (const uint8_t *)adv_name;

	sd[0].type = BT_DATA_UUID128_ALL;
	sd[0].data_len = sizeof(service_uuid.val);
	sd[0].data = service_uuid.val;
	sd_len = 1;

	/* Optional manufacturer-specific data (e.g. for app-side matching). */
	if (mfg_data_len > 0) {
		sd[1].type = BT_DATA_MANUFACTURER_DATA;
		sd[1].data_len = mfg_data_len;
		sd[1].data = mfg_data;
		sd_len = 2;
	}
}

static ssize_t read_ep(struct bt_conn *conn, const struct bt_gatt_attr *attr,
		       void *buf, uint16_t len, uint16_t offset)
{
	struct ep_io *io = attr->user_data;

	return bt_gatt_attr_read(conn, attr, buf, len, offset, io->resp, io->resp_len);
}

static ssize_t write_ep(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			const void *buf, uint16_t len, uint16_t offset,
			uint8_t flags)
{
	ARG_UNUSED(conn);
	struct ep_io *io = attr->user_data;

	/* Prepared (long) writes are queued; the data is replayed without the
	 * PREPARE flag on execute, which is where we process it.
	 */
	if (flags & BT_GATT_WRITE_FLAG_PREPARE) {
		return len;
	}
	if (offset != 0) {
		/* Single-chunk requests only; the negotiated MTU comfortably
		 * covers every provisioning payload.
		 */
		return BT_GATT_ERR(BT_ATT_ERR_NOT_SUPPORTED);
	}

	uint8_t *out = NULL;
	size_t outlen = 0;
	int ret = protocomm_req_handle(g_pc, io->name, buf, len, &out, &outlen);

	if (ret != 0) {
		LOG_WRN("endpoint '%s' handler failed: %d", io->name, ret);
		io->resp_len = 0;
		return BT_GATT_ERR(BT_ATT_ERR_UNLIKELY);
	}

	if (outlen > sizeof(io->resp)) {
		LOG_ERR("response (%zu) exceeds buffer (%zu)", outlen, sizeof(io->resp));
		k_free(out);
		io->resp_len = 0;
		return BT_GATT_ERR(BT_ATT_ERR_INSUFFICIENT_RESOURCES);
	}

	if (outlen > 0) {
		memcpy(io->resp, out, outlen);
	}
	io->resp_len = outlen;
	k_free(out);
	return len;
}

static void build_service(void)
{
	size_t n = protocomm_endpoint_count(g_pc);
	size_t ai = 0;

	if (n > MAX_EP) {
		n = MAX_EP;
	}

	attrs[ai++] = (struct bt_gatt_attr)BT_GATT_ATTRIBUTE(
		&uuid_gatt_primary.uuid, BT_GATT_PERM_READ,
		bt_gatt_attr_read_service, NULL, &service_uuid);

	for (size_t i = 0; i < n; i++) {
		const char *name = protocomm_endpoint_name(g_pc, i);

		strncpy(ep_io[i].name, name, sizeof(ep_io[i].name) - 1);
		ep_io[i].resp_len = 0;

		/* Distinct 128-bit UUID per endpoint, derived from the base. */
		ep_uuid[i] = service_uuid;
		ep_uuid[i].val[12] = 0xF0 + (uint8_t)i;

		ep_chrc[i] = (struct bt_gatt_chrc){
			.uuid = &ep_uuid[i].uuid,
			.value_handle = 0,
			.properties = BT_GATT_CHRC_READ | BT_GATT_CHRC_WRITE,
		};

		attrs[ai++] = (struct bt_gatt_attr)BT_GATT_ATTRIBUTE(
			&uuid_gatt_chrc.uuid, BT_GATT_PERM_READ,
			bt_gatt_attr_read_chrc, NULL, &ep_chrc[i]);
		attrs[ai++] = (struct bt_gatt_attr)BT_GATT_ATTRIBUTE(
			&ep_uuid[i].uuid, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE,
			read_ep, write_ep, &ep_io[i]);
		attrs[ai++] = (struct bt_gatt_attr)BT_GATT_ATTRIBUTE(
			&uuid_gatt_cud.uuid, BT_GATT_PERM_READ,
			bt_gatt_attr_read_cud, NULL, ep_io[i].name);
	}

	prov_svc.attrs = attrs;
	prov_svc.attr_count = ai;
}

static void connected(struct bt_conn *conn, uint8_t err)
{
	if (err) {
		LOG_WRN("connection failed (err %u)", err);
		return;
	}
	LOG_INF("central connected");
	protocomm_open_session(g_pc);
}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
	LOG_INF("central disconnected (reason %u)", reason);
	protocomm_close_session(g_pc);

	/* Reset any cached endpoint responses for the next session. */
	for (size_t i = 0; i < MAX_EP; i++) {
		ep_io[i].resp_len = 0;
	}
}

static void recycled(void)
{
	/* The connection object is only released after the disconnected
	 * callback returns; restarting advertising from disconnected() fails
	 * with -ENOMEM because the (single) connection slot is still in use.
	 */
	if (!svc_registered) {
		return;
	}

	int ret = bt_le_adv_start(BT_LE_ADV_CONN_FAST_1, ad, ARRAY_SIZE(ad),
				  sd, sd_len);
	if (ret && ret != -EALREADY) {
		LOG_ERR("failed to restart advertising: %d", ret);
	}
}

BT_CONN_CB_DEFINE(conn_callbacks) = {
	.connected = connected,
	.disconnected = disconnected,
	.recycled = recycled,
};

int network_prov_ble_start(struct protocomm *pc, const char *device_name)
{
	int ret;

	g_pc = pc;

	if (device_name != NULL && device_name[0] != '\0') {
		ret = bt_set_name(device_name);
		if (ret) {
			LOG_WRN("bt_set_name('%s') failed: %d", device_name, ret);
		}
	}

	ret = bt_enable(NULL);
	if (ret && ret != -EALREADY) {
		LOG_ERR("bt_enable failed: %d", ret);
		return ret;
	}

	build_service();

	ret = bt_gatt_service_register(&prov_svc);
	if (ret) {
		LOG_ERR("GATT service register failed: %d", ret);
		return ret;
	}
	svc_registered = true;

	build_adv(device_name);

	ret = bt_le_adv_start(BT_LE_ADV_CONN_FAST_1, ad, ARRAY_SIZE(ad),
			      sd, sd_len);
	if (ret) {
		LOG_ERR("advertising start failed: %d", ret);
		return ret;
	}

	LOG_INF("BLE provisioning started, advertising as '%s'", bt_get_name());
	return 0;
}

void network_prov_ble_stop(void)
{
	(void)bt_le_adv_stop();
	if (svc_registered) {
		bt_gatt_service_unregister(&prov_svc);
		svc_registered = false;
	}
	g_pc = NULL;
}
