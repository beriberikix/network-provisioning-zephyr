/*
 * prov-ctrl endpoint: Wi-Fi state-machine control (reset / re-provision).
 *
 * The stock provisioning apps send CmdCtrlWifiReset before (re)applying
 * credentials so a previous failed attempt does not leave the device stuck
 * in a failed state. Mirrors ESP-IDF's wifi_ctrl handler.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <errno.h>

#include <pb_encode.h>
#include <pb_decode.h>
#include "network_ctrl.pb.h"

#include "network_prov_internal.h"
#include "security.h"

LOG_MODULE_DECLARE(network_prov, CONFIG_NETWORK_PROV_LOG_LEVEL);

int network_prov_wifi_ctrl_handler(void *priv, const uint8_t *inbuf, size_t inlen,
				   uint8_t **outbuf, size_t *outlen)
{
	ARG_UNUSED(priv);

	NetworkCtrlPayload req = NetworkCtrlPayload_init_default;
	pb_istream_t istream = pb_istream_from_buffer(inbuf, inlen);

	if (!pb_decode(&istream, NetworkCtrlPayload_fields, &req)) {
		LOG_ERR("prov-ctrl: decode failed");
		return -EINVAL;
	}

	NetworkCtrlPayload resp = NetworkCtrlPayload_init_default;

	switch (req.msg) {
	case NetworkCtrlMsgType_TypeCmdCtrlWifiReset:
		LOG_INF("prov-ctrl: Wi-Fi state reset");
		network_prov_wifi_config_reset();
		resp.msg = NetworkCtrlMsgType_TypeRespCtrlWifiReset;
		resp.which_payload = NetworkCtrlPayload_resp_ctrl_wifi_reset_tag;
		resp.status = Status_Success;
		break;

	case NetworkCtrlMsgType_TypeCmdCtrlWifiReprov:
		LOG_INF("prov-ctrl: Wi-Fi re-provision");
		network_prov_wifi_config_reset();
		resp.msg = NetworkCtrlMsgType_TypeRespCtrlWifiReprov;
		resp.which_payload = NetworkCtrlPayload_resp_ctrl_wifi_reprov_tag;
		resp.status = Status_Success;
		break;

	default:
		LOG_WRN("prov-ctrl: unsupported msg %d", req.msg);
		return -ENOTSUP;
	}

	return network_prov_pb_encode(NetworkCtrlPayload_fields, &resp,
				      outbuf, outlen);
}
