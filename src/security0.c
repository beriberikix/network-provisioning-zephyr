/*
 * Security scheme 0: no encryption.
 *
 * The prov-session handshake is a trivial command/response exchange and all
 * data endpoints pass payloads through unmodified.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <string.h>
#include <errno.h>

#include <pb_encode.h>
#include <pb_decode.h>
#include "session.pb.h"

#include "protocomm.h"
#include "security.h"

/* The shared "network_prov" log module is registered here because security0
 * is always part of the protocol core, which can be built without the
 * manager (e.g. for the native_sim unit tests).
 */
LOG_MODULE_REGISTER(network_prov, CONFIG_NETWORK_PROV_LOG_LEVEL);

/* sec0 has no per-session state, but protocomm requires a non-NULL context to
 * mark a session as established, so we hand back a sentinel.
 */
static int sentinel;

static int sec0_init(void **ctx, const char *pop)
{
	ARG_UNUSED(pop);
	*ctx = &sentinel;
	return 0;
}

static void sec0_cleanup(void *ctx)
{
	ARG_UNUSED(ctx);
}

static int sec0_handshake(void *ctx, const uint8_t *inbuf, size_t inlen,
			  uint8_t **outbuf, size_t *outlen)
{
	ARG_UNUSED(ctx);

	SessionData req = SessionData_init_default;
	pb_istream_t istream = pb_istream_from_buffer(inbuf, inlen);

	if (!pb_decode(&istream, SessionData_fields, &req)) {
		LOG_ERR("sec0: failed to decode SessionData");
		return -EINVAL;
	}
	if (req.sec_ver != SecSchemeVersion_SecScheme0) {
		LOG_ERR("sec0: unexpected sec_ver %d", req.sec_ver);
		return -EINVAL;
	}

	SessionData resp = SessionData_init_default;

	resp.sec_ver = SecSchemeVersion_SecScheme0;
	resp.which_proto = SessionData_sec0_tag;
	resp.proto.sec0.msg = Sec0MsgType_S0_Session_Response;
	resp.proto.sec0.which_payload = Sec0Payload_sr_tag;
	resp.proto.sec0.payload.sr.status = Status_Success;

	return network_prov_pb_encode(SessionData_fields, &resp, outbuf, outlen);
}

static int sec0_passthrough(void *ctx, const uint8_t *in, size_t inlen,
			    uint8_t *out, size_t *outlen)
{
	ARG_UNUSED(ctx);
	memcpy(out, in, inlen);
	*outlen = inlen;
	return 0;
}

const struct protocomm_security network_prov_security0 = {
	.version = 0,
	.init = sec0_init,
	.cleanup = sec0_cleanup,
	.handshake = sec0_handshake,
	.encrypt = sec0_passthrough,
	.decrypt = sec0_passthrough,
};
