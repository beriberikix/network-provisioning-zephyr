/*
 * Unit tests for the protocomm core: endpoint registry, request dispatch,
 * the version endpoint and a full security-0 (plaintext) session.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <errno.h>
#include <zephyr/kernel.h>
#include <zephyr/ztest.h>

#include <pb_encode.h>
#include <pb_decode.h>
#include "session.pb.h"

#include "protocomm.h"
#include "security.h"

#define VERSION_JSON "{\"prov\":{\"ver\":\"v1.1\",\"sec_ver\":0}}"

/* Simple data handler: echoes the request back, prefixed with "echo:". */
static int echo_handler(void *priv, const uint8_t *inbuf, size_t inlen,
			uint8_t **outbuf, size_t *outlen)
{
	static const char prefix[] = "echo:";
	size_t plen = sizeof(prefix) - 1;
	uint8_t *out = k_malloc(plen + inlen);

	if (out == NULL) {
		return -ENOMEM;
	}
	memcpy(out, prefix, plen);
	memcpy(out + plen, inbuf, inlen);
	*outbuf = out;
	*outlen = plen + inlen;
	return 0;
}

static int noop_handler(void *priv, const uint8_t *inbuf, size_t inlen,
			uint8_t **outbuf, size_t *outlen)
{
	*outbuf = NULL;
	*outlen = 0;
	return 0;
}

/* Run the security-0 handshake on the session endpoint. */
static void do_sec0_handshake(struct protocomm *pc)
{
	SessionData cmd = SessionData_init_default;

	cmd.sec_ver = SecSchemeVersion_SecScheme0;
	cmd.which_proto = SessionData_sec0_tag;
	cmd.proto.sec0.msg = Sec0MsgType_S0_Session_Command;
	cmd.proto.sec0.which_payload = Sec0Payload_sc_tag;

	uint8_t buf[64];
	pb_ostream_t ostream = pb_ostream_from_buffer(buf, sizeof(buf));

	zassert_true(pb_encode(&ostream, SessionData_fields, &cmd),
		     "encode failed: %s", PB_GET_ERROR(&ostream));

	uint8_t *resp = NULL;
	size_t resp_len = 0;
	int ret = protocomm_req_handle(pc, "prov-session", buf,
				       ostream.bytes_written, &resp, &resp_len);

	zassert_equal(ret, 0, "sec0 handshake failed: %d", ret);
	zassert_true(resp_len > 0, "empty handshake response");

	SessionData sd = SessionData_init_default;
	pb_istream_t istream = pb_istream_from_buffer(resp, resp_len);

	zassert_true(pb_decode(&istream, SessionData_fields, &sd),
		     "decode failed: %s", PB_GET_ERROR(&istream));
	zassert_equal(sd.which_proto, SessionData_sec0_tag);
	zassert_equal(sd.proto.sec0.msg, Sec0MsgType_S0_Session_Response);
	zassert_equal(sd.proto.sec0.payload.sr.status, Status_Success);
	k_free(resp);
}

ZTEST(protocomm, test_lifecycle_and_registry)
{
	struct protocomm *pc = protocomm_new();

	zassert_not_null(pc);
	zassert_equal(protocomm_endpoint_count(pc), 0);

	zassert_equal(protocomm_add_endpoint(pc, "ep-a", echo_handler, NULL), 0);
	zassert_equal(protocomm_add_endpoint(pc, "ep-b", echo_handler, NULL), 0);
	zassert_equal(protocomm_endpoint_count(pc), 2);
	zassert_str_equal(protocomm_endpoint_name(pc, 0), "ep-a");
	zassert_str_equal(protocomm_endpoint_name(pc, 1), "ep-b");
	zassert_is_null(protocomm_endpoint_name(pc, 2));

	protocomm_delete(pc);
}

ZTEST(protocomm, test_endpoint_capacity)
{
	struct protocomm *pc = protocomm_new();

	zassert_not_null(pc);

	char name[PROTOCOMM_EP_NAME_MAX];

	for (int i = 0; i < PROTOCOMM_MAX_ENDPOINTS; i++) {
		snprintf(name, sizeof(name), "ep-%d", i);
		zassert_equal(protocomm_add_endpoint(pc, name, noop_handler, NULL),
			      0, "endpoint %d rejected", i);
	}
	zassert_equal(protocomm_endpoint_count(pc), PROTOCOMM_MAX_ENDPOINTS);
	/* The table is full now. */
	zassert_not_equal(protocomm_add_endpoint(pc, "overflow", noop_handler, NULL), 0);

	protocomm_delete(pc);
}

ZTEST(protocomm, test_version_endpoint)
{
	struct protocomm *pc = protocomm_new();

	zassert_not_null(pc);
	zassert_equal(protocomm_set_version(pc, "proto-ver", VERSION_JSON), 0);

	uint8_t *out = NULL;
	size_t outlen = 0;

	zassert_equal(protocomm_req_handle(pc, "proto-ver", NULL, 0, &out, &outlen), 0);
	zassert_equal(outlen, strlen(VERSION_JSON));
	zassert_mem_equal(out, VERSION_JSON, outlen);
	k_free(out);

	protocomm_delete(pc);
}

ZTEST(protocomm, test_unknown_endpoint)
{
	struct protocomm *pc = protocomm_new();
	uint8_t *out = NULL;
	size_t outlen = 0;

	zassert_not_null(pc);
	zassert_equal(protocomm_req_handle(pc, "nope", NULL, 0, &out, &outlen),
		      -ENOENT);
	protocomm_delete(pc);
}

ZTEST(protocomm, test_data_requires_session)
{
	struct protocomm *pc = protocomm_new();
	uint8_t *out = NULL;
	size_t outlen = 0;

	zassert_not_null(pc);
	zassert_equal(protocomm_add_endpoint(pc, "data", echo_handler, NULL), 0);

	/* No security configured / no session open: data must be rejected. */
	zassert_equal(protocomm_req_handle(pc, "data", (const uint8_t *)"x", 1,
					   &out, &outlen),
		      -EACCES);
	protocomm_delete(pc);
}

ZTEST(protocomm, test_sec0_session_and_echo)
{
	struct protocomm *pc = protocomm_new();

	zassert_not_null(pc);
	zassert_equal(protocomm_add_endpoint(pc, "data", echo_handler, NULL), 0);
	zassert_equal(protocomm_set_security(pc, "prov-session",
					     &network_prov_security0, NULL), 0);

	protocomm_open_session(pc);
	do_sec0_handshake(pc);

	/* Security 0 passes payloads through in plaintext. */
	static const char msg[] = "hello";
	uint8_t *out = NULL;
	size_t outlen = 0;

	zassert_equal(protocomm_req_handle(pc, "data", (const uint8_t *)msg,
					   strlen(msg), &out, &outlen), 0);
	zassert_equal(outlen, strlen("echo:hello"));
	zassert_mem_equal(out, "echo:hello", outlen);
	k_free(out);

	protocomm_close_session(pc);
	protocomm_delete(pc);
}

ZTEST_SUITE(protocomm, NULL, NULL, NULL, NULL, NULL);
