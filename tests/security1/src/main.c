/*
 * Security scheme 1 tests: drive the device side through protocomm_req_handle()
 * with the shared client-side Curve25519 + AES-256-CTR handshake from
 * tests/common/prov_client.c (the inverse of src/security1.c, doing what
 * esp_prov's security1 client does).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <errno.h>
#include <zephyr/kernel.h>
#include <zephyr/ztest.h>

#include "protocomm.h"
#include "security.h"
#include "prov_client.h"

#define DATA_EP "data"
#define POP     "abcd1234"

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

/* Transport adapter: a protocomm request is a direct in-process handle call.
 * The signature already matches prov_client_xport_t.
 */
static int pc_xport(void *ctx, const char *ep, const uint8_t *in, size_t inlen,
		    uint8_t **out, size_t *outlen)
{
	return protocomm_req_handle((struct protocomm *)ctx, ep, in, inlen, out, outlen);
}

/* Encrypted request/response round trip through the echo endpoint. */
static void encrypted_echo(struct protocomm *pc, struct prov_client *c,
			   const char *msg)
{
	size_t mlen = strlen(msg);
	uint8_t enc[64];

	zassert_true(mlen <= sizeof(enc));
	zassert_equal(prov_client_xform(c, (const uint8_t *)msg, mlen, enc), 0);

	uint8_t *out = NULL;
	size_t outlen = 0;

	zassert_equal(protocomm_req_handle(pc, DATA_EP, enc, mlen, &out, &outlen),
		      0, "encrypted request failed");

	char plain[80];

	zassert_true(outlen < sizeof(plain));
	zassert_equal(prov_client_xform(c, out, outlen, (uint8_t *)plain), 0);
	plain[outlen] = '\0';
	k_free(out);

	char expect[80];

	snprintf(expect, sizeof(expect), "echo:%s", msg);
	zassert_str_equal(plain, expect);
}

static struct protocomm *make_pc(const char *device_pop)
{
	struct protocomm *pc = protocomm_new();

	zassert_not_null(pc);
	zassert_equal(protocomm_add_endpoint(pc, DATA_EP, echo_handler, NULL), 0);
	zassert_equal(protocomm_set_security(pc, "prov-session",
					     &network_prov_security1, device_pop), 0);
	protocomm_open_session(pc);
	return pc;
}

ZTEST(security1, test_handshake_with_pop_and_echo)
{
	struct protocomm *pc = make_pc(POP);
	struct prov_client c;

	prov_client_init(&c, pc_xport, pc);
	zassert_equal(prov_client_handshake(&c, POP), 0, "handshake failed");

	/* Several messages in a row: the shared CTR keystream must stay in
	 * lock-step across request/response pairs.
	 */
	encrypted_echo(pc, &c, "hello");
	encrypted_echo(pc, &c, "second message, a bit longer");
	encrypted_echo(pc, &c, "3");

	prov_client_destroy(&c);
	protocomm_close_session(pc);
	protocomm_delete(pc);
}

ZTEST(security1, test_handshake_without_pop)
{
	struct protocomm *pc = make_pc(NULL);
	struct prov_client c;

	prov_client_init(&c, pc_xport, pc);
	zassert_equal(prov_client_handshake(&c, NULL), 0, "no-pop handshake failed");
	encrypted_echo(pc, &c, "plain pop-less session");

	prov_client_destroy(&c);
	protocomm_close_session(pc);
	protocomm_delete(pc);
}

ZTEST(security1, test_wrong_pop_rejected)
{
	struct protocomm *pc = make_pc(POP);
	struct prov_client c;

	prov_client_init(&c, pc_xport, pc);

	/* Client derives its key with the wrong PoP: Command0 succeeds (it is
	 * just a key exchange) but the Command1 verification must fail.
	 */
	zassert_equal(prov_client_handshake(&c, "not-the-pop"), -EACCES,
		      "handshake with wrong PoP was not rejected");

	/* And no data may flow on the failed session. */
	uint8_t enc[8] = {0};
	uint8_t *out = NULL;
	size_t outlen = 0;

	zassert_not_equal(protocomm_req_handle(pc, DATA_EP, enc, sizeof(enc),
					       &out, &outlen), 0);

	prov_client_destroy(&c);
	protocomm_close_session(pc);
	protocomm_delete(pc);
}

ZTEST(security1, test_session_reset_allows_rehandshake)
{
	struct protocomm *pc = make_pc(POP);
	struct prov_client c1;
	struct prov_client c2;

	prov_client_init(&c1, pc_xport, pc);
	zassert_equal(prov_client_handshake(&c1, POP), 0);
	encrypted_echo(pc, &c1, "first session");
	prov_client_destroy(&c1);

	/* A transport reconnect resets the session; a fresh handshake with new
	 * keys must succeed.
	 */
	protocomm_open_session(pc);
	prov_client_init(&c2, pc_xport, pc);
	zassert_equal(prov_client_handshake(&c2, POP), 0, "re-handshake failed");
	encrypted_echo(pc, &c2, "second session");

	prov_client_destroy(&c2);
	protocomm_close_session(pc);
	protocomm_delete(pc);
}

ZTEST_SUITE(security1, NULL, NULL, NULL, NULL, NULL);
