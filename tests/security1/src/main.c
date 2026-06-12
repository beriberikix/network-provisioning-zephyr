/*
 * Security scheme 1 tests: a complete client-side implementation of the
 * Curve25519 + AES-256-CTR handshake (the inverse of src/security1.c, doing
 * what esp_prov's security1 client does) driven against the device side
 * through protocomm_req_handle().
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <errno.h>
#include <zephyr/kernel.h>
#include <zephyr/ztest.h>

#include <psa/crypto.h>
#include <pb_encode.h>
#include <pb_decode.h>
#include "session.pb.h"

#include "protocomm.h"
#include "security.h"

#define PUBKEY_LEN  32
#define RANDOM_LEN  16
#define KEY_LEN     32

#define SESSION_EP  "prov-session"
#define DATA_EP     "data"
#define POP         "abcd1234"

/* Client-side session state. */
struct client {
	psa_key_id_t key;               /* client X25519 key pair */
	uint8_t pubkey[PUBKEY_LEN];
	uint8_t device_pubkey[PUBKEY_LEN];
	psa_key_id_t session_key;       /* AES-256 */
	psa_cipher_operation_t cipher;  /* persistent CTR keystream */
};

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

static void client_keygen(struct client *c)
{
	zassert_equal(psa_crypto_init(), PSA_SUCCESS);

	psa_key_attributes_t attr = psa_key_attributes_init();

	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
	psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
	psa_set_key_bits(&attr, 255);
	zassert_equal(psa_generate_key(&attr, &c->key), PSA_SUCCESS);
	psa_reset_key_attributes(&attr);

	size_t olen = 0;

	zassert_equal(psa_export_public_key(c->key, c->pubkey, sizeof(c->pubkey),
					    &olen), PSA_SUCCESS);
	zassert_equal(olen, PUBKEY_LEN);
}

/* Derive the session key from ECDH(client_priv, device_pub), XOR-mixed with
 * SHA256(pop) when a PoP is in use, and arm the CTR keystream with the
 * device-provided IV. Mirrors derive_session_key() in src/security1.c.
 */
static void client_derive(struct client *c, const char *pop,
			  const uint8_t *device_random)
{
	uint8_t shared[KEY_LEN];
	size_t shared_len = 0;

	zassert_equal(psa_raw_key_agreement(PSA_ALG_ECDH, c->key,
					    c->device_pubkey, PUBKEY_LEN,
					    shared, sizeof(shared), &shared_len),
		      PSA_SUCCESS);
	zassert_equal(shared_len, KEY_LEN);

	if (pop != NULL && pop[0] != '\0') {
		uint8_t hash[KEY_LEN];
		size_t hlen = 0;

		zassert_equal(psa_hash_compute(PSA_ALG_SHA_256, (const uint8_t *)pop,
					       strlen(pop), hash, sizeof(hash),
					       &hlen), PSA_SUCCESS);
		for (size_t i = 0; i < KEY_LEN; i++) {
			shared[i] ^= hash[i];
		}
	}

	psa_key_attributes_t attr = psa_key_attributes_init();

	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&attr, PSA_ALG_CTR);
	psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attr, 256);
	zassert_equal(psa_import_key(&attr, shared, KEY_LEN, &c->session_key),
		      PSA_SUCCESS);
	psa_reset_key_attributes(&attr);

	c->cipher = psa_cipher_operation_init();
	zassert_equal(psa_cipher_encrypt_setup(&c->cipher, c->session_key,
					       PSA_ALG_CTR), PSA_SUCCESS);
	zassert_equal(psa_cipher_set_iv(&c->cipher, device_random, RANDOM_LEN),
		      PSA_SUCCESS);
}

/* Advance the client's CTR keystream over inlen bytes (encrypt == decrypt). */
static void client_xform(struct client *c, const uint8_t *in, size_t inlen,
			 uint8_t *out)
{
	size_t olen = 0;

	zassert_equal(psa_cipher_update(&c->cipher, in, inlen, out, inlen, &olen),
		      PSA_SUCCESS);
	zassert_equal(olen, inlen);
}

static void client_destroy(struct client *c)
{
	psa_cipher_abort(&c->cipher);
	if (c->session_key != PSA_KEY_ID_NULL) {
		psa_destroy_key(c->session_key);
	}
	if (c->key != PSA_KEY_ID_NULL) {
		psa_destroy_key(c->key);
	}
	memset(c, 0, sizeof(*c));
}

/* Send Session_Command0 (client pubkey); returns the decoded Response0. */
static int send_cmd0(struct protocomm *pc, struct client *c, SessionData *resp_out)
{
	SessionData cmd = SessionData_init_default;

	cmd.sec_ver = SecSchemeVersion_SecScheme1;
	cmd.which_proto = SessionData_sec1_tag;
	cmd.proto.sec1.msg = Sec1MsgType_Session_Command0;
	cmd.proto.sec1.which_payload = Sec1Payload_sc0_tag;
	cmd.proto.sec1.payload.sc0.client_pubkey.size = PUBKEY_LEN;
	memcpy(cmd.proto.sec1.payload.sc0.client_pubkey.bytes, c->pubkey, PUBKEY_LEN);

	uint8_t buf[128];
	pb_ostream_t ostream = pb_ostream_from_buffer(buf, sizeof(buf));

	zassert_true(pb_encode(&ostream, SessionData_fields, &cmd),
		     "encode failed: %s", PB_GET_ERROR(&ostream));

	uint8_t *resp = NULL;
	size_t resp_len = 0;
	int ret = protocomm_req_handle(pc, SESSION_EP, buf, ostream.bytes_written,
				       &resp, &resp_len);

	if (ret != 0) {
		return ret;
	}

	pb_istream_t istream = pb_istream_from_buffer(resp, resp_len);

	zassert_true(pb_decode(&istream, SessionData_fields, resp_out),
		     "decode failed: %s", PB_GET_ERROR(&istream));
	k_free(resp);
	return 0;
}

/* Send Session_Command1 (client verify data); on success fills resp_out. */
static int send_cmd1(struct protocomm *pc, const uint8_t *client_verify,
		     SessionData *resp_out)
{
	SessionData cmd = SessionData_init_default;

	cmd.sec_ver = SecSchemeVersion_SecScheme1;
	cmd.which_proto = SessionData_sec1_tag;
	cmd.proto.sec1.msg = Sec1MsgType_Session_Command1;
	cmd.proto.sec1.which_payload = Sec1Payload_sc1_tag;
	cmd.proto.sec1.payload.sc1.client_verify_data.size = PUBKEY_LEN;
	memcpy(cmd.proto.sec1.payload.sc1.client_verify_data.bytes,
	       client_verify, PUBKEY_LEN);

	uint8_t buf[128];
	pb_ostream_t ostream = pb_ostream_from_buffer(buf, sizeof(buf));

	zassert_true(pb_encode(&ostream, SessionData_fields, &cmd),
		     "encode failed: %s", PB_GET_ERROR(&ostream));

	uint8_t *resp = NULL;
	size_t resp_len = 0;
	int ret = protocomm_req_handle(pc, SESSION_EP, buf, ostream.bytes_written,
				       &resp, &resp_len);

	if (ret != 0) {
		return ret;
	}

	pb_istream_t istream = pb_istream_from_buffer(resp, resp_len);

	zassert_true(pb_decode(&istream, SessionData_fields, resp_out),
		     "decode failed: %s", PB_GET_ERROR(&istream));
	k_free(resp);
	return 0;
}

/* Full handshake with @p client_pop on the client side. The device-side pop
 * is configured by the caller via protocomm_set_security(). Returns the
 * result of Command1 (0 on an established session).
 */
static int run_handshake(struct protocomm *pc, struct client *c,
			 const char *client_pop)
{
	client_keygen(c);

	SessionData resp0 = SessionData_init_default;

	zassert_equal(send_cmd0(pc, c, &resp0), 0, "command0 failed");
	zassert_equal(resp0.proto.sec1.msg, Sec1MsgType_Session_Response0);
	zassert_equal(resp0.proto.sec1.payload.sr0.status, Status_Success);
	zassert_equal(resp0.proto.sec1.payload.sr0.device_pubkey.size, PUBKEY_LEN);
	zassert_equal(resp0.proto.sec1.payload.sr0.device_random.size, RANDOM_LEN);
	memcpy(c->device_pubkey, resp0.proto.sec1.payload.sr0.device_pubkey.bytes,
	       PUBKEY_LEN);

	client_derive(c, client_pop, resp0.proto.sec1.payload.sr0.device_random.bytes);

	/* client_verify = keystream[0..31] XOR device_pubkey */
	uint8_t client_verify[PUBKEY_LEN];

	client_xform(c, c->device_pubkey, PUBKEY_LEN, client_verify);

	SessionData resp1 = SessionData_init_default;
	int ret = send_cmd1(pc, client_verify, &resp1);

	if (ret != 0) {
		return ret;
	}

	zassert_equal(resp1.proto.sec1.msg, Sec1MsgType_Session_Response1);
	zassert_equal(resp1.proto.sec1.payload.sr1.status, Status_Success);
	zassert_equal(resp1.proto.sec1.payload.sr1.device_verify_data.size,
		      PUBKEY_LEN);

	/* device_verify = keystream[32..63] XOR client_pubkey */
	uint8_t check[PUBKEY_LEN];

	client_xform(c, resp1.proto.sec1.payload.sr1.device_verify_data.bytes,
		     PUBKEY_LEN, check);
	zassert_mem_equal(check, c->pubkey, PUBKEY_LEN,
			  "device verify data mismatch");
	return 0;
}

/* Encrypted request/response round trip through the echo endpoint. */
static void encrypted_echo(struct protocomm *pc, struct client *c,
			   const char *msg)
{
	size_t mlen = strlen(msg);
	uint8_t enc[64];

	zassert_true(mlen <= sizeof(enc));
	client_xform(c, (const uint8_t *)msg, mlen, enc);

	uint8_t *out = NULL;
	size_t outlen = 0;

	zassert_equal(protocomm_req_handle(pc, DATA_EP, enc, mlen, &out, &outlen),
		      0, "encrypted request failed");

	char plain[80];

	zassert_true(outlen < sizeof(plain));
	client_xform(c, out, outlen, (uint8_t *)plain);
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
	zassert_equal(protocomm_set_security(pc, SESSION_EP,
					     &network_prov_security1, device_pop), 0);
	protocomm_open_session(pc);
	return pc;
}

ZTEST(security1, test_handshake_with_pop_and_echo)
{
	struct protocomm *pc = make_pc(POP);
	struct client c = {0};

	zassert_equal(run_handshake(pc, &c, POP), 0, "handshake failed");

	/* Several messages in a row: the shared CTR keystream must stay in
	 * lock-step across request/response pairs.
	 */
	encrypted_echo(pc, &c, "hello");
	encrypted_echo(pc, &c, "second message, a bit longer");
	encrypted_echo(pc, &c, "3");

	client_destroy(&c);
	protocomm_close_session(pc);
	protocomm_delete(pc);
}

ZTEST(security1, test_handshake_without_pop)
{
	struct protocomm *pc = make_pc(NULL);
	struct client c = {0};

	zassert_equal(run_handshake(pc, &c, NULL), 0, "no-pop handshake failed");
	encrypted_echo(pc, &c, "plain pop-less session");

	client_destroy(&c);
	protocomm_close_session(pc);
	protocomm_delete(pc);
}

ZTEST(security1, test_wrong_pop_rejected)
{
	struct protocomm *pc = make_pc(POP);
	struct client c = {0};

	/* Client derives its key with the wrong PoP: Command0 succeeds (it is
	 * just a key exchange) but the Command1 verification must fail.
	 */
	zassert_equal(run_handshake(pc, &c, "not-the-pop"), -EACCES,
		      "handshake with wrong PoP was not rejected");

	/* And no data may flow on the failed session. */
	uint8_t enc[8] = {0};
	uint8_t *out = NULL;
	size_t outlen = 0;

	zassert_not_equal(protocomm_req_handle(pc, DATA_EP, enc, sizeof(enc),
					       &out, &outlen), 0);

	client_destroy(&c);
	protocomm_close_session(pc);
	protocomm_delete(pc);
}

ZTEST(security1, test_session_reset_allows_rehandshake)
{
	struct protocomm *pc = make_pc(POP);
	struct client c1 = {0};
	struct client c2 = {0};

	zassert_equal(run_handshake(pc, &c1, POP), 0);
	encrypted_echo(pc, &c1, "first session");
	client_destroy(&c1);

	/* A transport reconnect resets the session; a fresh handshake with new
	 * keys must succeed.
	 */
	protocomm_open_session(pc);
	zassert_equal(run_handshake(pc, &c2, POP), 0, "re-handshake failed");
	encrypted_echo(pc, &c2, "second session");

	client_destroy(&c2);
	protocomm_close_session(pc);
	protocomm_delete(pc);
}

ZTEST_SUITE(security1, NULL, NULL, NULL, NULL, NULL);
