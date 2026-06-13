/*
 * Shared client-side security-1 handshake. See prov_client.h.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <errno.h>
#include <zephyr/kernel.h>

#include <pb_encode.h>
#include <pb_decode.h>
#include "session.pb.h"

#include "prov_client.h"

#define SESSION_EP "prov-session"

void prov_client_init(struct prov_client *c, prov_client_xport_t xport, void *ctx)
{
	memset(c, 0, sizeof(*c));
	c->xport = xport;
	c->xport_ctx = ctx;
}

int prov_client_keygen(struct prov_client *c)
{
	psa_status_t st;
	size_t olen = 0;

	st = psa_crypto_init();
	if (st != PSA_SUCCESS) {
		return -EIO;
	}

	psa_key_attributes_t attr = psa_key_attributes_init();

	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
	psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
	psa_set_key_bits(&attr, 255);
	st = psa_generate_key(&attr, &c->key);
	psa_reset_key_attributes(&attr);
	if (st != PSA_SUCCESS) {
		return -EIO;
	}

	st = psa_export_public_key(c->key, c->pubkey, sizeof(c->pubkey), &olen);
	if (st != PSA_SUCCESS || olen != PROV_CLIENT_PUBKEY_LEN) {
		return -EIO;
	}
	return 0;
}

int prov_client_derive(struct prov_client *c, const char *pop,
		       const uint8_t *device_random)
{
	uint8_t shared[PROV_CLIENT_KEY_LEN];
	size_t shared_len = 0;
	psa_status_t st;

	st = psa_raw_key_agreement(PSA_ALG_ECDH, c->key,
				   c->device_pubkey, PROV_CLIENT_PUBKEY_LEN,
				   shared, sizeof(shared), &shared_len);
	if (st != PSA_SUCCESS || shared_len != PROV_CLIENT_KEY_LEN) {
		return -EIO;
	}

	if (pop != NULL && pop[0] != '\0') {
		uint8_t hash[PROV_CLIENT_KEY_LEN];
		size_t hlen = 0;

		st = psa_hash_compute(PSA_ALG_SHA_256, (const uint8_t *)pop,
				      strlen(pop), hash, sizeof(hash), &hlen);
		if (st != PSA_SUCCESS) {
			return -EIO;
		}
		for (size_t i = 0; i < PROV_CLIENT_KEY_LEN; i++) {
			shared[i] ^= hash[i];
		}
	}

	psa_key_attributes_t attr = psa_key_attributes_init();

	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&attr, PSA_ALG_CTR);
	psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attr, 256);
	st = psa_import_key(&attr, shared, PROV_CLIENT_KEY_LEN, &c->session_key);
	psa_reset_key_attributes(&attr);
	if (st != PSA_SUCCESS) {
		return -EIO;
	}

	c->cipher = psa_cipher_operation_init();
	st = psa_cipher_encrypt_setup(&c->cipher, c->session_key, PSA_ALG_CTR);
	if (st != PSA_SUCCESS) {
		return -EIO;
	}
	st = psa_cipher_set_iv(&c->cipher, device_random, PROV_CLIENT_RANDOM_LEN);
	if (st != PSA_SUCCESS) {
		return -EIO;
	}
	return 0;
}

int prov_client_xform(struct prov_client *c, const uint8_t *in, size_t inlen,
		      uint8_t *out)
{
	size_t olen = 0;
	psa_status_t st;

	st = psa_cipher_update(&c->cipher, in, inlen, out, inlen, &olen);
	if (st != PSA_SUCCESS || olen != inlen) {
		return -EIO;
	}
	return 0;
}

void prov_client_destroy(struct prov_client *c)
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

/* Encode @p cmd, run it through the bound transport, decode into @p resp_out. */
static int session_exchange(struct prov_client *c, const SessionData *cmd,
			    SessionData *resp_out)
{
	uint8_t buf[128];
	pb_ostream_t ostream = pb_ostream_from_buffer(buf, sizeof(buf));

	if (!pb_encode(&ostream, SessionData_fields, cmd)) {
		return -EINVAL;
	}

	uint8_t *resp = NULL;
	size_t resp_len = 0;
	int ret = c->xport(c->xport_ctx, SESSION_EP, buf, ostream.bytes_written,
			   &resp, &resp_len);

	if (ret != 0) {
		return ret;
	}

	pb_istream_t istream = pb_istream_from_buffer(resp, resp_len);
	bool ok = pb_decode(&istream, SessionData_fields, resp_out);

	k_free(resp);
	return ok ? 0 : -EILSEQ;
}

int prov_client_handshake(struct prov_client *c, const char *pop)
{
	int ret = prov_client_keygen(c);

	if (ret != 0) {
		return ret;
	}

	/* Command0: client public key. */
	SessionData cmd0 = SessionData_init_default;

	cmd0.sec_ver = SecSchemeVersion_SecScheme1;
	cmd0.which_proto = SessionData_sec1_tag;
	cmd0.proto.sec1.msg = Sec1MsgType_Session_Command0;
	cmd0.proto.sec1.which_payload = Sec1Payload_sc0_tag;
	cmd0.proto.sec1.payload.sc0.client_pubkey.size = PROV_CLIENT_PUBKEY_LEN;
	memcpy(cmd0.proto.sec1.payload.sc0.client_pubkey.bytes, c->pubkey,
	       PROV_CLIENT_PUBKEY_LEN);

	SessionData resp0 = SessionData_init_default;

	ret = session_exchange(c, &cmd0, &resp0);
	if (ret != 0) {
		return ret;
	}
	if (resp0.proto.sec1.msg != Sec1MsgType_Session_Response0 ||
	    resp0.proto.sec1.payload.sr0.status != Status_Success ||
	    resp0.proto.sec1.payload.sr0.device_pubkey.size != PROV_CLIENT_PUBKEY_LEN ||
	    resp0.proto.sec1.payload.sr0.device_random.size != PROV_CLIENT_RANDOM_LEN) {
		return -EPROTO;
	}
	memcpy(c->device_pubkey, resp0.proto.sec1.payload.sr0.device_pubkey.bytes,
	       PROV_CLIENT_PUBKEY_LEN);

	ret = prov_client_derive(c, pop, resp0.proto.sec1.payload.sr0.device_random.bytes);
	if (ret != 0) {
		return ret;
	}

	/* Command1: client_verify = keystream[0..31] XOR device_pubkey. */
	uint8_t client_verify[PROV_CLIENT_PUBKEY_LEN];

	ret = prov_client_xform(c, c->device_pubkey, PROV_CLIENT_PUBKEY_LEN, client_verify);
	if (ret != 0) {
		return ret;
	}

	SessionData cmd1 = SessionData_init_default;

	cmd1.sec_ver = SecSchemeVersion_SecScheme1;
	cmd1.which_proto = SessionData_sec1_tag;
	cmd1.proto.sec1.msg = Sec1MsgType_Session_Command1;
	cmd1.proto.sec1.which_payload = Sec1Payload_sc1_tag;
	cmd1.proto.sec1.payload.sc1.client_verify_data.size = PROV_CLIENT_PUBKEY_LEN;
	memcpy(cmd1.proto.sec1.payload.sc1.client_verify_data.bytes, client_verify,
	       PROV_CLIENT_PUBKEY_LEN);

	SessionData resp1 = SessionData_init_default;

	ret = session_exchange(c, &cmd1, &resp1);
	if (ret != 0) {
		/* The device rejects a wrong-PoP client verify with -EACCES. */
		return ret;
	}
	if (resp1.proto.sec1.msg != Sec1MsgType_Session_Response1 ||
	    resp1.proto.sec1.payload.sr1.status != Status_Success ||
	    resp1.proto.sec1.payload.sr1.device_verify_data.size != PROV_CLIENT_PUBKEY_LEN) {
		return -EPROTO;
	}

	/* device_verify = keystream[32..63] XOR client_pubkey. */
	uint8_t check[PROV_CLIENT_PUBKEY_LEN];

	ret = prov_client_xform(c, resp1.proto.sec1.payload.sr1.device_verify_data.bytes,
				PROV_CLIENT_PUBKEY_LEN, check);
	if (ret != 0) {
		return ret;
	}
	if (memcmp(check, c->pubkey, PROV_CLIENT_PUBKEY_LEN) != 0) {
		return -EACCES;
	}
	return 0;
}
