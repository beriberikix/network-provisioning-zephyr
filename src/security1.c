/*
 * Security scheme 1: Curve25519 (X25519) ECDH key agreement, an optional
 * proof-of-possession mixed into the session key, and AES-256-CTR for all
 * subsequent payloads. Wire-compatible with Espressif protocomm security1.
 *
 * Handshake (device side):
 *   Cmd0  in:  client_pubkey
 *         out: device_pubkey, device_random (the AES-CTR IV)
 *   Cmd1  in:  client_verify_data = AES-CTR(device_pubkey)   [keystream 0..31]
 *         out: device_verify_data = AES-CTR(client_pubkey)   [keystream 32..63]
 *
 * A single AES-CTR keystream is shared by both directions for the rest of the
 * session; encrypt and decrypt are the same XOR operation, so one persistent
 * PSA multipart cipher operation drives everything and stays in lock-step with
 * the peer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <string.h>
#include <errno.h>

#include <psa/crypto.h>
#include <pb_encode.h>
#include <pb_decode.h>
#include "session.pb.h"

#include "protocomm.h"
#include "security.h"

LOG_MODULE_DECLARE(network_prov, CONFIG_NETWORK_PROV_LOG_LEVEL);

#define PUBKEY_LEN  32
#define RANDOM_LEN  16
#define SESSION_KEY_LEN 32
#define POP_MAX     64

enum sec1_state {
	SEC1_INIT,
	SEC1_CMD0_DONE,
	SEC1_DONE,
};

struct sec1_ctx {
	enum sec1_state state;

	char pop[POP_MAX];
	size_t pop_len;

	psa_key_id_t device_key;            /* X25519 key pair */
	uint8_t device_pubkey[PUBKEY_LEN];
	uint8_t client_pubkey[PUBKEY_LEN];
	uint8_t device_random[RANDOM_LEN];  /* AES-CTR IV */

	psa_key_id_t session_key;           /* AES-256 */
	psa_cipher_operation_t cipher;      /* persistent CTR keystream */
};

static int sec1_init(void **out_ctx, const char *pop)
{
	psa_status_t status = psa_crypto_init();

	if (status != PSA_SUCCESS) {
		LOG_ERR("psa_crypto_init failed: %d", status);
		return -EIO;
	}

	struct sec1_ctx *ctx = k_calloc(1, sizeof(*ctx));

	if (ctx == NULL) {
		return -ENOMEM;
	}
	ctx->cipher = psa_cipher_operation_init();

	if (pop != NULL && pop[0] != '\0') {
		/* Not strnlen(): the host libc on native_sim hides it behind
		 * POSIX feature macros.
		 */
		ctx->pop_len = MIN(strlen(pop), (size_t)(POP_MAX - 1));
		memcpy(ctx->pop, pop, ctx->pop_len);
	}

	/* Generate the device's X25519 key pair. */
	psa_key_attributes_t attr = psa_key_attributes_init();

	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
	psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
	psa_set_key_bits(&attr, 255);

	status = psa_generate_key(&attr, &ctx->device_key);
	psa_reset_key_attributes(&attr);
	if (status != PSA_SUCCESS) {
		LOG_ERR("X25519 keygen failed: %d", status);
		k_free(ctx);
		return -EIO;
	}

	size_t olen = 0;

	status = psa_export_public_key(ctx->device_key, ctx->device_pubkey,
				       sizeof(ctx->device_pubkey), &olen);
	if (status != PSA_SUCCESS || olen != PUBKEY_LEN) {
		LOG_ERR("X25519 pubkey export failed: %d", status);
		psa_destroy_key(ctx->device_key);
		k_free(ctx);
		return -EIO;
	}

	*out_ctx = ctx;
	return 0;
}

static void sec1_cleanup(void *vctx)
{
	struct sec1_ctx *ctx = vctx;

	if (ctx == NULL) {
		return;
	}
	psa_cipher_abort(&ctx->cipher);
	if (ctx->session_key != PSA_KEY_ID_NULL) {
		psa_destroy_key(ctx->session_key);
	}
	if (ctx->device_key != PSA_KEY_ID_NULL) {
		psa_destroy_key(ctx->device_key);
	}
	/* Wipe key material before freeing. */
	memset(ctx, 0, sizeof(*ctx));
	k_free(ctx);
}

/* Derive the AES key from the ECDH shared secret and the proof-of-possession,
 * import it, and arm the CTR keystream with device_random as the IV.
 */
static int derive_session_key(struct sec1_ctx *ctx)
{
	uint8_t shared[SESSION_KEY_LEN];
	size_t shared_len = 0;
	psa_status_t status;

	status = psa_raw_key_agreement(PSA_ALG_ECDH, ctx->device_key,
				       ctx->client_pubkey, PUBKEY_LEN,
				       shared, sizeof(shared), &shared_len);
	if (status != PSA_SUCCESS || shared_len != SESSION_KEY_LEN) {
		LOG_ERR("ECDH failed: %d", status);
		return -EIO;
	}

	if (ctx->pop_len > 0) {
		uint8_t hash[SESSION_KEY_LEN];
		size_t hlen = 0;

		status = psa_hash_compute(PSA_ALG_SHA_256, ctx->pop, ctx->pop_len,
					  hash, sizeof(hash), &hlen);
		if (status != PSA_SUCCESS || hlen != SESSION_KEY_LEN) {
			LOG_ERR("PoP hash failed: %d", status);
			return -EIO;
		}
		for (size_t i = 0; i < SESSION_KEY_LEN; i++) {
			shared[i] ^= hash[i];
		}
		memset(hash, 0, sizeof(hash));
	}

	psa_key_attributes_t attr = psa_key_attributes_init();

	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_algorithm(&attr, PSA_ALG_CTR);
	psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attr, 256);

	status = psa_import_key(&attr, shared, SESSION_KEY_LEN, &ctx->session_key);
	psa_reset_key_attributes(&attr);
	memset(shared, 0, sizeof(shared));
	if (status != PSA_SUCCESS) {
		LOG_ERR("AES key import failed: %d", status);
		return -EIO;
	}

	ctx->cipher = psa_cipher_operation_init();
	status = psa_cipher_encrypt_setup(&ctx->cipher, ctx->session_key, PSA_ALG_CTR);
	if (status != PSA_SUCCESS) {
		LOG_ERR("cipher setup failed: %d", status);
		return -EIO;
	}
	status = psa_cipher_set_iv(&ctx->cipher, ctx->device_random, RANDOM_LEN);
	if (status != PSA_SUCCESS) {
		LOG_ERR("cipher set_iv failed: %d", status);
		return -EIO;
	}
	return 0;
}

/* Run @p inlen bytes through the shared CTR keystream (encrypt == decrypt). */
static int ctr_xform(struct sec1_ctx *ctx, const uint8_t *in, size_t inlen,
		     uint8_t *out, size_t *outlen)
{
	size_t olen = 0;
	psa_status_t status = psa_cipher_update(&ctx->cipher, in, inlen,
						out, inlen, &olen);

	if (status != PSA_SUCCESS) {
		LOG_ERR("cipher update failed: %d", status);
		return -EIO;
	}
	*outlen = olen;
	return 0;
}

static int build_resp0(struct sec1_ctx *ctx, uint8_t **outbuf, size_t *outlen)
{
	SessionData resp = SessionData_init_default;

	resp.sec_ver = SecSchemeVersion_SecScheme1;
	resp.which_proto = SessionData_sec1_tag;
	resp.proto.sec1.msg = Sec1MsgType_Session_Response0;
	resp.proto.sec1.which_payload = Sec1Payload_sr0_tag;
	resp.proto.sec1.payload.sr0.status = Status_Success;

	resp.proto.sec1.payload.sr0.device_pubkey.size = PUBKEY_LEN;
	memcpy(resp.proto.sec1.payload.sr0.device_pubkey.bytes,
	       ctx->device_pubkey, PUBKEY_LEN);
	resp.proto.sec1.payload.sr0.device_random.size = RANDOM_LEN;
	memcpy(resp.proto.sec1.payload.sr0.device_random.bytes,
	       ctx->device_random, RANDOM_LEN);

	return network_prov_pb_encode(SessionData_fields, &resp, outbuf, outlen);
}

static int build_resp1(struct sec1_ctx *ctx, const uint8_t *device_verify,
		       uint8_t **outbuf, size_t *outlen)
{
	SessionData resp = SessionData_init_default;

	resp.sec_ver = SecSchemeVersion_SecScheme1;
	resp.which_proto = SessionData_sec1_tag;
	resp.proto.sec1.msg = Sec1MsgType_Session_Response1;
	resp.proto.sec1.which_payload = Sec1Payload_sr1_tag;
	resp.proto.sec1.payload.sr1.status = Status_Success;
	resp.proto.sec1.payload.sr1.device_verify_data.size = PUBKEY_LEN;
	memcpy(resp.proto.sec1.payload.sr1.device_verify_data.bytes,
	       device_verify, PUBKEY_LEN);

	return network_prov_pb_encode(SessionData_fields, &resp, outbuf, outlen);
}

static int handle_cmd0(struct sec1_ctx *ctx, const Sec1Payload *p,
		       uint8_t **outbuf, size_t *outlen)
{
	if (p->payload.sc0.client_pubkey.size != PUBKEY_LEN) {
		LOG_ERR("sec1: bad client_pubkey length");
		return -EINVAL;
	}
	memcpy(ctx->client_pubkey, p->payload.sc0.client_pubkey.bytes, PUBKEY_LEN);

	psa_status_t status = psa_generate_random(ctx->device_random, RANDOM_LEN);

	if (status != PSA_SUCCESS) {
		return -EIO;
	}

	int ret = derive_session_key(ctx);

	if (ret != 0) {
		return ret;
	}

	ctx->state = SEC1_CMD0_DONE;
	return build_resp0(ctx, outbuf, outlen);
}

static int handle_cmd1(struct sec1_ctx *ctx, const Sec1Payload *p,
		       uint8_t **outbuf, size_t *outlen)
{
	if (ctx->state != SEC1_CMD0_DONE) {
		LOG_ERR("sec1: command1 before command0");
		return -EACCES;
	}
	if (p->payload.sc1.client_verify_data.size != PUBKEY_LEN) {
		return -EINVAL;
	}

	/* Decrypt client_verify_data (keystream bytes 0..31). It must equal our
	 * own device_pubkey, otherwise the shared key / PoP did not match.
	 */
	uint8_t check[PUBKEY_LEN];
	size_t clen = 0;
	int ret = ctr_xform(ctx, p->payload.sc1.client_verify_data.bytes,
			    PUBKEY_LEN, check, &clen);

	if (ret != 0) {
		return ret;
	}
	if (clen != PUBKEY_LEN ||
	    memcmp(check, ctx->device_pubkey, PUBKEY_LEN) != 0) {
		LOG_WRN("sec1: proof-of-possession mismatch");
		return -EACCES;
	}

	/* device_verify_data = encrypt(client_pubkey) (keystream bytes 32..63). */
	uint8_t device_verify[PUBKEY_LEN];
	size_t dlen = 0;

	ret = ctr_xform(ctx, ctx->client_pubkey, PUBKEY_LEN, device_verify, &dlen);
	if (ret != 0) {
		return ret;
	}

	ctx->state = SEC1_DONE;
	return build_resp1(ctx, device_verify, outbuf, outlen);
}

static int sec1_handshake(void *vctx, const uint8_t *inbuf, size_t inlen,
			  uint8_t **outbuf, size_t *outlen)
{
	struct sec1_ctx *ctx = vctx;

	if (ctx == NULL) {
		return -EINVAL;
	}

	SessionData req = SessionData_init_default;
	pb_istream_t istream = pb_istream_from_buffer(inbuf, inlen);

	if (!pb_decode(&istream, SessionData_fields, &req)) {
		LOG_ERR("sec1: failed to decode SessionData");
		return -EINVAL;
	}
	if (req.sec_ver != SecSchemeVersion_SecScheme1 ||
	    req.which_proto != SessionData_sec1_tag) {
		LOG_ERR("sec1: unexpected security version");
		return -EINVAL;
	}

	const Sec1Payload *p = &req.proto.sec1;

	switch (p->msg) {
	case Sec1MsgType_Session_Command0:
		return handle_cmd0(ctx, p, outbuf, outlen);
	case Sec1MsgType_Session_Command1:
		return handle_cmd1(ctx, p, outbuf, outlen);
	default:
		LOG_ERR("sec1: unexpected msg type %d", p->msg);
		return -EINVAL;
	}
}

static int sec1_encrypt(void *vctx, const uint8_t *in, size_t inlen,
			uint8_t *out, size_t *outlen)
{
	struct sec1_ctx *ctx = vctx;

	if (ctx == NULL || ctx->state != SEC1_DONE) {
		return -EACCES;
	}
	return ctr_xform(ctx, in, inlen, out, outlen);
}

const struct protocomm_security network_prov_security1 = {
	.version = 1,
	.init = sec1_init,
	.cleanup = sec1_cleanup,
	.handshake = sec1_handshake,
	.encrypt = sec1_encrypt,
	.decrypt = sec1_encrypt, /* CTR: decrypt == encrypt (shared keystream). */
};
