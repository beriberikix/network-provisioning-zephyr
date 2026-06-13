/*
 * Shared client-side implementation of the protocomm security-1 handshake
 * (Curve25519 + AES-256-CTR), the inverse of src/security1.c and what
 * esp_prov's security1 client does. Transport-agnostic: the caller supplies a
 * request callback that carries an encoded request to a protocomm endpoint and
 * returns the response, so the same client drives the device over a direct
 * protocomm_req_handle() call (tests/security1), over HTTP (tests/protocomm_http)
 * or over BLE GATT (tests/bsim/ble_e2e).
 *
 * Unlike a ztest helper these functions return negative errno on failure rather
 * than asserting, so they are usable from the BabbleSim bst_test harness too.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef NETWORK_PROV_TESTS_COMMON_PROV_CLIENT_H_
#define NETWORK_PROV_TESTS_COMMON_PROV_CLIENT_H_

#include <stddef.h>
#include <stdint.h>
#include <psa/crypto.h>

#define PROV_CLIENT_PUBKEY_LEN 32
#define PROV_CLIENT_RANDOM_LEN 16
#define PROV_CLIENT_KEY_LEN    32

/*
 * Transport callback: send @p inbuf (an encoded protobuf request) to endpoint
 * @p ep and return the response in a freshly k_malloc()'d buffer at @p outbuf /
 * @p outlen, which the client frees with k_free(). Return 0 on success or a
 * negative errno; a non-zero protocomm-level rejection is reported as the
 * negative errno the underlying transport produced.
 */
typedef int (*prov_client_xport_t)(void *ctx, const char *ep,
				   const uint8_t *inbuf, size_t inlen,
				   uint8_t **outbuf, size_t *outlen);

struct prov_client {
	psa_key_id_t key;		/* client X25519 key pair */
	uint8_t pubkey[PROV_CLIENT_PUBKEY_LEN];
	uint8_t device_pubkey[PROV_CLIENT_PUBKEY_LEN];
	psa_key_id_t session_key;	/* AES-256 */
	psa_cipher_operation_t cipher;	/* persistent CTR keystream */

	prov_client_xport_t xport;
	void *xport_ctx;
};

/* Bind the transport the client uses for its requests. */
void prov_client_init(struct prov_client *c, prov_client_xport_t xport, void *ctx);

/* Generate the ephemeral X25519 key pair and export the public key. */
int prov_client_keygen(struct prov_client *c);

/*
 * Derive the session key from ECDH(client_priv, device_pub), XOR-mixed with
 * SHA256(pop) when a PoP is in use, and arm the CTR keystream with the
 * device-provided IV (@p device_random, PROV_CLIENT_RANDOM_LEN bytes).
 */
int prov_client_derive(struct prov_client *c, const char *pop,
		       const uint8_t *device_random);

/* Advance the CTR keystream over @p inlen bytes (encrypt == decrypt). */
int prov_client_xform(struct prov_client *c, const uint8_t *in, size_t inlen,
		      uint8_t *out);

/* Release the PSA keys and cipher and zero the state. */
void prov_client_destroy(struct prov_client *c);

/*
 * Run the full security-1 handshake over the bound transport (Command0 ->
 * Response0 -> Command1 -> Response1) using @p pop on the client side. On
 * success the keystream is armed and synchronised with the device. Returns 0,
 * -EACCES if the device rejected the client verify data (wrong PoP), or another
 * negative errno on transport/decode failure.
 */
int prov_client_handshake(struct prov_client *c, const char *pop);

#endif /* NETWORK_PROV_TESTS_COMMON_PROV_CLIENT_H_ */
