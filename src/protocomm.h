/*
 * Minimal protocomm core: endpoint registry + per-session security hook.
 *
 * A pared-down re-implementation of Espressif's protocomm tailored to the
 * BLE transport and security schemes 0/1. The transport (protocomm_ble.c)
 * receives a request for a named endpoint and calls protocomm_req_handle();
 * protocomm transparently decrypts the request, dispatches it to the
 * registered endpoint handler, and encrypts the response.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef NETWORK_PROVISIONING_PROTOCOMM_H_
#define NETWORK_PROVISIONING_PROTOCOMM_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PROTOCOMM_MAX_ENDPOINTS 8
#define PROTOCOMM_EP_NAME_MAX   16

struct protocomm;

/**
 * Endpoint request handler.
 *
 * @param priv      Private pointer registered with the endpoint.
 * @param inbuf     Plaintext request bytes (already decrypted).
 * @param inlen     Length of @p inbuf.
 * @param outbuf    Set to a malloc'd response buffer (caller frees), or NULL.
 * @param outlen    Set to the length of @p outbuf.
 * @return 0 on success, negative errno otherwise.
 */
typedef int (*protocomm_req_handler_t)(void *priv,
				       const uint8_t *inbuf, size_t inlen,
				       uint8_t **outbuf, size_t *outlen);

/**
 * Security handler interface (implemented by security0.c / security1.c).
 *
 * A single transport session is supported at a time, which matches the BLE
 * peripheral use case (one central connected during provisioning).
 */
struct protocomm_security {
	int version; /**< 0 or 1 (advertised as sec_ver). */

	/** Allocate per-session security state. @p pop may be NULL. */
	int (*init)(void **sec_ctx, const char *pop);
	/** Free per-session security state. */
	void (*cleanup)(void *sec_ctx);
	/** Handle a prov-session handshake message. Same contract as
	 *  @ref protocomm_req_handler_t (operates on raw bytes). */
	int (*handshake)(void *sec_ctx,
			 const uint8_t *inbuf, size_t inlen,
			 uint8_t **outbuf, size_t *outlen);
	/** Encrypt (or copy, for sec0) @p inlen bytes from @p in into @p out.
	 *  @p out must hold at least @p inlen bytes; *outlen is set on return. */
	int (*encrypt)(void *sec_ctx, const uint8_t *in, size_t inlen,
		       uint8_t *out, size_t *outlen);
	/** Decrypt (or copy, for sec0); same buffer contract as encrypt. */
	int (*decrypt)(void *sec_ctx, const uint8_t *in, size_t inlen,
		       uint8_t *out, size_t *outlen);
};

/** Create an empty protocomm instance. */
struct protocomm *protocomm_new(void);

/** Destroy a protocomm instance and any active session state. */
void protocomm_delete(struct protocomm *pc);

/**
 * Register a data endpoint. Requests are decrypted before, and responses
 * encrypted after, the handler runs.
 */
int protocomm_add_endpoint(struct protocomm *pc, const char *name,
			   protocomm_req_handler_t handler, void *priv);

/**
 * Register the security endpoint (prov-session). Its handler bypasses the
 * encrypt/decrypt path and drives the handshake directly.
 */
int protocomm_set_security(struct protocomm *pc, const char *name,
			   const struct protocomm_security *sec,
			   const char *pop);

/**
 * Register the version endpoint (proto-ver). The handler returns a copy of
 * @p version on every request. @p version must outlive the instance.
 */
int protocomm_set_version(struct protocomm *pc, const char *name,
			  const char *version);

/**
 * Dispatch a request for @p ep_name. Allocates *outbuf (caller frees).
 * Called by the transport layer.
 */
int protocomm_req_handle(struct protocomm *pc, const char *ep_name,
			 const uint8_t *inbuf, size_t inlen,
			 uint8_t **outbuf, size_t *outlen);

/** Open a new transport session (resets security state). */
void protocomm_open_session(struct protocomm *pc);
/** Close the current transport session. */
void protocomm_close_session(struct protocomm *pc);

/** Number of registered endpoints (used by the transport to build the GATT DB). */
size_t protocomm_endpoint_count(const struct protocomm *pc);
/** Name of endpoint @p idx (0-based), or NULL. */
const char *protocomm_endpoint_name(const struct protocomm *pc, size_t idx);

#ifdef __cplusplus
}
#endif

#endif /* NETWORK_PROVISIONING_PROTOCOMM_H_ */
