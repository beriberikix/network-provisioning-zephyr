/*
 * Minimal protocomm core implementation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <string.h>
#include <errno.h>

#include "protocomm.h"

LOG_MODULE_REGISTER(protocomm, CONFIG_NETWORK_PROV_LOG_LEVEL);

enum ep_type {
	EP_DATA,
	EP_SECURITY,
	EP_VERSION,
};

struct protocomm_ep {
	char name[PROTOCOMM_EP_NAME_MAX];
	enum ep_type type;
	protocomm_req_handler_t handler;
	void *priv;
};

struct protocomm {
	struct protocomm_ep endpoints[PROTOCOMM_MAX_ENDPOINTS];
	size_t n_endpoints;

	const struct protocomm_security *sec;
	const char *pop;
	void *sec_ctx;

	const char *version;
};

struct protocomm *protocomm_new(void)
{
	struct protocomm *pc = k_calloc(1, sizeof(*pc));

	return pc;
}

void protocomm_delete(struct protocomm *pc)
{
	if (pc == NULL) {
		return;
	}
	protocomm_close_session(pc);
	k_free(pc);
}

static struct protocomm_ep *find_ep(struct protocomm *pc, const char *name)
{
	for (size_t i = 0; i < pc->n_endpoints; i++) {
		if (strcmp(pc->endpoints[i].name, name) == 0) {
			return &pc->endpoints[i];
		}
	}
	return NULL;
}

static int add_ep(struct protocomm *pc, const char *name, enum ep_type type,
		  protocomm_req_handler_t handler, void *priv)
{
	if (pc == NULL || name == NULL) {
		return -EINVAL;
	}
	if (strlen(name) >= PROTOCOMM_EP_NAME_MAX) {
		return -ENAMETOOLONG;
	}
	if (find_ep(pc, name) != NULL) {
		return -EALREADY;
	}
	if (pc->n_endpoints >= PROTOCOMM_MAX_ENDPOINTS) {
		return -ENOMEM;
	}

	struct protocomm_ep *ep = &pc->endpoints[pc->n_endpoints++];

	strncpy(ep->name, name, PROTOCOMM_EP_NAME_MAX - 1);
	ep->type = type;
	ep->handler = handler;
	ep->priv = priv;
	return 0;
}

int protocomm_add_endpoint(struct protocomm *pc, const char *name,
			   protocomm_req_handler_t handler, void *priv)
{
	return add_ep(pc, name, EP_DATA, handler, priv);
}

int protocomm_set_security(struct protocomm *pc, const char *name,
			   const struct protocomm_security *sec, const char *pop)
{
	if (sec == NULL) {
		return -EINVAL;
	}
	int ret = add_ep(pc, name, EP_SECURITY, NULL, NULL);

	if (ret != 0) {
		return ret;
	}
	pc->sec = sec;
	pc->pop = pop;
	return 0;
}

int protocomm_set_version(struct protocomm *pc, const char *name,
			  const char *version)
{
	if (version == NULL) {
		return -EINVAL;
	}
	int ret = add_ep(pc, name, EP_VERSION, NULL, NULL);

	if (ret != 0) {
		return ret;
	}
	pc->version = version;
	return 0;
}

void protocomm_open_session(struct protocomm *pc)
{
	if (pc == NULL || pc->sec == NULL) {
		return;
	}
	/* Drop any stale session and start fresh. */
	protocomm_close_session(pc);
	if (pc->sec->init != NULL) {
		int ret = pc->sec->init(&pc->sec_ctx, pc->pop);

		if (ret != 0) {
			LOG_ERR("security init failed: %d", ret);
			pc->sec_ctx = NULL;
		}
	}
}

void protocomm_close_session(struct protocomm *pc)
{
	if (pc == NULL || pc->sec == NULL || pc->sec_ctx == NULL) {
		return;
	}
	if (pc->sec->cleanup != NULL) {
		pc->sec->cleanup(pc->sec_ctx);
	}
	pc->sec_ctx = NULL;
}

static int handle_version(struct protocomm *pc, uint8_t **outbuf, size_t *outlen)
{
	size_t len = strlen(pc->version);
	uint8_t *out = k_malloc(len);

	if (out == NULL) {
		return -ENOMEM;
	}
	memcpy(out, pc->version, len);
	*outbuf = out;
	*outlen = len;
	return 0;
}

static int handle_data(struct protocomm *pc, struct protocomm_ep *ep,
		       const uint8_t *inbuf, size_t inlen,
		       uint8_t **outbuf, size_t *outlen)
{
	uint8_t *plain = NULL;
	size_t plain_len = 0;
	int ret;

	/* Decrypt the request (sec0 copies it through). */
	if (inlen > 0) {
		plain = k_malloc(inlen);
		if (plain == NULL) {
			return -ENOMEM;
		}
		ret = pc->sec->decrypt(pc->sec_ctx, inbuf, inlen, plain, &plain_len);
		if (ret != 0) {
			k_free(plain);
			return ret;
		}
	}

	uint8_t *raw_out = NULL;
	size_t raw_len = 0;

	ret = ep->handler(ep->priv, plain, plain_len, &raw_out, &raw_len);
	k_free(plain);
	if (ret != 0) {
		k_free(raw_out);
		return ret;
	}

	if (raw_len == 0) {
		*outbuf = NULL;
		*outlen = 0;
		return 0;
	}

	/* Encrypt the response in place into a fresh buffer. */
	uint8_t *enc = k_malloc(raw_len);

	if (enc == NULL) {
		k_free(raw_out);
		return -ENOMEM;
	}
	size_t enc_len = 0;

	ret = pc->sec->encrypt(pc->sec_ctx, raw_out, raw_len, enc, &enc_len);
	k_free(raw_out);
	if (ret != 0) {
		k_free(enc);
		return ret;
	}
	*outbuf = enc;
	*outlen = enc_len;
	return 0;
}

int protocomm_req_handle(struct protocomm *pc, const char *ep_name,
			 const uint8_t *inbuf, size_t inlen,
			 uint8_t **outbuf, size_t *outlen)
{
	if (pc == NULL || ep_name == NULL || outbuf == NULL || outlen == NULL) {
		return -EINVAL;
	}
	*outbuf = NULL;
	*outlen = 0;

	struct protocomm_ep *ep = find_ep(pc, ep_name);

	if (ep == NULL) {
		LOG_WRN("request for unknown endpoint '%s'", ep_name);
		return -ENOENT;
	}

	switch (ep->type) {
	case EP_VERSION:
		return handle_version(pc, outbuf, outlen);
	case EP_SECURITY:
		if (pc->sec == NULL || pc->sec->handshake == NULL) {
			return -ENOSYS;
		}
		return pc->sec->handshake(pc->sec_ctx, inbuf, inlen, outbuf, outlen);
	case EP_DATA:
	default:
		if (pc->sec == NULL || pc->sec_ctx == NULL) {
			LOG_WRN("data request before session established");
			return -EACCES;
		}
		return handle_data(pc, ep, inbuf, inlen, outbuf, outlen);
	}
}

size_t protocomm_endpoint_count(const struct protocomm *pc)
{
	return pc ? pc->n_endpoints : 0;
}

const char *protocomm_endpoint_name(const struct protocomm *pc, size_t idx)
{
	if (pc == NULL || idx >= pc->n_endpoints) {
		return NULL;
	}
	return pc->endpoints[idx].name;
}
