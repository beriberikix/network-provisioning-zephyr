/*
 * Integration test for the SoftAP (HTTP) transport: a minimal HTTP client on
 * the loopback interface drives the real transport glue — URI routing, body
 * round-trips and the cookie-based session semantics — with the same
 * security-1 handshake the stock clients use, so a transport-level session
 * reset or keystream desync fails loudly here.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <zephyr/kernel.h>
#include <zephyr/ztest.h>
#include <zephyr/net/socket.h>

#include <psa/crypto.h>
#include <pb_encode.h>
#include <pb_decode.h>
#include "session.pb.h"

#include "protocomm.h"
#include "security.h"
#include "network_prov_internal.h"

#define SERVER_ADDR "127.0.0.1"
#define SERVER_PORT 80

#define VERSION_JSON "{\"prov\":{\"ver\":\"v1.1\",\"sec_ver\":1}}"

#define PUBKEY_LEN  32
#define RANDOM_LEN  16
#define KEY_LEN     32
#define POP         "abcd1234"

static struct protocomm *pc;
static char cookie[64]; /* "session=<id>" captured from Set-Cookie */

/* ------------------------------------------------------------------------- */
/* Client-side security-1 implementation (same as tests/security1).          */

struct client {
	psa_key_id_t key;               /* client X25519 key pair */
	uint8_t pubkey[PUBKEY_LEN];
	uint8_t device_pubkey[PUBKEY_LEN];
	psa_key_id_t session_key;       /* AES-256 */
	psa_cipher_operation_t cipher;  /* persistent CTR keystream */
};

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

/* ------------------------------------------------------------------------- */
/* Minimal HTTP client.                                                      */

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

static int connect_to_server(void)
{
	struct net_sockaddr_in addr = {
		.sin_family = NET_AF_INET,
		.sin_port = net_htons(SERVER_PORT),
	};

	zsock_inet_pton(NET_AF_INET, SERVER_ADDR, &addr.sin_addr.s_addr);

	/* With MAX_CLIENTS=1 the server may still be tearing down the
	 * previous connection; retry briefly with a fresh socket each time.
	 */
	int sock = -1;

	for (int attempt = 0; attempt < 100; attempt++) {
		sock = zsock_socket(NET_AF_INET, NET_SOCK_STREAM,
				    NET_IPPROTO_TCP);
		zassert_true(sock >= 0, "socket failed: %d", -errno);

		if (zsock_connect(sock, (struct net_sockaddr *)&addr,
				  sizeof(addr)) == 0) {
			break;
		}
		zsock_close(sock);
		sock = -1;
		k_sleep(K_MSEC(20));
	}
	zassert_true(sock >= 0, "connect failed: %d", -errno);
	return sock;
}

/* Mirror the header set (and order) of esp_prov's python http.client —
 * notably the 33-char Content-Type that exceeds the server's default
 * CONFIG_HTTP_SERVER_MAX_HEADER_LEN, with Cookie after it.
 */
static int send_request(int sock, const char *uri, const uint8_t *body,
			size_t body_len, bool send_cookie, bool close_conn)
{
	char hdr[320];
	int hdr_len = snprintf(hdr, sizeof(hdr),
			       "POST %s HTTP/1.1\r\n"
			       "Host: %s\r\n"
			       "Accept-Encoding: identity\r\n"
			       "Content-Length: %zu\r\n"
			       "Content-Type: application/x-www-form-urlencoded\r\n"
			       "Accept: text/plain\r\n"
			       "%s%s%s"
			       "%s"
			       "\r\n",
			       uri, SERVER_ADDR, body_len,
			       send_cookie ? "Cookie: " : "",
			       send_cookie ? cookie : "",
			       send_cookie ? "\r\n" : "",
			       close_conn ? "Connection: close\r\n" : "");

	zassert_true(hdr_len > 0 && hdr_len < (int)sizeof(hdr));
	zassert_equal(zsock_send(sock, hdr, hdr_len, 0), hdr_len);
	if (body_len > 0) {
		zassert_equal(zsock_send(sock, body, body_len, 0),
			      (ssize_t)body_len);
	}
	return 0;
}

/* Parse one buffered HTTP response: check the status, capture Set-Cookie and
 * de-chunk the body into resp. Returns the body length, or -EIO on a non-200
 * status. The body is binary-safe (responses carry raw protobuf).
 */
static int parse_response(uint8_t *raw, size_t total, uint8_t *resp,
			  size_t resp_size)
{
	raw[MIN(total, (size_t)2047)] = '\0';

	if (strncmp((char *)raw, "HTTP/1.1 200", 12) != 0) {
		return -EIO;
	}

	char *sc = strstr((char *)raw, "Set-Cookie: ");

	if (sc != NULL) {
		sc += strlen("Set-Cookie: ");

		size_t i = 0;

		while (sc[i] != '\r' && sc[i] != '\0' && i < sizeof(cookie) - 1) {
			cookie[i] = sc[i];
			i++;
		}
		cookie[i] = '\0';
	}

	char *body_start = strstr((char *)raw, "\r\n\r\n");

	zassert_not_null(body_start, "no header/body separator");
	body_start += 4;

	/* Dynamic resources respond with chunked transfer encoding: decode
	 * "<hex-size>\r\n<data>\r\n" frames until the terminating 0 chunk.
	 */
	if (strstr((char *)raw, "Transfer-Encoding: chunked") != NULL) {
		char *p = body_start;
		size_t out = 0;

		while ((size_t)(p - (char *)raw) < total) {
			char *endptr;
			size_t chunk = strtoul(p, &endptr, 16);

			if (chunk == 0) {
				break;
			}
			p = strstr(endptr, "\r\n");
			zassert_not_null(p, "malformed chunk header");
			p += 2;
			zassert_true(out + chunk <= resp_size,
				     "response too large");
			memcpy(resp + out, p, chunk);
			out += chunk;
			p += chunk + 2; /* skip data + CRLF */
		}
		return (int)out;
	}

	size_t blen = total - (body_start - (char *)raw);

	zassert_true(blen <= resp_size, "response too large");
	memcpy(resp, body_start, blen);
	return (int)blen;
}

/* One POST on a fresh connection with "Connection: close". */
static int http_post(const char *uri, const uint8_t *body, size_t body_len,
		     bool send_cookie, uint8_t *resp, size_t resp_size)
{
	int sock = connect_to_server();

	send_request(sock, uri, body, body_len, send_cookie, true);

	/* Read until the peer closes. */
	static uint8_t raw[2048];
	size_t total = 0;

	while (total < sizeof(raw) - 1) {
		ssize_t n = zsock_recv(sock, raw + total,
				       sizeof(raw) - 1 - total, 0);

		if (n <= 0) {
			break;
		}
		total += n;
	}
	zsock_close(sock);
	zassert_true(total > 0, "empty HTTP response");

	return parse_response(raw, total, resp, resp_size);
}

/* One POST on an already-open keep-alive connection, mirroring esp_prov's
 * persistent http.client connection. Reads exactly one chunked response
 * (terminated by the 0-length chunk; binary-safe search).
 */
static int http_post_keepalive(int sock, const char *uri, const uint8_t *body,
			       size_t body_len, bool send_cookie,
			       uint8_t *resp, size_t resp_size)
{
	send_request(sock, uri, body, body_len, send_cookie, false);

	static const char term[] = "\r\n0\r\n\r\n";
	static uint8_t raw[2048];
	size_t total = 0;
	bool found = false;

	while (!found && total < sizeof(raw) - 1) {
		ssize_t n = zsock_recv(sock, raw + total,
				       sizeof(raw) - 1 - total, 0);

		zassert_true(n > 0, "connection closed mid-response");
		total += n;

		for (size_t i = 0; total >= sizeof(term) - 1 &&
				   i <= total - (sizeof(term) - 1); i++) {
			if (memcmp(raw + i, term, sizeof(term) - 1) == 0) {
				found = true;
				break;
			}
		}
	}

	return parse_response(raw, total, resp, resp_size);
}

/* Post abstraction: sock < 0 means a fresh connection per request. */
struct poster {
	int sock;
	bool send_cookie;
};

static int do_post(struct poster *p, const char *uri, const uint8_t *body,
		   size_t body_len, uint8_t *resp, size_t resp_size)
{
	if (p->sock >= 0) {
		return http_post_keepalive(p->sock, uri, body, body_len,
					   p->send_cookie, resp, resp_size);
	}
	return http_post(uri, body, body_len, p->send_cookie, resp, resp_size);
}

/* ------------------------------------------------------------------------- */
/* Security-1 handshake over HTTP.                                           */

static int post_session_msg(struct poster *p, const SessionData *cmd,
			    SessionData *resp_out)
{
	uint8_t buf[128];
	pb_ostream_t ostream = pb_ostream_from_buffer(buf, sizeof(buf));

	zassert_true(pb_encode(&ostream, SessionData_fields, cmd),
		     "encode failed: %s", PB_GET_ERROR(&ostream));

	uint8_t resp[256];
	int rlen = do_post(p, "/prov-session", buf, ostream.bytes_written,
			   resp, sizeof(resp));

	if (rlen < 0) {
		return rlen;
	}

	pb_istream_t istream = pb_istream_from_buffer(resp, rlen);

	zassert_true(pb_decode(&istream, SessionData_fields, resp_out),
		     "decode failed: %s", PB_GET_ERROR(&istream));
	return 0;
}

/* Full security-1 handshake; returns the Command1 result (0 on success). The
 * two-step shape makes it sensitive to transport session resets: a reset
 * between Command0 and Command1 fails with "command1 before command0".
 */
static int run_handshake(struct poster *p, struct client *c)
{
	client_keygen(c);

	SessionData cmd0 = SessionData_init_default;

	cmd0.sec_ver = SecSchemeVersion_SecScheme1;
	cmd0.which_proto = SessionData_sec1_tag;
	cmd0.proto.sec1.msg = Sec1MsgType_Session_Command0;
	cmd0.proto.sec1.which_payload = Sec1Payload_sc0_tag;
	cmd0.proto.sec1.payload.sc0.client_pubkey.size = PUBKEY_LEN;
	memcpy(cmd0.proto.sec1.payload.sc0.client_pubkey.bytes, c->pubkey,
	       PUBKEY_LEN);

	SessionData resp0 = SessionData_init_default;

	zassert_equal(post_session_msg(p, &cmd0, &resp0), 0, "command0 failed");
	zassert_equal(resp0.proto.sec1.msg, Sec1MsgType_Session_Response0);
	zassert_equal(resp0.proto.sec1.payload.sr0.status, Status_Success);
	zassert_equal(resp0.proto.sec1.payload.sr0.device_pubkey.size, PUBKEY_LEN);
	zassert_equal(resp0.proto.sec1.payload.sr0.device_random.size, RANDOM_LEN);
	memcpy(c->device_pubkey, resp0.proto.sec1.payload.sr0.device_pubkey.bytes,
	       PUBKEY_LEN);

	client_derive(c, POP, resp0.proto.sec1.payload.sr0.device_random.bytes);

	/* client_verify = keystream[0..31] XOR device_pubkey */
	uint8_t client_verify[PUBKEY_LEN];

	client_xform(c, c->device_pubkey, PUBKEY_LEN, client_verify);

	SessionData cmd1 = SessionData_init_default;

	cmd1.sec_ver = SecSchemeVersion_SecScheme1;
	cmd1.which_proto = SessionData_sec1_tag;
	cmd1.proto.sec1.msg = Sec1MsgType_Session_Command1;
	cmd1.proto.sec1.which_payload = Sec1Payload_sc1_tag;
	cmd1.proto.sec1.payload.sc1.client_verify_data.size = PUBKEY_LEN;
	memcpy(cmd1.proto.sec1.payload.sc1.client_verify_data.bytes,
	       client_verify, PUBKEY_LEN);

	SessionData resp1 = SessionData_init_default;
	int ret = post_session_msg(p, &cmd1, &resp1);

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

/* Encrypted round trip through the echo endpoint; the shared CTR keystream
 * must be in lock-step or the decrypted reply is garbage.
 */
static int encrypted_echo(struct poster *p, struct client *c, const char *msg)
{
	size_t mlen = strlen(msg);
	uint8_t enc[64];

	zassert_true(mlen <= sizeof(enc));
	client_xform(c, (const uint8_t *)msg, mlen, enc);

	uint8_t out[128];
	int outlen = do_post(p, "/prov-config", enc, mlen, out, sizeof(out));

	if (outlen < 0) {
		return outlen;
	}

	char plain[80];

	zassert_true(outlen < (int)sizeof(plain));
	client_xform(c, out, outlen, (uint8_t *)plain);
	plain[outlen] = '\0';

	char expect[80];

	snprintf(expect, sizeof(expect), "echo:%s", msg);
	zassert_str_equal(plain, expect);
	return 0;
}

/* ------------------------------------------------------------------------- */

static void *suite_setup(void)
{
	pc = protocomm_new();
	zassert_not_null(pc);
	zassert_equal(protocomm_set_version(pc, "proto-ver", VERSION_JSON), 0);
	zassert_equal(protocomm_set_security(pc, "prov-session",
					     &network_prov_security1, POP), 0);
	/* Reuse a standard endpoint URI for the echo data endpoint. */
	zassert_equal(protocomm_add_endpoint(pc, "prov-config", echo_handler,
					     NULL), 0);

	zassert_equal(network_prov_softap_http_start(pc), 0);
	/* Give the server thread a moment to start listening. */
	k_sleep(K_MSEC(100));
	return NULL;
}

static void suite_teardown(void *fixture)
{
	ARG_UNUSED(fixture);
	network_prov_softap_http_stop();
	protocomm_delete(pc);
}

ZTEST(protocomm_http, test_01_proto_ver)
{
	uint8_t resp[128];
	int rlen = http_post("/proto-ver", (const uint8_t *)"---", 3, false,
			     resp, sizeof(resp));

	zassert_equal(rlen, (int)strlen(VERSION_JSON));
	zassert_mem_equal(resp, VERSION_JSON, rlen);
	zassert_true(strncmp(cookie, "session=", 8) == 0,
		     "no session cookie issued");
}

ZTEST(protocomm_http, test_02_sec1_session_per_request_connections)
{
	/* iOS-style client: every request on a fresh TCP connection, the
	 * session carried purely by the cookie.
	 */
	struct poster p = { .sock = -1, .send_cookie = true };
	struct client c = {0};

	zassert_equal(run_handshake(&p, &c), 0, "handshake failed");
	zassert_equal(encrypted_echo(&p, &c, "hello-over-http"), 0);
	zassert_equal(encrypted_echo(&p, &c, "second message"), 0);

	client_destroy(&c);
}

ZTEST(protocomm_http, test_03_cookie_reset_semantics)
{
	/* Establish a session, then send a request WITHOUT the cookie: the
	 * transport must reset the protocomm session (fresh cookie, old
	 * keystream dead) so an unknown client can never ride along.
	 */
	struct poster p = { .sock = -1, .send_cookie = true };
	struct client c = {0};

	zassert_equal(run_handshake(&p, &c), 0, "handshake failed");
	zassert_equal(encrypted_echo(&p, &c, "before reset"), 0);

	char saved_cookie[sizeof(cookie)];

	memcpy(saved_cookie, cookie, sizeof(saved_cookie));

	uint8_t resp[128];
	int rlen = http_post("/proto-ver", (const uint8_t *)"---", 3, false,
			     resp, sizeof(resp));

	zassert_true(rlen > 0);
	zassert_true(strcmp(cookie, saved_cookie) != 0,
		     "cookie should have rotated on session reset");

	/* The old security session must be gone. */
	zassert_true(encrypted_echo(&p, &c, "stale keystream") < 0,
		     "request with the old session state should fail");
	client_destroy(&c);

	/* New session: a fresh handshake under the new cookie works. */
	struct client c2 = {0};

	zassert_equal(run_handshake(&p, &c2), 0, "re-handshake failed");
	zassert_equal(encrypted_echo(&p, &c2, "second session"), 0);
	client_destroy(&c2);
}

ZTEST(protocomm_http, test_04_keepalive_like_esp_prov)
{
	/* esp_prov drives every request through one persistent connection;
	 * replicate that: proto-ver, the sec1 handshake and encrypted data
	 * round-trips without closing the socket in between.
	 */
	int sock = connect_to_server();

	uint8_t resp[128];
	int rlen = http_post_keepalive(sock, "/proto-ver",
				       (const uint8_t *)"---", 3, false,
				       resp, sizeof(resp));

	zassert_equal(rlen, (int)strlen(VERSION_JSON));
	zassert_true(strncmp(cookie, "session=", 8) == 0,
		     "no session cookie issued");

	struct poster p = { .sock = sock, .send_cookie = true };
	struct client c = {0};

	zassert_equal(run_handshake(&p, &c), 0, "keep-alive handshake failed");
	zassert_equal(encrypted_echo(&p, &c, "hello-keepalive"), 0);
	zassert_equal(encrypted_echo(&p, &c, "still in lock-step"), 0);

	client_destroy(&c);
	zsock_close(sock);
}

ZTEST_SUITE(protocomm_http, NULL, suite_setup, NULL, NULL, suite_teardown);
