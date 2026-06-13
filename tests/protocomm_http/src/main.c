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

#include "protocomm.h"
#include "security.h"
#include "network_prov_internal.h"
#include "prov_client.h"

#define SERVER_ADDR "127.0.0.1"
#define SERVER_PORT 80

#define VERSION_JSON "{\"prov\":{\"ver\":\"v1.1\",\"sec_ver\":1}}"

#define POP "abcd1234"

static struct protocomm *pc;
static char cookie[64]; /* "session=<id>" captured from Set-Cookie */

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

	/* Bound every read so a wedged server (e.g. a poll-budget regression
	 * that leaves a connection unserved) fails the test cleanly instead of
	 * blocking forever.
	 */
	struct zsock_timeval tv = { .tv_sec = 4, .tv_usec = 0 };

	(void)zsock_setsockopt(sock, ZSOCK_SOL_SOCKET, ZSOCK_SO_RCVTIMEO,
			       &tv, sizeof(tv));
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
/* Security-1 handshake over HTTP, via the shared prov_client.               */

/* prov_client transport adapter: POST the encoded request to "/<ep>" and hand
 * the de-chunked body back in a k_malloc()'d buffer (freed by prov_client).
 */
static int http_xport(void *ctx, const char *ep, const uint8_t *in, size_t inlen,
		      uint8_t **out, size_t *outlen)
{
	struct poster *p = ctx;
	char uri[64];

	snprintf(uri, sizeof(uri), "/%s", ep);

	uint8_t resp[256];
	int rlen = do_post(p, uri, in, inlen, resp, sizeof(resp));

	if (rlen < 0) {
		return rlen;
	}

	uint8_t *buf = k_malloc(rlen > 0 ? (size_t)rlen : 1);

	if (buf == NULL) {
		return -ENOMEM;
	}
	memcpy(buf, resp, rlen);
	*out = buf;
	*outlen = rlen;
	return 0;
}

/* Encrypted round trip through the echo endpoint; the shared CTR keystream
 * must be in lock-step or the decrypted reply is garbage.
 */
static int encrypted_echo(struct poster *p, struct prov_client *c, const char *msg)
{
	size_t mlen = strlen(msg);
	uint8_t enc[64];

	zassert_true(mlen <= sizeof(enc));
	zassert_equal(prov_client_xform(c, (const uint8_t *)msg, mlen, enc), 0);

	uint8_t out[128];
	int outlen = do_post(p, "/prov-config", enc, mlen, out, sizeof(out));

	if (outlen < 0) {
		return outlen;
	}

	char plain[80];

	zassert_true(outlen < (int)sizeof(plain));
	zassert_equal(prov_client_xform(c, out, outlen, (uint8_t *)plain), 0);
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
	struct prov_client c;

	prov_client_init(&c, http_xport, &p);
	zassert_equal(prov_client_handshake(&c, POP), 0, "handshake failed");
	zassert_equal(encrypted_echo(&p, &c, "hello-over-http"), 0);
	zassert_equal(encrypted_echo(&p, &c, "second message"), 0);

	prov_client_destroy(&c);
}

ZTEST(protocomm_http, test_03_cookie_reset_semantics)
{
	/* Establish a session, then send a request WITHOUT the cookie: the
	 * transport must reset the protocomm session (fresh cookie, old
	 * keystream dead) so an unknown client can never ride along.
	 */
	struct poster p = { .sock = -1, .send_cookie = true };
	struct prov_client c;

	prov_client_init(&c, http_xport, &p);
	zassert_equal(prov_client_handshake(&c, POP), 0, "handshake failed");
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
	prov_client_destroy(&c);

	/* New session: a fresh handshake under the new cookie works. */
	struct prov_client c2;

	prov_client_init(&c2, http_xport, &p);
	zassert_equal(prov_client_handshake(&c2, POP), 0, "re-handshake failed");
	zassert_equal(encrypted_echo(&p, &c2, "second session"), 0);
	prov_client_destroy(&c2);
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
	struct prov_client c;

	prov_client_init(&c, http_xport, &p);
	zassert_equal(prov_client_handshake(&c, POP), 0, "keep-alive handshake failed");
	zassert_equal(encrypted_echo(&p, &c, "hello-keepalive"), 0);
	zassert_equal(encrypted_echo(&p, &c, "still in lock-step"), 0);

	prov_client_destroy(&c);
	zsock_close(sock);
}

ZTEST(protocomm_http, test_05_concurrent_connections)
{
	/* The Android app's HttpURLConnection opens a fresh connection for the
	 * next status poll while a previous keep-alive one still lingers, so
	 * the server must service several connections at once. The server
	 * polls (1 eventfd + 1 listener + MAX_CLIENTS) sockets in a single
	 * zsock_poll(); if CONFIG_ZVFS_POLL_MAX is smaller than that, the poll
	 * fails with ENOMEM once a second client connects and that client gets
	 * an empty/closed response — which the stock app feeds to
	 * Cipher.update(null) ("Null input buffer").
	 *
	 * Hold connection A open (keep-alive) while opening B and C, so the
	 * server's poll set grows to eventfd + listener + 3 clients, then drive
	 * a request on each and confirm all are served.
	 */
	uint8_t resp[128];
	int a = connect_to_server();
	int rlen = http_post_keepalive(a, "/proto-ver", (const uint8_t *)"-", 1,
				       false, resp, sizeof(resp));

	zassert_equal(rlen, (int)strlen(VERSION_JSON), "connection A");

	int b = connect_to_server(); /* A still open: poll set now has 2 clients */

	rlen = http_post_keepalive(b, "/proto-ver", (const uint8_t *)"-", 1,
				   false, resp, sizeof(resp));
	zassert_equal(rlen, (int)strlen(VERSION_JSON),
		      "second concurrent connection not served (poll budget?)");

	int c = connect_to_server(); /* A and B still open: 3 clients */

	rlen = http_post_keepalive(c, "/proto-ver", (const uint8_t *)"-", 1,
				   false, resp, sizeof(resp));
	zassert_equal(rlen, (int)strlen(VERSION_JSON),
		      "third concurrent connection not served (poll budget?)");

	/* A and B must still work after the others joined the poll set. */
	rlen = http_post_keepalive(a, "/proto-ver", (const uint8_t *)"-", 1,
				   false, resp, sizeof(resp));
	zassert_equal(rlen, (int)strlen(VERSION_JSON), "connection A after B/C");
	rlen = http_post_keepalive(b, "/proto-ver", (const uint8_t *)"-", 1,
				   false, resp, sizeof(resp));
	zassert_equal(rlen, (int)strlen(VERSION_JSON), "connection B after C");

	zsock_close(a);
	zsock_close(b);
	zsock_close(c);
}

ZTEST_SUITE(protocomm_http, NULL, suite_setup, NULL, NULL, suite_teardown);
