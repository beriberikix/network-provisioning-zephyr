/*
 * Console (shell) transport for protocomm.
 *
 * Carries the provisioning protocol over the device console for bring-up and
 * debugging — the transport esp_prov speaks with `--transport console`. A
 * single shell command,
 *
 *     net_prov <endpoint> <session_id> <hex-request>
 *
 * decodes the hex request, runs it through the named protocomm endpoint and
 * prints the response as lowercase hex (an empty line for an empty response).
 * The session_id mirrors upstream's per-session reset: a change in its value
 * opens a fresh protocomm session (resetting the security handshake), the way a
 * BLE connect or a new HTTP cookie does on the other transports.
 *
 * The bridging between this command and esp_prov is manual (human-in-the-loop),
 * exactly as upstream's console scheme: esp_prov prints the request line for an
 * operator to paste here, and the device's hex response is pasted back.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/shell/shell.h>
#include <zephyr/sys/util.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "protocomm.h"
#include "network_prov_internal.h"
#include "network_provisioning/scheme_console.h"

LOG_MODULE_DECLARE(network_prov, CONFIG_NETWORK_PROV_LOG_LEVEL);

static struct protocomm *g_pc;
static uint32_t cur_session;
static bool have_session;

int network_prov_console_start(struct protocomm *pc)
{
	g_pc = pc;
	have_session = false;
	cur_session = 0;
	LOG_INF("console provisioning started (shell command 'net_prov')");
	return 0;
}

void network_prov_console_stop(void)
{
	if (g_pc != NULL) {
		protocomm_close_session(g_pc);
	}
	g_pc = NULL;
	have_session = false;
}

/* Scheme vtable: the console takes neither a service name nor a key. */
static int console_scheme_start(struct protocomm *pc, const char *service_name,
				const char *service_key)
{
	ARG_UNUSED(service_name);
	ARG_UNUSED(service_key);
	return network_prov_console_start(pc);
}

const struct network_prov_scheme network_prov_scheme_console = {
	.start = console_scheme_start,
	.stop = network_prov_console_stop,
};

static int cmd_net_prov(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);

	if (g_pc == NULL) {
		shell_error(sh, "net_prov: provisioning not started");
		return -ENOEXEC;
	}

	const char *ep = argv[1];
	char *endp;

	errno = 0;
	unsigned long parsed = strtoul(argv[2], &endp, 10);

	/* Require the whole token to be a number and reject out-of-range values,
	 * so distinct inputs can't alias the same session (matches the SoftAP
	 * cookie parsing).
	 */
	if (argv[2][0] == '\0' || *endp != '\0' || errno == ERANGE ||
	    parsed > UINT32_MAX) {
		shell_error(sh, "net_prov: bad session_id '%s'", argv[2]);
		return -EINVAL;
	}
	uint32_t session = (uint32_t)parsed;

	size_t hexlen = strlen(argv[3]);

	if ((hexlen & 1) != 0) {
		shell_error(sh, "net_prov: hex data must have an even length");
		return -EINVAL;
	}

	size_t inlen = hexlen / 2;
	uint8_t *inbuf = k_malloc(inlen > 0 ? inlen : 1);

	if (inbuf == NULL) {
		shell_error(sh, "net_prov: out of memory");
		return -ENOMEM;
	}
	if (inlen > 0 && hex2bin(argv[3], hexlen, inbuf, inlen) != inlen) {
		shell_error(sh, "net_prov: invalid hex data");
		k_free(inbuf);
		return -EINVAL;
	}

	/* A new session_id resets the protocomm session, like a BLE reconnect
	 * or a fresh HTTP cookie does on the other transports.
	 */
	if (!have_session || session != cur_session) {
		protocomm_open_session(g_pc);
		cur_session = session;
		have_session = true;
	}

	uint8_t *out = NULL;
	size_t outlen = 0;
	int ret = protocomm_req_handle(g_pc, ep, inbuf, inlen, &out, &outlen);

	k_free(inbuf);
	if (ret != 0) {
		shell_error(sh, "net_prov: endpoint '%s' failed: %d", ep, ret);
		return -ENOEXEC;
	}

	/* Emit the response as lowercase hex (empty line for an empty body). */
	size_t hexsize = outlen * 2 + 1;
	char *hexout = k_malloc(hexsize);

	if (hexout == NULL) {
		k_free(out);
		shell_error(sh, "net_prov: out of memory");
		return -ENOMEM;
	}
	(void)bin2hex(out, outlen, hexout, hexsize);
	shell_print(sh, "%s", hexout);

	k_free(hexout);
	k_free(out);
	return 0;
}

SHELL_CMD_ARG_REGISTER(net_prov, NULL,
		       "Provisioning console transport: "
		       "net_prov <endpoint> <session_id> <hex-request>",
		       cmd_net_prov, 4, 0);
