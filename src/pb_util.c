/*
 * Shared nanopb helper: encode a message into a k_malloc'd buffer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <errno.h>

#include <pb_encode.h>
#include "security.h"

int network_prov_pb_encode(const pb_msgdesc_t *fields, const void *src,
			   uint8_t **outbuf, size_t *outlen)
{
	size_t size = 0;

	if (!pb_get_encoded_size(&size, fields, src)) {
		return -EINVAL;
	}

	uint8_t *buf = k_malloc(size ? size : 1);

	if (buf == NULL) {
		return -ENOMEM;
	}

	pb_ostream_t ostream = pb_ostream_from_buffer(buf, size);

	if (!pb_encode(&ostream, fields, src)) {
		k_free(buf);
		return -EINVAL;
	}

	*outbuf = buf;
	*outlen = ostream.bytes_written;
	return 0;
}
