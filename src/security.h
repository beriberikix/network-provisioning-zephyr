/*
 * Internal security-scheme objects and shared protobuf helper.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef NETWORK_PROVISIONING_SECURITY_H_
#define NETWORK_PROVISIONING_SECURITY_H_

#include <stddef.h>
#include <stdint.h>
#include <pb.h>

#include "protocomm.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const struct protocomm_security network_prov_security0;
extern const struct protocomm_security network_prov_security1;

/**
 * Encode a nanopb message into a freshly allocated buffer.
 *
 * @param fields  nanopb message descriptor (e.g. SessionData_fields).
 * @param src     Pointer to the populated message struct.
 * @param outbuf  Set to a k_malloc'd buffer holding the encoded bytes.
 * @param outlen  Set to the encoded length.
 * @return 0 on success, negative errno otherwise.
 */
int network_prov_pb_encode(const pb_msgdesc_t *fields, const void *src,
			   uint8_t **outbuf, size_t *outlen);

#ifdef __cplusplus
}
#endif

#endif /* NETWORK_PROVISIONING_SECURITY_H_ */
