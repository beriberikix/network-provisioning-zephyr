/*
 * Shared constants/helpers for the Thread provisioning BabbleSim E2E.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef NETWORK_PROV_BSIM_THREAD_COMMON_H_
#define NETWORK_PROV_BSIM_THREAD_COMMON_H_

#include <openthread/dataset.h>

/* The network the peer node forms and the DUT scan must discover. */
#define PEER_NET_NAME "ot-e2e-net"
#define PEER_CHANNEL  20

/* Build a complete Active Operational Dataset with a known network name and
 * channel (random key/PAN/ext-PAN), serialised to TLVs. Used by the peer to
 * form the discoverable network. Returns 0 on success.
 */
int build_peer_dataset(otOperationalDatasetTlvs *out);

#endif /* NETWORK_PROV_BSIM_THREAD_COMMON_H_ */
