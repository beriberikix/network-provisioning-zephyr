/*
 * Shared dataset builder for the Thread provisioning BabbleSim E2E.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include <openthread.h>
#include <openthread/dataset.h>
#include <openthread/dataset_ftd.h>

#include "common.h"

int build_peer_dataset(otOperationalDatasetTlvs *out)
{
	/* Caller holds the OpenThread mutex. */
	otInstance *inst = openthread_get_default_instance();
	otOperationalDataset ds;

	if (otDatasetCreateNewNetwork(inst, &ds) != OT_ERROR_NONE) {
		return -1;
	}

	/* Override the name and channel with known values so the DUT can scan the
	 * right channel and assert on the discovered network name.
	 */
	memset(ds.mNetworkName.m8, 0, sizeof(ds.mNetworkName.m8));
	strncpy(ds.mNetworkName.m8, PEER_NET_NAME, sizeof(ds.mNetworkName.m8) - 1);
	ds.mComponents.mIsNetworkNamePresent = true;
	ds.mChannel = PEER_CHANNEL;
	ds.mComponents.mIsChannelPresent = true;

	otDatasetConvertToTlvs(&ds, out);
	return 0;
}
