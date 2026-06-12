/* Iterable section for the SoftAP transport's HTTP resources.
 * Each HTTP_SERVICE_DEFINE needs a matching ITERABLE_SECTION_ROM entry.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/linker/iterable_sections.h>

ITERABLE_SECTION_ROM(http_resource_desc_network_prov_http_service, Z_LINK_ITERABLE_SUBALIGN)
