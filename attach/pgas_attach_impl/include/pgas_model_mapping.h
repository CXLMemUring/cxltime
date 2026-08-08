// SPDX-License-Identifier: MIT
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct pgas_model_inventory_c {
    uint64_t mapped_bytes;
    uint64_t seeded_bytes;
    uint64_t node0_model_bytes;
    uint64_t node1_model_bytes;
    uint64_t rejected_mappings;
    uint64_t dram_fallbacks;
    uint32_t views;
};

void *pgas_model_map(int fd, size_t length, off_t offset, int *error_out);
int pgas_model_unmap(void *address, size_t length);
int pgas_model_get_inventory(struct pgas_model_inventory_c *out);

#ifdef __cplusplus
}
#endif
