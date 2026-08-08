// SPDX-License-Identifier: MIT
#pragma once

#include "pgas_x86_memory_access.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace bpftime::attach {

enum class pgas_x86_bulk_kind { copy, move, set };
enum class pgas_x86_copy_direction { forward, backward };

struct pgas_x86_bulk_chunk {
    uint64_t destination{};
    uint64_t source{};
    uint32_t size{};
    uint16_t destination_node{};
    uint16_t source_node{};
    bool destination_remote{};
    bool source_remote{};
};

struct pgas_x86_bulk_plan {
    pgas_x86_bulk_kind kind{};
    pgas_x86_copy_direction direction{};
    uint64_t destination{};
    uint64_t source{};
    uint64_t total_size{};
    uint32_t chunk_size{ 64 * 1024 };
    int status{};
};

struct pgas_x86_bulk_range {
    uint64_t address{};
    uint64_t size{};
};

struct pgas_x86_bulk_lock {
    pgas_x86_runtime *runtime{};
    std::array<uint16_t, 4096> stripes{};
    uint16_t acquired{};
    bool active{};
};

pgas_x86_bulk_plan pgas_x86_plan_bulk(pgas_x86_bulk_kind kind,
                                      uint64_t destination, uint64_t source,
                                      uint64_t size);

bool pgas_x86_bulk_next(const pgas_x86_runtime_config &config,
                        const pgas_x86_bulk_plan &plan, uint64_t completed,
                        pgas_x86_bulk_chunk &chunk);

int pgas_x86_bulk_copy(pgas_x86_runtime *runtime, void *destination,
                       const void *source, size_t size);
// Internal seed path: update the writable shadow alias while the application
// view remains read-only, then publish the same bytes remotely.
int pgas_x86_bulk_seed(pgas_x86_runtime *runtime, void *destination,
                       const void *source, size_t size);
int pgas_x86_bulk_move(pgas_x86_runtime *runtime, void *destination,
                       const void *source, size_t size);
int pgas_x86_bulk_set(pgas_x86_runtime *runtime, void *destination,
                      unsigned char value, size_t size);
int pgas_x86_bulk_refresh(pgas_x86_runtime *runtime, void *address,
                          size_t size);
int pgas_x86_bulk_flush(pgas_x86_runtime *runtime, const void *address,
                        size_t size);
int pgas_x86_bulk_lock_ranges(pgas_x86_runtime *runtime,
                              const pgas_x86_bulk_range *ranges,
                              size_t range_count,
                              pgas_x86_bulk_lock &lock);
void pgas_x86_bulk_unlock_ranges(pgas_x86_bulk_lock &lock);
int pgas_x86_bulk_refresh_locked(pgas_x86_runtime *runtime, void *address,
                                 size_t size);
int pgas_x86_bulk_flush_locked(pgas_x86_runtime *runtime,
                               const void *address, size_t size);

} // namespace bpftime::attach
