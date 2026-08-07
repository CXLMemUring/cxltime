// SPDX-License-Identifier: MIT
#pragma once

#include "pgas_x86_memory_access.hpp"

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

pgas_x86_bulk_plan pgas_x86_plan_bulk(pgas_x86_bulk_kind kind,
                                      uint64_t destination, uint64_t source,
                                      uint64_t size);

bool pgas_x86_bulk_next(const pgas_x86_runtime_config &config,
                        const pgas_x86_bulk_plan &plan, uint64_t completed,
                        pgas_x86_bulk_chunk &chunk);

} // namespace bpftime::attach
