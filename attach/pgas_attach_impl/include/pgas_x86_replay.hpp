// SPDX-License-Identifier: MIT
#pragma once

#include "pgas_x86_memory_access.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace bpftime::attach {

constexpr size_t pgas_x86_max_replay_lanes = 64;
constexpr size_t pgas_x86_max_replay_fragments = 128;

struct pgas_x86_replay_lane {
    uint64_t address{};
    uint16_t byte_offset{};
    uint8_t width{};
    uint8_t lane{};
    bool active{};
    bool remote{};
};

struct pgas_x86_replay_fragment {
    uint64_t address{};
    uint16_t byte_offset{};
    uint8_t size{};
    uint16_t node{};
    uint64_t line{};
    bool remote{};
};

struct pgas_x86_replay_plan {
    std::array<pgas_x86_replay_lane, pgas_x86_max_replay_lanes> lanes{};
    std::array<pgas_x86_replay_fragment,
               pgas_x86_max_replay_fragments>
        fragments{};
    std::array<uint64_t, pgas_x86_max_replay_fragments> lock_lines{};
    uint16_t lane_count{};
    uint16_t active_lanes{};
    uint16_t fragment_count{};
    uint16_t lock_count{};
    int status{};
};

pgas_x86_replay_plan
pgas_x86_plan_contiguous(const pgas_x86_runtime_config &config,
                         uint64_t address, uint8_t width);

pgas_x86_replay_plan
pgas_x86_plan_lanes(const pgas_x86_runtime_config &config,
                    const uint64_t *addresses, size_t lane_count,
                    uint8_t lane_width, uint64_t active_mask);

} // namespace bpftime::attach
