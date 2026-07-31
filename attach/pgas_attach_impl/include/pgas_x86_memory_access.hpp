// SPDX-License-Identifier: MIT
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace bpftime::attach {

enum class pgas_x86_range_result { outside, inside, partial, overflow };

struct pgas_x86_segment {
    uint64_t address{};
    uint8_t offset{};
    uint8_t size{};
};

struct pgas_x86_segments {
    std::array<pgas_x86_segment, 2> value{};
    uint8_t count{};
};

pgas_x86_range_result pgas_x86_classify_range(uint64_t address,
                                               size_t width,
                                               uint64_t base,
                                               uint64_t region_size);

pgas_x86_segments pgas_x86_split_cachelines(uint64_t address, size_t width);

} // namespace bpftime::attach
