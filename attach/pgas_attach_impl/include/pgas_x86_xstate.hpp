// SPDX-License-Identifier: MIT
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace bpftime::attach {

struct pgas_x86_xstate_component {
    uint32_t offset{};
    uint32_t size{};
    bool enabled{};
};

struct pgas_x86_xstate_layout {
    uint64_t enabled_mask{};
    uint32_t area_size{};
    bool osxsave{};
    bool avx{};
    bool avx512{};
    std::array<pgas_x86_xstate_component, 64> component{};
};

int pgas_x86_detect_xstate(pgas_x86_xstate_layout &out);

int pgas_x86_read_vector(const pgas_x86_xstate_layout &layout,
                         const std::byte *image, size_t image_size,
                         unsigned register_index,
                         std::byte *destination, size_t destination_size);

int pgas_x86_read_opmask(const pgas_x86_xstate_layout &layout,
                         const std::byte *image, size_t image_size,
                         unsigned register_index, uint64_t &value);

} // namespace bpftime::attach
