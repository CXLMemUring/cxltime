// SPDX-License-Identifier: MIT
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include <frida-gum.h>

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

struct pgas_x86_state_frame {
    uint32_t stack_bytes{};
    uint32_t xsave_offset{};
    uint32_t saved_rax_offset{};
    uint32_t saved_rdx_offset{};
    uint32_t saved_pointer_offset{};
    uint32_t saved_flags_offset{};
    GumX86Reg pointer_register{ GUM_X86_NONE };
};

int pgas_x86_detect_xstate(pgas_x86_xstate_layout &out);

int pgas_x86_read_vector(const pgas_x86_xstate_layout &layout,
                         const std::byte *image, size_t image_size,
                         unsigned register_index,
                         std::byte *destination, size_t destination_size);

int pgas_x86_read_opmask(const pgas_x86_xstate_layout &layout,
                         const std::byte *image, size_t image_size,
                         unsigned register_index, uint64_t &value);

bool pgas_x86_emit_state_save(GumX86Writer *writer,
                              const pgas_x86_xstate_layout &layout,
                              GumX86Reg pointer_register,
                              pgas_x86_state_frame &frame);
bool pgas_x86_emit_state_restore(GumX86Writer *writer,
                                 const pgas_x86_xstate_layout &layout,
                                 const pgas_x86_state_frame &frame);

} // namespace bpftime::attach
