// SPDX-License-Identifier: MIT
#include "pgas_x86_xstate.hpp"

#include <cerrno>
#include <cstring>
#include <limits>

#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#endif

namespace bpftime::attach {

namespace {

bool range_available(size_t offset, size_t size, size_t limit)
{
    return offset <= limit && size <= limit - offset;
}

constexpr uint32_t align_up(uint32_t value, uint32_t alignment)
{
    return (value + alignment - 1) & ~(alignment - 1);
}

#if defined(__x86_64__)
bool encode_xsave_memory_operand(GumX86Reg pointer_register, bool restore,
                                 std::array<guint8, 5> &bytes,
                                 guint &size)
{
    unsigned code{};
    bool extension{};
    switch (pointer_register) {
    case GUM_X86_RAX: code = 0; break;
    case GUM_X86_RCX: code = 1; break;
    case GUM_X86_RDX: code = 2; break;
    case GUM_X86_RBX: code = 3; break;
    case GUM_X86_RSI: code = 6; break;
    case GUM_X86_RDI: code = 7; break;
    case GUM_X86_R8: code = 0; extension = true; break;
    case GUM_X86_R9: code = 1; extension = true; break;
    case GUM_X86_R10: code = 2; extension = true; break;
    case GUM_X86_R11: code = 3; extension = true; break;
    case GUM_X86_R12: code = 4; extension = true; break;
    case GUM_X86_R14: code = 6; extension = true; break;
    case GUM_X86_R15: code = 7; extension = true; break;
    default: return false;
    }

    bytes[0] = static_cast<guint8>(0x48 | (extension ? 1 : 0));
    bytes[1] = 0x0f;
    bytes[2] = 0xae;
    bytes[3] = static_cast<guint8>((restore ? 0x28 : 0x20) | code);
    size = 4;
    if (code == 4) {
        bytes[4] = 0x24;
        size = 5;
    }
    return true;
}
#endif

int copy_image_range(const pgas_x86_xstate_layout &layout,
                     const std::byte *image, size_t image_size,
                     size_t offset, size_t size, std::byte *destination)
{
    if (!range_available(offset, size, layout.area_size) ||
        !range_available(offset, size, image_size))
        return -ERANGE;
    std::memcpy(destination, image + offset, size);
    return 0;
}

int require_component(const pgas_x86_xstate_layout &layout, unsigned index,
                      size_t relative_offset, size_t size,
                      const std::byte *image, size_t image_size,
                      std::byte *destination)
{
    if (index >= layout.component.size() ||
        !layout.component[index].enabled)
        return -ENOTSUP;
    const auto &component = layout.component[index];
    if (!range_available(relative_offset, size, component.size))
        return -ERANGE;
    if (component.offset > std::numeric_limits<size_t>::max() - relative_offset)
        return -ERANGE;
    return copy_image_range(layout, image, image_size,
                            static_cast<size_t>(component.offset) +
                                relative_offset,
                            size, destination);
}

#if defined(__x86_64__) || defined(__i386__)
uint64_t read_xcr0()
{
    uint32_t low{};
    uint32_t high{};
    __asm__ volatile("xgetbv" : "=a"(low), "=d"(high) : "c"(0));
    return (static_cast<uint64_t>(high) << 32) | low;
}
#endif

} // namespace

int pgas_x86_detect_xstate(pgas_x86_xstate_layout &out)
{
    out = {};
#if !defined(__x86_64__) && !defined(__i386__)
    return -ENOTSUP;
#else
    if (__get_cpuid_max(0, nullptr) < 0x0d)
        return -ENOTSUP;

    unsigned eax{};
    unsigned ebx{};
    unsigned ecx{};
    unsigned edx{};
    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx))
        return -ENOTSUP;

    constexpr unsigned cpuid_xsave = 1U << 26;
    constexpr unsigned cpuid_osxsave = 1U << 27;
    constexpr unsigned cpuid_avx = 1U << 28;
    if ((ecx & cpuid_xsave) == 0 || (ecx & cpuid_osxsave) == 0)
        return -ENOTSUP;

    out.osxsave = true;
    out.enabled_mask = read_xcr0();

    unsigned leaf0_eax{};
    unsigned leaf0_ebx{};
    unsigned leaf0_ecx{};
    unsigned leaf0_edx{};
    __cpuid_count(0x0d, 0, leaf0_eax, leaf0_ebx, leaf0_ecx, leaf0_edx);
    out.area_size = leaf0_ebx;
    if (out.area_size < 512)
        return -ENOTSUP;

    for (unsigned index = 2; index < out.component.size(); ++index) {
        if ((out.enabled_mask & (UINT64_C(1) << index)) == 0)
            continue;
        unsigned component_size{};
        unsigned component_offset{};
        unsigned component_ecx{};
        unsigned component_edx{};
        __cpuid_count(0x0d, index, component_size, component_offset,
                      component_ecx, component_edx);
        if (component_size == 0)
            continue;
        if (component_offset > out.area_size ||
            component_size > out.area_size - component_offset)
            return -ERANGE;
        out.component[index] = {
            static_cast<uint32_t>(component_offset),
            static_cast<uint32_t>(component_size), true
        };
    }

    out.avx = (ecx & cpuid_avx) != 0 &&
              (out.enabled_mask & UINT64_C(0x6)) == UINT64_C(0x6) &&
              out.component[2].enabled;

    bool cpu_avx512{};
    if (__get_cpuid_max(0, nullptr) >= 7) {
        unsigned leaf7_eax{};
        unsigned leaf7_ebx{};
        unsigned leaf7_ecx{};
        unsigned leaf7_edx{};
        __cpuid_count(7, 0, leaf7_eax, leaf7_ebx, leaf7_ecx, leaf7_edx);
        cpu_avx512 = (leaf7_ebx & (1U << 16)) != 0;
    }
    out.avx512 = out.avx && cpu_avx512 &&
                 (out.enabled_mask & UINT64_C(0xe0)) == UINT64_C(0xe0) &&
                 out.component[5].enabled && out.component[6].enabled &&
                 out.component[7].enabled;
    return 0;
#endif
}

int pgas_x86_read_vector(const pgas_x86_xstate_layout &layout,
                         const std::byte *image, size_t image_size,
                         unsigned register_index,
                         std::byte *destination, size_t destination_size)
{
    if (image == nullptr || destination == nullptr || register_index >= 32 ||
        (destination_size != 16 && destination_size != 32 &&
         destination_size != 64))
        return -EINVAL;

    if (register_index >= 16) {
        return require_component(layout, 7,
                                 static_cast<size_t>(register_index - 16) * 64,
                                 destination_size, image, image_size,
                                 destination);
    }

    const size_t legacy_offset = 160 + register_index * 16;
    int result = copy_image_range(layout, image, image_size, legacy_offset, 16,
                                  destination);
    if (result != 0 || destination_size == 16)
        return result;

    result = require_component(layout, 2, register_index * 16, 16, image,
                               image_size, destination + 16);
    if (result != 0 || destination_size == 32)
        return result;

    return require_component(layout, 6, register_index * 32, 32, image,
                             image_size, destination + 32);
}

int pgas_x86_read_opmask(const pgas_x86_xstate_layout &layout,
                         const std::byte *image, size_t image_size,
                         unsigned register_index, uint64_t &value)
{
    if (image == nullptr || register_index >= 8)
        return -EINVAL;
    std::array<std::byte, sizeof(uint64_t)> bytes{};
    const int result = require_component(
        layout, 5, register_index * sizeof(uint64_t), sizeof(uint64_t), image,
        image_size, bytes.data());
    if (result != 0)
        return result;
    std::memcpy(&value, bytes.data(), sizeof(value));
    return 0;
}

bool pgas_x86_emit_state_save(GumX86Writer *writer,
                              const pgas_x86_xstate_layout &layout,
                              GumX86Reg pointer_register,
                              pgas_x86_state_frame &frame)
{
#if !defined(__x86_64__)
    (void)writer;
    (void)layout;
    (void)pointer_register;
    frame = {};
    return false;
#else
    frame = {};
    std::array<guint8, 5> xsave_bytes{};
    guint xsave_size{};
    if (writer == nullptr ||
        !encode_xsave_memory_operand(pointer_register, false, xsave_bytes,
                                     xsave_size) ||
        !layout.osxsave || layout.area_size < 576 ||
        (layout.enabled_mask & UINT64_C(0x3)) != UINT64_C(0x3))
        return false;

    constexpr uint32_t red_zone_size = 128;
    constexpr uint32_t alignment_slack = 64;
    const uint32_t slots = align_up(layout.area_size + alignment_slack, 8);
    if (slots > std::numeric_limits<uint32_t>::max() -
                    red_zone_size - 4 * sizeof(uint64_t))
        return false;
    frame.stack_bytes = align_up(
        red_zone_size + slots + 4 * sizeof(uint64_t), 16);
    frame.xsave_offset = alignment_slack - 1;
    frame.saved_rax_offset = slots;
    frame.saved_rdx_offset = slots + sizeof(uint64_t);
    frame.saved_pointer_offset = slots + 2 * sizeof(uint64_t);
    frame.saved_flags_offset = slots + 3 * sizeof(uint64_t);
    frame.pointer_register = pointer_register;

    if (!gum_x86_writer_put_lea_reg_reg_offset(
            writer, GUM_X86_RSP, GUM_X86_RSP,
            -static_cast<gssize>(frame.stack_bytes)) ||
        !gum_x86_writer_put_mov_reg_offset_ptr_reg(
            writer, GUM_X86_RSP, frame.saved_rax_offset, GUM_X86_RAX) ||
        !gum_x86_writer_put_mov_reg_offset_ptr_reg(
            writer, GUM_X86_RSP, frame.saved_rdx_offset, GUM_X86_RDX) ||
        !gum_x86_writer_put_mov_reg_offset_ptr_reg(
            writer, GUM_X86_RSP, frame.saved_pointer_offset,
            pointer_register))
        return false;

    gum_x86_writer_put_pushfx(writer);
    const bool pop_flags =
        gum_x86_writer_put_pop_reg(writer, pointer_register);
    const bool store_flags = gum_x86_writer_put_mov_reg_offset_ptr_reg(
        writer, GUM_X86_RSP, frame.saved_flags_offset, pointer_register);
    const bool pointer_copy = gum_x86_writer_put_mov_reg_reg(
        writer, pointer_register, GUM_X86_RSP);
    const bool pointer_bias = gum_x86_writer_put_add_reg_imm(
        writer, pointer_register, frame.xsave_offset);
    const bool pointer_align = gum_x86_writer_put_and_reg_u32(
        writer, pointer_register, UINT32_C(0xffffffc0));
    const bool zero_rax =
        gum_x86_writer_put_mov_reg_u32(writer, GUM_X86_EAX, 0);
    if (!pop_flags || !store_flags || !pointer_copy || !pointer_bias ||
        !pointer_align || !zero_rax)
        return false;

    // XRSTOR requires every reserved byte in the XSAVE header to be zero.
    for (gssize offset = 512; offset != 576; offset += sizeof(uint64_t)) {
        if (!gum_x86_writer_put_mov_reg_offset_ptr_reg(
                writer, pointer_register, offset, GUM_X86_RAX))
            return false;
    }

    if (!gum_x86_writer_put_mov_reg_u32(
            writer, GUM_X86_EAX,
            static_cast<uint32_t>(layout.enabled_mask)) ||
        !gum_x86_writer_put_mov_reg_u32(
            writer, GUM_X86_EDX,
            static_cast<uint32_t>(layout.enabled_mask >> 32)))
        return false;
    gum_x86_writer_put_bytes(writer, xsave_bytes.data(), xsave_size);

    return gum_x86_writer_put_mov_reg_reg_offset_ptr(
               writer, GUM_X86_RAX, GUM_X86_RSP,
               frame.saved_rax_offset) &&
           gum_x86_writer_put_mov_reg_reg_offset_ptr(
               writer, GUM_X86_RDX, GUM_X86_RSP,
               frame.saved_rdx_offset);
#endif
}

bool pgas_x86_emit_state_restore(GumX86Writer *writer,
                                 const pgas_x86_xstate_layout &layout,
                                 const pgas_x86_state_frame &frame)
{
#if !defined(__x86_64__)
    (void)writer;
    (void)layout;
    (void)frame;
    return false;
#else
    std::array<guint8, 5> xrstor_bytes{};
    guint xrstor_size{};
    if (writer == nullptr ||
        !encode_xsave_memory_operand(frame.pointer_register, true,
                                     xrstor_bytes, xrstor_size) ||
        frame.stack_bytes == 0 || !layout.osxsave ||
        layout.area_size < 576)
        return false;
    if (!gum_x86_writer_put_mov_reg_reg(
            writer, frame.pointer_register, GUM_X86_RSP) ||
        !gum_x86_writer_put_add_reg_imm(
            writer, frame.pointer_register, frame.xsave_offset) ||
        !gum_x86_writer_put_and_reg_u32(
            writer, frame.pointer_register, UINT32_C(0xffffffc0)) ||
        !gum_x86_writer_put_mov_reg_u32(
            writer, GUM_X86_EAX,
            static_cast<uint32_t>(layout.enabled_mask)) ||
        !gum_x86_writer_put_mov_reg_u32(
            writer, GUM_X86_EDX,
            static_cast<uint32_t>(layout.enabled_mask >> 32)))
        return false;
    gum_x86_writer_put_bytes(writer, xrstor_bytes.data(), xrstor_size);

    if (!gum_x86_writer_put_mov_reg_reg_offset_ptr(
            writer, GUM_X86_RAX, GUM_X86_RSP,
            frame.saved_rax_offset) ||
        !gum_x86_writer_put_mov_reg_reg_offset_ptr(
            writer, GUM_X86_RDX, GUM_X86_RSP,
            frame.saved_rdx_offset) ||
        !gum_x86_writer_put_mov_reg_reg_offset_ptr(
            writer, frame.pointer_register, GUM_X86_RSP,
            frame.saved_flags_offset) ||
        !gum_x86_writer_put_push_reg(writer, frame.pointer_register))
        return false;
    gum_x86_writer_put_popfx(writer);
    if (!gum_x86_writer_put_mov_reg_reg_offset_ptr(
            writer, frame.pointer_register, GUM_X86_RSP,
            frame.saved_pointer_offset))
        return false;
    return gum_x86_writer_put_lea_reg_reg_offset(
        writer, GUM_X86_RSP, GUM_X86_RSP, frame.stack_bytes);
#endif
}

} // namespace bpftime::attach
