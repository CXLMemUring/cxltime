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

} // namespace bpftime::attach
