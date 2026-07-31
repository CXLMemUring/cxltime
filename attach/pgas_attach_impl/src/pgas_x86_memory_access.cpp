// SPDX-License-Identifier: MIT
#include "pgas_x86_memory_access.hpp"

#include <algorithm>

namespace bpftime::attach {

namespace {

constexpr size_t cache_line_size = 64;
constexpr size_t maximum_access_width = 64;

bool checked_end(uint64_t start, size_t width, uint64_t &end)
{
    return !__builtin_add_overflow(start, static_cast<uint64_t>(width), &end);
}

} // namespace

pgas_x86_range_result pgas_x86_classify_range(uint64_t address,
                                               size_t width,
                                               uint64_t base,
                                               uint64_t region_size)
{
    if (width == 0 || width > maximum_access_width)
        return pgas_x86_range_result::overflow;

    uint64_t access_end{};
    uint64_t region_end{};
    if (!checked_end(address, width, access_end) ||
        __builtin_add_overflow(base, region_size, &region_end))
        return pgas_x86_range_result::overflow;

    if (region_size == 0 || access_end <= base || address >= region_end)
        return pgas_x86_range_result::outside;

    if (address < base || access_end > region_end)
        return pgas_x86_range_result::partial;

    return pgas_x86_range_result::inside;
}

pgas_x86_segments pgas_x86_split_cachelines(uint64_t address, size_t width)
{
    pgas_x86_segments result{};
    uint64_t access_end{};
    if (width == 0 || width > maximum_access_width ||
        !checked_end(address, width, access_end))
        return result;

    const size_t line_offset = address % cache_line_size;
    const size_t first_size =
        std::min(width, cache_line_size - line_offset);

    result.value[0] = { address, 0, static_cast<uint8_t>(first_size) };
    result.count = 1;

    const size_t second_size = width - first_size;
    if (second_size != 0) {
        result.value[1] = { address + first_size,
                            static_cast<uint8_t>(first_size),
                            static_cast<uint8_t>(second_size) };
        result.count = 2;
    }

    return result;
}

} // namespace bpftime::attach
