// SPDX-License-Identifier: MIT
#include <catch2/catch_test_macros.hpp>

#include "pgas_x86_memory_access.hpp"

#include <cstdint>
#include <limits>

using namespace bpftime::attach;

TEST_CASE("high PGAS base is not truncated", "[pgas][x86][range]")
{
    REQUIRE(pgas_x86_classify_range(0x4000000000ULL, 8,
                                    0x4000000000ULL, 4096) ==
            pgas_x86_range_result::inside);
    REQUIRE(pgas_x86_classify_range(0, 8, 0x4000000000ULL, 4096) ==
            pgas_x86_range_result::outside);
}

TEST_CASE("half-open PGAS boundaries are classified", "[pgas][x86][range]")
{
    constexpr uint64_t base = 0x4000000000ULL;
    constexpr uint64_t size = 4096;

    REQUIRE(pgas_x86_classify_range(base - 8, 8, base, size) ==
            pgas_x86_range_result::outside);
    REQUIRE(pgas_x86_classify_range(base + size, 8, base, size) ==
            pgas_x86_range_result::outside);
    REQUIRE(pgas_x86_classify_range(base + size - 8, 8, base, size) ==
            pgas_x86_range_result::inside);
    REQUIRE(pgas_x86_classify_range(base - 4, 8, base, size) ==
            pgas_x86_range_result::partial);
    REQUIRE(pgas_x86_classify_range(base + size - 4, 8, base, size) ==
            pgas_x86_range_result::partial);
}

TEST_CASE("invalid or overflowing PGAS intervals are rejected",
          "[pgas][x86][range]")
{
    constexpr uint64_t max = std::numeric_limits<uint64_t>::max();

    REQUIRE(pgas_x86_classify_range(0x4000000000ULL, 0,
                                    0x4000000000ULL, 4096) ==
            pgas_x86_range_result::overflow);
    REQUIRE(pgas_x86_classify_range(0x4000000000ULL, 65,
                                    0x4000000000ULL, 4096) ==
            pgas_x86_range_result::overflow);
    REQUIRE(pgas_x86_classify_range(max - 3, 8, 0, max) ==
            pgas_x86_range_result::overflow);
    REQUIRE(pgas_x86_classify_range(0, 8, max - 3, 8) ==
            pgas_x86_range_result::overflow);
}

TEST_CASE("scalar access splits at a cache line", "[pgas][x86][segment]")
{
    const auto segments = pgas_x86_split_cachelines(0x400000003cULL, 8);

    REQUIRE(segments.count == 2);
    REQUIRE(segments.value[0].address == 0x400000003cULL);
    REQUIRE(segments.value[0].offset == 0);
    REQUIRE(segments.value[0].size == 4);
    REQUIRE(segments.value[1].address == 0x4000000040ULL);
    REQUIRE(segments.value[1].offset == 4);
    REQUIRE(segments.value[1].size == 4);
}

TEST_CASE("scalar widths retain exact segment sizes", "[pgas][x86][segment]")
{
    for (const uint8_t width : { uint8_t{ 1 }, uint8_t{ 2 }, uint8_t{ 4 },
                                 uint8_t{ 8 } }) {
        const auto segments =
            pgas_x86_split_cachelines(0x4000000020ULL, width);
        REQUIRE(segments.count == 1);
        REQUIRE(segments.value[0].address == 0x4000000020ULL);
        REQUIRE(segments.value[0].offset == 0);
        REQUIRE(segments.value[0].size == width);
    }
}

TEST_CASE("invalid segment widths return no segments", "[pgas][x86][segment]")
{
    REQUIRE(pgas_x86_split_cachelines(0x4000000000ULL, 0).count == 0);
    REQUIRE(pgas_x86_split_cachelines(0x4000000000ULL, 65).count == 0);
}
