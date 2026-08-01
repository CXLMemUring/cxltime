// SPDX-License-Identifier: MIT
#include <catch2/catch_test_macros.hpp>

#include "pgas_x86_xstate.hpp"

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <vector>

using namespace bpftime::attach;

namespace {

pgas_x86_xstate_layout avx512_layout()
{
    pgas_x86_xstate_layout layout{};
    layout.enabled_mask = 0xe7;
    layout.area_size = 2688;
    layout.osxsave = true;
    layout.avx = true;
    layout.avx512 = true;
    layout.component[2] = { 576, 256, true };
    layout.component[5] = { 1088, 64, true };
    layout.component[6] = { 1152, 512, true };
    layout.component[7] = { 1664, 1024, true };
    return layout;
}

} // namespace

TEST_CASE("standard xsave image reconstructs zmm", "[pgas][x86][xstate]")
{
    const auto layout = avx512_layout();
    std::vector<std::byte> image(layout.area_size);
    for (unsigned i = 0; i != 16; ++i)
        image[160 + 16 * 3 + i] = std::byte(0x10 + i);
    for (unsigned i = 0; i != 16; ++i)
        image[576 + 16 * 3 + i] = std::byte(0x20 + i);
    for (unsigned i = 0; i != 32; ++i)
        image[1152 + 32 * 3 + i] = std::byte(0x30 + i);

    std::array<std::byte, 64> zmm{};
    REQUIRE(pgas_x86_read_vector(layout, image.data(), image.size(), 3,
                                 zmm.data(), zmm.size()) == 0);
    for (unsigned i = 0; i != 16; ++i)
        REQUIRE(zmm[i] == std::byte(0x10 + i));
    for (unsigned i = 0; i != 16; ++i)
        REQUIRE(zmm[16 + i] == std::byte(0x20 + i));
    for (unsigned i = 0; i != 32; ++i)
        REQUIRE(zmm[32 + i] == std::byte(0x30 + i));
}

TEST_CASE("component seven contains xmm through zmm views",
          "[pgas][x86][xstate]")
{
    const auto layout = avx512_layout();
    std::vector<std::byte> image(layout.area_size);
    const size_t zmm31_offset = layout.component[7].offset + 15 * 64;
    for (unsigned i = 0; i != 64; ++i)
        image[zmm31_offset + i] = std::byte(0x40 + i);

    std::array<std::byte, 16> xmm{};
    REQUIRE(pgas_x86_read_vector(layout, image.data(), image.size(), 31,
                                 xmm.data(), xmm.size()) == 0);
    for (unsigned i = 0; i != xmm.size(); ++i)
        REQUIRE(xmm[i] == std::byte(0x40 + i));

    std::array<std::byte, 64> zmm{};
    REQUIRE(pgas_x86_read_vector(layout, image.data(), image.size(), 31,
                                 zmm.data(), zmm.size()) == 0);
    for (unsigned i = 0; i != zmm.size(); ++i)
        REQUIRE(zmm[i] == std::byte(0x40 + i));
}

TEST_CASE("standard xsave image exposes opmask registers",
          "[pgas][x86][xstate]")
{
    const auto layout = avx512_layout();
    std::vector<std::byte> image(layout.area_size);
    constexpr uint64_t expected = UINT64_C(0x8877665544332211);
    const size_t offset = layout.component[5].offset + 6 * sizeof(expected);
    for (unsigned i = 0; i != sizeof(expected); ++i)
        image[offset + i] = std::byte(expected >> (8 * i));

    uint64_t actual{};
    REQUIRE(pgas_x86_read_opmask(layout, image.data(), image.size(), 6,
                                 actual) == 0);
    REQUIRE(actual == expected);
}

TEST_CASE("xstate extraction rejects unavailable or truncated state",
          "[pgas][x86][xstate][failure]")
{
    auto layout = avx512_layout();
    std::vector<std::byte> image(layout.area_size);
    std::array<std::byte, 64> output{};

    REQUIRE(pgas_x86_read_vector(layout, image.data(), image.size() - 1, 31,
                                 output.data(), output.size()) == -ERANGE);
    REQUIRE(pgas_x86_read_vector(layout, image.data(), image.size(), 32,
                                 output.data(), output.size()) == -EINVAL);
    REQUIRE(pgas_x86_read_vector(layout, image.data(), image.size(), 0,
                                 output.data(), 24) == -EINVAL);

    layout.component[6].enabled = false;
    REQUIRE(pgas_x86_read_vector(layout, image.data(), image.size(), 0,
                                 output.data(), output.size()) == -ENOTSUP);

    uint64_t mask{};
    REQUIRE(pgas_x86_read_opmask(layout, image.data(), image.size(), 8,
                                 mask) == -EINVAL);
}

TEST_CASE("live host exposes AVX-512 xstate", "[pgas][x86][xstate][live]")
{
    pgas_x86_xstate_layout layout{};
    REQUIRE(pgas_x86_detect_xstate(layout) == 0);
    REQUIRE(layout.osxsave);
    REQUIRE(layout.avx);
    REQUIRE(layout.avx512);
    REQUIRE((layout.enabled_mask & UINT64_C(0xe7)) == UINT64_C(0xe7));
    REQUIRE(layout.area_size >= 2688);
    REQUIRE(layout.component[2].enabled);
    REQUIRE(layout.component[5].enabled);
    REQUIRE(layout.component[6].enabled);
    REQUIRE(layout.component[7].enabled);
}
