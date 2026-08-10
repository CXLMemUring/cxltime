// SPDX-License-Identifier: MIT
#include <catch2/catch_test_macros.hpp>

#include "pgas_x86_xstate.hpp"

#include <array>
#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

using namespace bpftime::attach;

namespace {

struct gum_test_runtime {
    gum_test_runtime() { gum_init_embedded(); }
    ~gum_test_runtime() { gum_deinit_embedded(); }
};

gum_test_runtime gum_runtime;

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

#if defined(__x86_64__)
extern "C" __attribute__((naked)) void pgas_x86_test_clobber_xstate()
{
    asm volatile("vpxord %zmm0, %zmm0, %zmm0\n\t"
                 "kxnorq %k1, %k1, %k1\n\t"
                 "xor %eax, %eax\n\t"
                 "xor %edx, %edx\n\t"
                 "mov $0x55, %r11d\n\t"
                 "ret\n\t");
}
#endif

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

TEST_CASE("xstate envelope emits xsave64 and xrstor64",
          "[pgas][x86][xstate][writer]")
{
    pgas_x86_xstate_layout layout{};
    REQUIRE(pgas_x86_detect_xstate(layout) == 0);
    const long system_page_size = sysconf(_SC_PAGESIZE);
    REQUIRE(system_page_size > 0);
    auto *code = static_cast<uint8_t *>(mmap(
        nullptr, static_cast<size_t>(system_page_size),
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    REQUIRE(code != MAP_FAILED);
    GumX86Writer writer;
    gum_x86_writer_init(&writer, code);
    pgas_x86_state_frame frame{};
    REQUIRE(pgas_x86_emit_state_save(&writer, layout, GUM_X86_R11, frame));
    REQUIRE(pgas_x86_emit_state_restore(&writer, layout, frame));
    gum_x86_writer_put_ret(&writer);
    REQUIRE(gum_x86_writer_flush(&writer));

    const auto end = code + gum_x86_writer_offset(&writer);
    const std::array<uint8_t, 4> xsave{ 0x49, 0x0f, 0xae, 0x23 };
    const std::array<uint8_t, 4> xrstor{ 0x49, 0x0f, 0xae, 0x2b };
    REQUIRE(std::search(code, end, xsave.begin(), xsave.end()) != end);
    REQUIRE(std::search(code, end, xrstor.begin(), xrstor.end()) !=
            end);
    gum_x86_writer_clear(&writer);
    REQUIRE(munmap(code, static_cast<size_t>(system_page_size)) == 0);
}

#if defined(__x86_64__)
TEST_CASE("live envelope preserves flags zmm and opmask across a clobber",
          "[pgas][x86][xstate][writer][live]")
{
    constexpr uint64_t expected_mask = UINT64_C(0x5a3c);
    constexpr uint64_t input_flags = UINT64_C(0x246);
    constexpr uint64_t arithmetic_flags = UINT64_C(0x8d5);
    alignas(64) std::array<uint8_t, 64> expected{};
    alignas(64) std::array<uint8_t, 64> actual{};
    for (size_t i = 0; i < expected.size(); ++i)
        expected[i] = static_cast<uint8_t>(0x80 + i);

    pgas_x86_xstate_layout layout{};
    REQUIRE(pgas_x86_detect_xstate(layout) == 0);
    const long system_page_size = sysconf(_SC_PAGESIZE);
    REQUIRE(system_page_size > 0);
    auto *code = static_cast<uint8_t *>(mmap(
        nullptr, static_cast<size_t>(system_page_size),
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    REQUIRE(code != MAP_FAILED);
    GumX86Writer writer;
    gum_x86_writer_init(&writer, code);
    pgas_x86_state_frame frame{};
    REQUIRE(pgas_x86_emit_state_save(&writer, layout, GUM_X86_R11, frame));
    REQUIRE(gum_x86_writer_put_mov_reg_u64(
        &writer, GUM_X86_RAX,
        reinterpret_cast<uint64_t>(&pgas_x86_test_clobber_xstate)));
    REQUIRE(gum_x86_writer_put_call_reg(&writer, GUM_X86_RAX));
    REQUIRE(pgas_x86_emit_state_restore(&writer, layout, frame));
    gum_x86_writer_put_ret(&writer);
    REQUIRE(gum_x86_writer_flush(&writer));

    uint64_t actual_mask{};
    uint64_t actual_flags{};
    const auto function = reinterpret_cast<void (*)()>(code);
    asm volatile("vmovdqu64 %[expected], %%zmm0\n\t"
                 "kmovq %[expected_mask], %%k1\n\t"
                 "push %[input_flags]\n\t"
                 "popfq\n\t"
                 "call *%[function]\n\t"
                 "pushfq\n\t"
                 "pop %[actual_flags]\n\t"
                 "vmovdqu64 %%zmm0, %[actual]\n\t"
                 "kmovq %%k1, %[actual_mask]\n\t"
                 : [actual] "=m"(actual),
                   [actual_mask] "=r"(actual_mask),
                   [actual_flags] "=r"(actual_flags)
                 : [expected] "m"(expected),
                   [expected_mask] "r"(expected_mask),
                   [input_flags] "r"(input_flags),
                   [function] "r"(function)
                 : "rax", "rdx", "r11", "zmm0", "k1", "memory", "cc");

    REQUIRE(actual == expected);
    REQUIRE(actual_mask == expected_mask);
    REQUIRE((actual_flags & arithmetic_flags) ==
            (input_flags & arithmetic_flags));
    gum_x86_writer_clear(&writer);
    REQUIRE(munmap(code, static_cast<size_t>(system_page_size)) == 0);
}
#endif
