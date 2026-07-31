// SPDX-License-Identifier: MIT
#include <catch2/catch_test_macros.hpp>

#include "pgas_stalker_mov.hpp"

#include <array>
#include <cstdint>
#include <utility>

using namespace bpftime::attach;

namespace {

using range_function = int (*)(uint64_t);

struct call_state {
    int result{};
    uint64_t r10{};
    uint64_t r11{};
    uint64_t r12{};
    uint64_t flags{};
    uint64_t red_zone{};
};

call_state call_preserving_state(range_function function, uint64_t address)
{
    constexpr uint64_t sentinel_r10 = 0x1010101010101010ULL;
    constexpr uint64_t sentinel_r11 = 0x1111111111111111ULL;
    constexpr uint64_t sentinel_r12 = 0x1212121212121212ULL;
    constexpr uint64_t input_flags = 0x246;
    constexpr uint64_t red_zone_sentinel = 0xfeedfacecafebeefULL;
    call_state state{};

    asm volatile(
        "mov %[function], %%r13\n\t"
        "mov %[address], %%rdi\n\t"
        "mov %[sentinel_r10], %%r10\n\t"
        "mov %[sentinel_r11], %%r11\n\t"
        "mov %[sentinel_r12], %%r12\n\t"
        "mov %[input_flags], %%rax\n\t"
        "mov %[red_zone_sentinel], %%rax\n\t"
        "mov %%rax, -16(%%rsp)\n\t"
        "mov %[input_flags], %%rax\n\t"
        "push %%rax\n\t"
        "popfq\n\t"
        "call *%%r13\n\t"
        "mov %%eax, %[result]\n\t"
        "pushfq\n\t"
        "pop %%rax\n\t"
        "mov %%rax, %[flags]\n\t"
        "mov %%r10, %[r10]\n\t"
        "mov %%r11, %[r11]\n\t"
        "mov %%r12, %[r12]\n\t"
        "mov -16(%%rsp), %%rax\n\t"
        "mov %%rax, %[red_zone]\n\t"
        : [result] "=m"(state.result), [flags] "=m"(state.flags),
          [r10] "=m"(state.r10), [r11] "=m"(state.r11),
          [r12] "=m"(state.r12), [red_zone] "=m"(state.red_zone)
        : [function] "r"(function), [address] "r"(address),
          [sentinel_r10] "r"(sentinel_r10),
          [sentinel_r11] "r"(sentinel_r11),
          [sentinel_r12] "r"(sentinel_r12),
          [input_flags] "r"(input_flags),
          [red_zone_sentinel] "r"(red_zone_sentinel)
        : "rax", "rdi", "r10", "r11", "r12", "r13", "memory", "cc");

    return state;
}

} // namespace

TEST_CASE("generated x86 range gate preserves 64-bit bounds and state",
          "[pgas][x86][jit]")
{
    constexpr uint64_t base = 0x4000000000ULL;
    constexpr uint64_t size = 4096;
    constexpr uint64_t arithmetic_flags_mask = 0x8d5;
    constexpr uint64_t expected_flags = 0x246;
    constexpr uint64_t sentinel_r10 = 0x1010101010101010ULL;
    constexpr uint64_t sentinel_r11 = 0x1111111111111111ULL;
    constexpr uint64_t sentinel_r12 = 0x1212121212121212ULL;
    constexpr uint64_t red_zone_sentinel = 0xfeedfacecafebeefULL;

    gum_init_embedded();
    auto *code = static_cast<uint8_t *>(gum_alloc_n_pages(1, GUM_PAGE_RWX));
    REQUIRE(code != nullptr);

    GumX86Writer writer;
    gum_x86_writer_init(&writer, code);
    static const char inside_label{};
    static const char outside_label{};
    static const char partial_label{};
    static const char overflow_label{};

    REQUIRE(pgas_x86_emit_range_gate(
        &writer, GUM_X86_RDI, GUM_X86_R10, GUM_X86_R11, GUM_X86_R12, 0, 8,
        base, size, &inside_label, &outside_label, &partial_label,
        &overflow_label));

    gum_x86_writer_put_label(&writer, &inside_label);
    REQUIRE(gum_x86_writer_put_mov_reg_u32(&writer, GUM_X86_EAX, 1));
    gum_x86_writer_put_ret(&writer);
    gum_x86_writer_put_label(&writer, &outside_label);
    REQUIRE(gum_x86_writer_put_mov_reg_u32(&writer, GUM_X86_EAX, 0));
    gum_x86_writer_put_ret(&writer);
    gum_x86_writer_put_label(&writer, &partial_label);
    REQUIRE(gum_x86_writer_put_mov_reg_u32(&writer, GUM_X86_EAX, 2));
    gum_x86_writer_put_ret(&writer);
    gum_x86_writer_put_label(&writer, &overflow_label);
    REQUIRE(gum_x86_writer_put_mov_reg_u32(&writer, GUM_X86_EAX, 3));
    gum_x86_writer_put_ret(&writer);
    REQUIRE(gum_x86_writer_flush(&writer));

    const auto function = reinterpret_cast<range_function>(code);
    const std::array<std::pair<uint64_t, int>, 7> cases{
        std::pair{ base - 8, 0 },
        std::pair{ base - 4, 2 },
        std::pair{ base, 1 },
        std::pair{ base + size - 8, 1 },
        std::pair{ base + size - 4, 2 },
        std::pair{ base + size, 0 },
        std::pair{ UINT64_MAX - 3, 3 },
    };

    for (const auto &[address, expected] : cases) {
        const auto state = call_preserving_state(function, address);
        REQUIRE(state.result == expected);
        REQUIRE(state.r10 == sentinel_r10);
        REQUIRE(state.r11 == sentinel_r11);
        REQUIRE(state.r12 == sentinel_r12);
        REQUIRE(state.red_zone == red_zone_sentinel);
        REQUIRE((state.flags & arithmetic_flags_mask) ==
                (expected_flags & arithmetic_flags_mask));
    }

    gum_x86_writer_clear(&writer);
    gum_free_pages(code);
    gum_deinit_embedded();
}
