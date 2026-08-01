// SPDX-License-Identifier: MIT
#include <catch2/catch_test_macros.hpp>

#include "pgas_x86_replay.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <limits>

using namespace bpftime::attach;

namespace {

constexpr uint64_t base = UINT64_C(0x4000000000);

pgas_x86_runtime_config two_node_config()
{
    pgas_x86_runtime_config config{};
    config.pgas_base = base;
    config.pgas_size = 512;
    config.local_node_id = 0;
    config.num_nodes = 2;
    return config;
}

} // namespace

TEST_CASE("contiguous replay splits cache lines", "[pgas][x86][replay]")
{
    const auto config = two_node_config();
    const auto plan = pgas_x86_plan_contiguous(config, base + 256 + 32, 64);

    REQUIRE(plan.status == 0);
    REQUIRE(plan.lane_count == 1);
    REQUIRE(plan.active_lanes == 1);
    REQUIRE(plan.fragment_count == 2);
    REQUIRE(plan.fragments[0].address == base + 256 + 32);
    REQUIRE(plan.fragments[0].byte_offset == 0);
    REQUIRE(plan.fragments[0].size == 32);
    REQUIRE(plan.fragments[0].node == 1);
    REQUIRE(plan.fragments[0].remote);
    REQUIRE(plan.fragments[1].address == base + 256 + 64);
    REQUIRE(plan.fragments[1].byte_offset == 32);
    REQUIRE(plan.fragments[1].size == 32);
    REQUIRE(plan.lock_count == 2);
    REQUIRE(plan.lock_lines[0] == base + 256);
    REQUIRE(plan.lock_lines[1] == base + 256 + 64);
}

TEST_CASE("contiguous replay splits a node boundary",
          "[pgas][x86][replay]")
{
    const auto config = two_node_config();
    const auto plan = pgas_x86_plan_contiguous(config, base + 252, 8);

    REQUIRE(plan.status == 0);
    REQUIRE(plan.fragment_count == 2);
    REQUIRE(plan.fragments[0].address == base + 252);
    REQUIRE(plan.fragments[0].size == 4);
    REQUIRE(plan.fragments[0].node == 0);
    REQUIRE_FALSE(plan.fragments[0].remote);
    REQUIRE(plan.fragments[1].address == base + 256);
    REQUIRE(plan.fragments[1].size == 4);
    REQUIRE(plan.fragments[1].node == 1);
    REQUIRE(plan.fragments[1].remote);
}

TEST_CASE("masked lane planning sorts and deduplicates line locks",
          "[pgas][x86][replay][lanes]")
{
    const auto config = two_node_config();
    const std::array<uint64_t, 8> addresses{
        base + 256, base + 260, base + 316, base + 320,
        base + 260, base + 384, base + 448, base + 508
    };
    const auto plan = pgas_x86_plan_lanes(
        config, addresses.data(), addresses.size(), 4, 0b00111101);

    REQUIRE(plan.status == 0);
    REQUIRE(plan.lane_count == addresses.size());
    REQUIRE(plan.active_lanes == 5);
    REQUIRE(plan.fragment_count == 5);
    REQUIRE(plan.lock_count == 3);
    const auto lock_end = plan.lock_lines.begin() + plan.lock_count;
    REQUIRE(std::is_sorted(plan.lock_lines.begin(), lock_end));
    REQUIRE(std::adjacent_find(plan.lock_lines.begin(), lock_end) == lock_end);
    REQUIRE(plan.lock_lines[0] == base + 256);
    REQUIRE(plan.lock_lines[1] == base + 256 + 64);
    REQUIRE(plan.lock_lines[2] == base + 256 + 128);
}

TEST_CASE("inactive lanes do not participate in address validation",
          "[pgas][x86][replay][lanes]")
{
    const auto config = two_node_config();
    const std::array<uint64_t, 4> addresses{
        base + 256, std::numeric_limits<uint64_t>::max(), base + 320,
        std::numeric_limits<uint64_t>::max()
    };
    const auto plan = pgas_x86_plan_lanes(
        config, addresses.data(), addresses.size(), 4, 0b0101);

    REQUIRE(plan.status == 0);
    REQUIRE(plan.active_lanes == 2);
    REQUIRE(plan.fragment_count == 2);
    REQUIRE_FALSE(plan.lanes[1].active);
    REQUIRE_FALSE(plan.lanes[3].active);
}

TEST_CASE("empty lane mask creates an empty successful plan",
          "[pgas][x86][replay][lanes]")
{
    const auto config = two_node_config();
    const std::array<uint64_t, 2> addresses{
        std::numeric_limits<uint64_t>::max(),
        std::numeric_limits<uint64_t>::max()
    };
    const auto plan = pgas_x86_plan_lanes(
        config, addresses.data(), addresses.size(), 8, 0);

    REQUIRE(plan.status == 0);
    REQUIRE(plan.lane_count == 2);
    REQUIRE(plan.active_lanes == 0);
    REQUIRE(plan.fragment_count == 0);
    REQUIRE(plan.lock_count == 0);
}

TEST_CASE("replay planning rejects overflow and partial PGAS operands",
          "[pgas][x86][replay][failure]")
{
    const auto config = two_node_config();
    REQUIRE(pgas_x86_plan_contiguous(
                config, std::numeric_limits<uint64_t>::max() - 1, 4)
                .status == -EOVERFLOW);
    REQUIRE(pgas_x86_plan_contiguous(config, base + 510, 4).status ==
            -ERANGE);
    REQUIRE(pgas_x86_plan_contiguous(config, base - 2, 4).status ==
            -ERANGE);
}

TEST_CASE("replay planning rejects invalid dimensions",
          "[pgas][x86][replay][failure]")
{
    const auto config = two_node_config();
    std::array<uint64_t, 65> addresses{};
    addresses.fill(base + 256);

    REQUIRE(pgas_x86_plan_contiguous(config, base + 256, 0).status ==
            -EINVAL);
    REQUIRE(pgas_x86_plan_contiguous(config, base + 256, 65).status ==
            -EINVAL);
    REQUIRE(pgas_x86_plan_lanes(config, nullptr, 1, 4, 1).status ==
            -EINVAL);
    REQUIRE(pgas_x86_plan_lanes(config, addresses.data(), addresses.size(), 4,
                                UINT64_MAX)
                .status == -E2BIG);
}
