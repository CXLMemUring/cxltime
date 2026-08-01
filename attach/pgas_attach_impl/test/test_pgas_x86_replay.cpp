// SPDX-License-Identifier: MIT
#include <catch2/catch_test_macros.hpp>

#include "pgas_x86_replay.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cerrno>
#include <cstring>
#include <cstdint>
#include <limits>
#include <thread>

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

namespace {

struct replay_transport_state {
    std::array<uint8_t, 256> remote{};
    uint8_t *shadow{};
    size_t watched_offset{};
    uint8_t watched_value{};
    int reads{};
    int writes{};
    int fail_write_call{};
    bool shadow_unchanged_during_reads{ true };
};

int replay_read(void *opaque, uint16_t, uint64_t address, void *destination,
                size_t size)
{
    auto &state = *static_cast<replay_transport_state *>(opaque);
    ++state.reads;
    if (state.shadow != nullptr &&
        state.shadow[state.watched_offset] != state.watched_value)
        state.shadow_unchanged_during_reads = false;
    std::memcpy(destination, state.remote.data() + address, size);
    return 0;
}

int replay_write(void *opaque, uint16_t, uint64_t address,
                 const void *source, size_t size)
{
    auto &state = *static_cast<replay_transport_state *>(opaque);
    ++state.writes;
    if (state.writes == state.fail_write_call)
        return -EIO;
    std::memcpy(state.remote.data() + address, source, size);
    return 0;
}

pgas_x86_runtime *make_replay_runtime(replay_transport_state &state,
                                      uint8_t *shadow, size_t size)
{
    pgas_x86_runtime_config config{};
    config.pgas_base = reinterpret_cast<uint64_t>(shadow);
    config.pgas_size = size;
    config.local_node_id = 0;
    config.num_nodes = 2;
    config.transport = { replay_read, replay_write, &state };
    return pgas_x86_runtime_create(config);
}

pgas_x86_replay_plan remote_plan(uint8_t *shadow, size_t size,
                                 size_t offset, uint8_t width)
{
    pgas_x86_runtime_config config{};
    config.pgas_base = reinterpret_cast<uint64_t>(shadow);
    config.pgas_size = size;
    config.local_node_id = 0;
    config.num_nodes = 2;
    return pgas_x86_plan_contiguous(
        config, reinterpret_cast<uint64_t>(shadow + offset), width);
}

} // namespace

TEST_CASE("replay prepare publishes shadow only after every read",
          "[pgas][x86][replay][transaction]")
{
    alignas(64) std::array<uint8_t, 512> shadow{};
    shadow.fill(0x55);
    replay_transport_state state;
    state.remote.fill(0xaa);
    state.shadow = shadow.data();
    state.watched_offset = 288;
    state.watched_value = 0x55;
    auto *runtime = make_replay_runtime(state, shadow.data(), shadow.size());
    REQUIRE(runtime != nullptr);
    const auto plan = remote_plan(shadow.data(), shadow.size(), 288, 64);
    REQUIRE(plan.fragment_count == 2);

    pgas_x86_replay_transaction transaction{};
    REQUIRE(pgas_x86_replay_prepare(runtime, transaction, plan,
                                    pgas_x86_access_class::read) == 0);
    REQUIRE(state.reads == 2);
    REQUIRE(state.shadow_unchanged_during_reads);
    REQUIRE(std::all_of(shadow.begin() + 288, shadow.begin() + 352,
                        [](uint8_t value) { return value == 0xaa; }));
    pgas_x86_replay_abort(transaction);
    pgas_x86_runtime_destroy(runtime);
}

TEST_CASE("write replay prepares without reading and commits final shadow",
          "[pgas][x86][replay][transaction]")
{
    alignas(64) std::array<uint8_t, 512> shadow{};
    replay_transport_state state;
    auto *runtime = make_replay_runtime(state, shadow.data(), shadow.size());
    REQUIRE(runtime != nullptr);
    const auto plan = remote_plan(shadow.data(), shadow.size(), 316, 8);

    pgas_x86_replay_transaction transaction{};
    REQUIRE(pgas_x86_replay_prepare(runtime, transaction, plan,
                                    pgas_x86_access_class::write) == 0);
    REQUIRE(state.reads == 0);
    for (size_t i = 0; i < 8; ++i)
        shadow[316 + i] = static_cast<uint8_t>(0xc0 + i);
    REQUIRE(pgas_x86_replay_commit(transaction) == 0);
    REQUIRE_FALSE(transaction.active);
    REQUIRE(state.writes == 2);
    REQUIRE(std::memcmp(state.remote.data() + 60, shadow.data() + 316, 8) ==
            0);
    pgas_x86_runtime_destroy(runtime);
}

TEST_CASE("failed commit remains failed until abort releases its line",
          "[pgas][x86][replay][transaction][failure]")
{
    alignas(64) std::array<uint8_t, 512> shadow{};
    replay_transport_state state;
    state.fail_write_call = 1;
    auto *runtime = make_replay_runtime(state, shadow.data(), shadow.size());
    REQUIRE(runtime != nullptr);
    const auto plan = remote_plan(shadow.data(), shadow.size(), 320, 8);

    pgas_x86_replay_transaction failed{};
    REQUIRE(pgas_x86_replay_prepare(runtime, failed, plan,
                                    pgas_x86_access_class::write) == 0);
    REQUIRE(pgas_x86_replay_commit(failed) == -EIO);
    REQUIRE(failed.active);
    REQUIRE(failed.failed);
    pgas_x86_replay_abort(failed);
    REQUIRE_FALSE(failed.active);

    state.fail_write_call = 0;
    pgas_x86_replay_transaction next{};
    REQUIRE(pgas_x86_replay_prepare(runtime, next, plan,
                                    pgas_x86_access_class::write) == 0);
    pgas_x86_replay_abort(next);
    pgas_x86_runtime_destroy(runtime);
}

TEST_CASE("same replay line excludes a second transaction",
          "[pgas][x86][replay][transaction][locking]")
{
    alignas(64) std::array<uint8_t, 512> shadow{};
    replay_transport_state state;
    auto *runtime = make_replay_runtime(state, shadow.data(), shadow.size());
    REQUIRE(runtime != nullptr);
    const auto plan = remote_plan(shadow.data(), shadow.size(), 320, 8);

    pgas_x86_replay_transaction first{};
    REQUIRE(pgas_x86_replay_prepare(runtime, first, plan,
                                    pgas_x86_access_class::write) == 0);
    std::atomic<bool> started{};
    std::atomic<bool> completed{};
    int second_result = -1;
    std::thread contender([&] {
        pgas_x86_replay_transaction second{};
        started.store(true, std::memory_order_release);
        second_result = pgas_x86_replay_prepare(
            runtime, second, plan, pgas_x86_access_class::write);
        completed.store(true, std::memory_order_release);
        if (second_result == 0)
            pgas_x86_replay_abort(second);
    });
    while (!started.load(std::memory_order_acquire))
        std::this_thread::yield();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    REQUIRE_FALSE(completed.load(std::memory_order_acquire));
    pgas_x86_replay_abort(first);
    contender.join();
    REQUIRE(second_result == 0);
    REQUIRE(completed.load(std::memory_order_acquire));
    pgas_x86_runtime_destroy(runtime);
}

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
