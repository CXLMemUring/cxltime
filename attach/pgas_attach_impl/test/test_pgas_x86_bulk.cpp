// SPDX-License-Identifier: MIT
#include <catch2/catch_test_macros.hpp>

#include "pgas_x86_bulk.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <cstdint>
#include <thread>
#include <vector>

using namespace bpftime::attach;

namespace {

constexpr uint64_t base = UINT64_C(0x100000);
constexpr uint64_t node_size = UINT64_C(0x20000);

pgas_x86_runtime_config config(unsigned nodes = 2)
{
    pgas_x86_runtime_config value{};
    value.pgas_base = base;
    value.pgas_size = node_size * nodes;
    value.local_node_id = 0;
    value.num_nodes = static_cast<uint16_t>(nodes);
    return value;
}

std::vector<pgas_x86_bulk_chunk>
collect(const pgas_x86_runtime_config &runtime_config,
        const pgas_x86_bulk_plan &plan)
{
    std::vector<pgas_x86_bulk_chunk> chunks;
    uint64_t completed = 0;
    pgas_x86_bulk_chunk chunk{};
    while (pgas_x86_bulk_next(runtime_config, plan, completed, chunk)) {
        REQUIRE(chunk.size > 0);
        REQUIRE(chunk.size <= 64 * 1024);
        chunks.push_back(chunk);
        completed += chunk.size;
    }
    REQUIRE(completed == plan.total_size);
    return chunks;
}

} // namespace

namespace {

struct bulk_transport_state {
    std::array<std::vector<uint8_t>, 3> nodes;
    int fail_read{};
    int fail_write{};
    std::atomic<int> active_writes{};
    std::atomic<int> maximum_active_writes{};
    bool delay_writes{};

    bulk_transport_state()
    {
        for (auto &node : nodes)
            node.resize(node_size);
    }
};

int bulk_read(void *opaque, uint16_t node, uint64_t offset,
              void *destination, size_t size)
{
    auto &state = *static_cast<bulk_transport_state *>(opaque);
    if (state.fail_read != 0)
        return state.fail_read;
    if (node >= state.nodes.size() || offset + size > state.nodes[node].size())
        return -ERANGE;
    std::memcpy(destination, state.nodes[node].data() + offset, size);
    return 0;
}

int bulk_write(void *opaque, uint16_t node, uint64_t offset,
               const void *source, size_t size)
{
    auto &state = *static_cast<bulk_transport_state *>(opaque);
    if (state.fail_write != 0)
        return state.fail_write;
    const int active = state.active_writes.fetch_add(1) + 1;
    int maximum = state.maximum_active_writes.load();
    while (active > maximum &&
           !state.maximum_active_writes.compare_exchange_weak(maximum,
                                                               active)) {
    }
    if (state.delay_writes)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    if (node >= state.nodes.size() || offset + size > state.nodes[node].size()) {
        state.active_writes.fetch_sub(1);
        return -ERANGE;
    }
    std::memcpy(state.nodes[node].data() + offset, source, size);
    state.active_writes.fetch_sub(1);
    return 0;
}

pgas_x86_runtime *make_bulk_runtime(std::vector<uint8_t> &shadow,
                                    bulk_transport_state &transport)
{
    pgas_x86_runtime_config runtime_config{};
    runtime_config.pgas_base = reinterpret_cast<uint64_t>(shadow.data());
    runtime_config.pgas_size = shadow.size();
    runtime_config.local_node_id = 0;
    runtime_config.num_nodes = 3;
    runtime_config.transport = { bulk_read, bulk_write, &transport };
    return pgas_x86_runtime_create(runtime_config);
}

void fill_pattern(uint8_t *destination, size_t size, uint8_t seed)
{
    for (size_t index = 0; index < size; ++index)
        destination[index] = static_cast<uint8_t>(seed + index * 17);
}

} // namespace

TEST_CASE("bulk planner classifies local and remote endpoints independently",
          "[pgas][x86][bulk][plan]")
{
    const auto cfg = config();
    const uint64_t remote = base + node_size + 0x100;
    const uint64_t local = UINT64_C(0x80000000);

    auto plan = pgas_x86_plan_bulk(pgas_x86_bulk_kind::copy, remote, local,
                                   128);
    REQUIRE(plan.status == 0);
    auto chunks = collect(cfg, plan);
    REQUIRE(chunks.size() == 1);
    CHECK(chunks[0].destination_remote);
    CHECK_FALSE(chunks[0].source_remote);
    CHECK(chunks[0].destination_node == 1);
    CHECK(chunks[0].source_node == 0);

    plan = pgas_x86_plan_bulk(pgas_x86_bulk_kind::copy, local, remote, 128);
    chunks = collect(cfg, plan);
    REQUIRE(chunks.size() == 1);
    CHECK_FALSE(chunks[0].destination_remote);
    CHECK(chunks[0].source_remote);
    CHECK(chunks[0].destination_node == 0);
    CHECK(chunks[0].source_node == 1);
}

TEST_CASE("bulk planner retains same and distinct remote node identities",
          "[pgas][x86][bulk][plan]")
{
    const auto cfg = config(3);
    const uint64_t node1 = base + node_size + 0x100;
    const uint64_t node2 = base + 2 * node_size + 0x200;

    auto chunks = collect(
        cfg, pgas_x86_plan_bulk(pgas_x86_bulk_kind::copy, node1 + 0x400,
                                node1, 256));
    REQUIRE(chunks.size() == 1);
    CHECK(chunks[0].destination_remote);
    CHECK(chunks[0].source_remote);
    CHECK(chunks[0].destination_node == 1);
    CHECK(chunks[0].source_node == 1);

    chunks = collect(
        cfg, pgas_x86_plan_bulk(pgas_x86_bulk_kind::copy, node2, node1, 256));
    REQUIRE(chunks.size() == 1);
    CHECK(chunks[0].destination_node == 2);
    CHECK(chunks[0].source_node == 1);
}

TEST_CASE("bulk move chooses the architectural overlap direction",
          "[pgas][x86][bulk][plan]")
{
    const auto cfg = config();
    const uint64_t remote = base + node_size + 0x1000;

    auto forward = pgas_x86_plan_bulk(pgas_x86_bulk_kind::move, remote,
                                      remote + 0x80, 256);
    CHECK(forward.direction == pgas_x86_copy_direction::forward);
    auto forward_chunks = collect(cfg, forward);
    REQUIRE(forward_chunks.size() == 1);
    CHECK(forward_chunks[0].destination == remote);
    CHECK(forward_chunks[0].source == remote + 0x80);

    auto backward = pgas_x86_plan_bulk(pgas_x86_bulk_kind::move,
                                       remote + 0x80, remote, 256);
    CHECK(backward.direction == pgas_x86_copy_direction::backward);
    auto backward_chunks = collect(cfg, backward);
    REQUIRE(backward_chunks.size() == 1);
    CHECK(backward_chunks[0].destination == remote + 0x80);
    CHECK(backward_chunks[0].source == remote);
}

TEST_CASE("bulk chunks stop at each endpoint node boundary",
          "[pgas][x86][bulk][plan]")
{
    const auto cfg = config();
    const uint64_t boundary = base + node_size;
    auto chunks = collect(
        cfg, pgas_x86_plan_bulk(pgas_x86_bulk_kind::copy, boundary - 32,
                                UINT64_C(0x80000000), 128));

    REQUIRE(chunks.size() == 2);
    CHECK(chunks[0].size == 32);
    CHECK_FALSE(chunks[0].destination_remote);
    CHECK(chunks[0].destination_node == 0);
    CHECK(chunks[1].size == 96);
    CHECK(chunks[1].destination_remote);
    CHECK(chunks[1].destination_node == 1);
}

TEST_CASE("bulk chunks are bounded to sixty-four KiB",
          "[pgas][x86][bulk][plan]")
{
    const auto cfg = config(3);
    constexpr uint64_t size = 2 * 64 * 1024 + 17;
    auto chunks = collect(
        cfg, pgas_x86_plan_bulk(pgas_x86_bulk_kind::set,
                                base + node_size + 0x100, 0, size));

    REQUIRE(chunks.size() >= 3);
    uint64_t total = 0;
    for (const auto &chunk : chunks)
        total += chunk.size;
    CHECK(total == size);
}

TEST_CASE("bulk execution preserves every local and remote copy combination",
          "[pgas][x86][bulk][execute]")
{
    std::vector<uint8_t> shadow(3 * node_size, 0x55);
    bulk_transport_state transport;
    auto *runtime = make_bulk_runtime(shadow, transport);
    REQUIRE(runtime != nullptr);
    auto *remote1 = shadow.data() + node_size;
    auto *remote2 = shadow.data() + 2 * node_size;
    std::array<uint8_t, 256> local_source{};
    std::array<uint8_t, 256> local_destination{};
    fill_pattern(local_source.data(), local_source.size(), 3);

    REQUIRE(pgas_x86_bulk_copy(runtime, remote1 + 128, local_source.data(),
                               local_source.size()) == 0);
    CHECK(std::memcmp(remote1 + 128, local_source.data(),
                      local_source.size()) == 0);
    CHECK(std::memcmp(transport.nodes[1].data() + 128, local_source.data(),
                      local_source.size()) == 0);

    fill_pattern(transport.nodes[1].data() + 1024,
                 local_destination.size(), 29);
    REQUIRE(pgas_x86_bulk_copy(runtime, local_destination.data(),
                               remote1 + 1024,
                               local_destination.size()) == 0);
    CHECK(std::memcmp(local_destination.data(),
                      transport.nodes[1].data() + 1024,
                      local_destination.size()) == 0);
    CHECK(std::memcmp(remote1 + 1024, local_destination.data(),
                      local_destination.size()) == 0);

    fill_pattern(transport.nodes[1].data() + 2048, 256, 47);
    REQUIRE(pgas_x86_bulk_copy(runtime, remote1 + 4096, remote1 + 2048,
                               256) == 0);
    CHECK(std::memcmp(transport.nodes[1].data() + 4096,
                      transport.nodes[1].data() + 2048, 256) == 0);

    REQUIRE(pgas_x86_bulk_copy(runtime, remote2 + 8192, remote1 + 2048,
                               256) == 0);
    CHECK(std::memcmp(transport.nodes[2].data() + 8192,
                      transport.nodes[1].data() + 2048, 256) == 0);
    CHECK(std::memcmp(remote2 + 8192,
                      transport.nodes[2].data() + 8192, 256) == 0);

    std::vector<uint8_t> large_source(node_size);
    fill_pattern(large_source.data(), large_source.size(), 151);
    REQUIRE(pgas_x86_bulk_copy(runtime, remote1, large_source.data(),
                               large_source.size()) == 0);
    CHECK(std::memcmp(transport.nodes[1].data(), large_source.data(),
                      large_source.size()) == 0);

    REQUIRE(pgas_x86_bulk_set(runtime, remote2 + 16384, 0x6c, 4096) == 0);
    CHECK(std::all_of(transport.nodes[2].begin() + 16384,
                      transport.nodes[2].begin() + 16384 + 4096,
                      [](uint8_t value) { return value == 0x6c; }));

    pgas_x86_runtime_destroy(runtime);
}

TEST_CASE("bulk move honors forward and backward remote overlap",
          "[pgas][x86][bulk][execute]")
{
    std::vector<uint8_t> shadow(3 * node_size, 0);
    bulk_transport_state transport;
    auto *runtime = make_bulk_runtime(shadow, transport);
    REQUIRE(runtime != nullptr);
    auto *remote = shadow.data() + node_size;

    for (const bool backward : { false, true }) {
        fill_pattern(transport.nodes[1].data() + 512, 1024,
                     backward ? 71 : 93);
        std::memset(remote + 512, 0xa5, 1024);
        auto expected = transport.nodes[1];
        const size_t destination = backward ? 640 : 512;
        const size_t source = backward ? 512 : 640;
        std::memmove(expected.data() + destination,
                     expected.data() + source, 768);

        REQUIRE(pgas_x86_bulk_move(runtime, remote + destination,
                                   remote + source, 768) == 0);
        CHECK(transport.nodes[1] == expected);
        CHECK(std::memcmp(remote + destination,
                          expected.data() + destination, 768) == 0);
    }

    pgas_x86_runtime_destroy(runtime);
}

TEST_CASE("bulk execution splits nodes and reports transport failures",
          "[pgas][x86][bulk][execute][failure]")
{
    std::vector<uint8_t> shadow(3 * node_size, 0);
    bulk_transport_state transport;
    auto *runtime = make_bulk_runtime(shadow, transport);
    REQUIRE(runtime != nullptr);
    std::array<uint8_t, 128> source{};
    fill_pattern(source.data(), source.size(), 117);
    auto *crossing = shadow.data() + 2 * node_size - 32;

    REQUIRE(pgas_x86_bulk_copy(runtime, crossing, source.data(),
                               source.size()) == 0);
    CHECK(std::memcmp(transport.nodes[1].data() + node_size - 32,
                      source.data(), 32) == 0);
    CHECK(std::memcmp(transport.nodes[2].data(), source.data() + 32,
                      source.size() - 32) == 0);

    transport.fail_read = -EMSGSIZE;
    CHECK(pgas_x86_bulk_copy(runtime, source.data(),
                             shadow.data() + node_size, 64) == -EMSGSIZE);
    transport.fail_read = 0;
    transport.fail_write = -EIO;
    CHECK(pgas_x86_bulk_set(runtime, shadow.data() + node_size, 0x6c, 64) ==
          -EIO);

    pgas_x86_runtime_destroy(runtime);
}

TEST_CASE("bulk operations serialize threads touching the same remote line",
          "[pgas][x86][bulk][execute][thread]")
{
    std::vector<uint8_t> shadow(3 * node_size, 0);
    bulk_transport_state transport;
    transport.delay_writes = true;
    auto *runtime = make_bulk_runtime(shadow, transport);
    REQUIRE(runtime != nullptr);
    std::array<uint8_t, 64> first{};
    std::array<uint8_t, 64> second{};
    first.fill(0x11);
    second.fill(0x22);
    auto *remote = shadow.data() + node_size + 256;
    std::atomic<int> first_status{ -1 };
    std::atomic<int> second_status{ -1 };

    std::thread a([&] {
        first_status = pgas_x86_bulk_copy(runtime, remote, first.data(),
                                          first.size());
    });
    std::thread b([&] {
        second_status = pgas_x86_bulk_copy(runtime, remote, second.data(),
                                           second.size());
    });
    a.join();
    b.join();

    CHECK(first_status == 0);
    CHECK(second_status == 0);
    CHECK(transport.maximum_active_writes == 1);
    const bool is_first =
        std::memcmp(transport.nodes[1].data() + 256, first.data(), 64) == 0;
    const bool is_second =
        std::memcmp(transport.nodes[1].data() + 256, second.data(), 64) == 0;
    CHECK((is_first || is_second));
    pgas_x86_runtime_destroy(runtime);
}

TEST_CASE("bulk refresh and flush synchronize shadow in bounded chunks",
          "[pgas][x86][bulk][sync]")
{
    std::vector<uint8_t> shadow(3 * node_size, 0x11);
    bulk_transport_state transport;
    auto *runtime = make_bulk_runtime(shadow, transport);
    REQUIRE(runtime != nullptr);
    auto *remote = shadow.data() + node_size;
    fill_pattern(transport.nodes[1].data(), node_size, 61);

    REQUIRE(pgas_x86_bulk_refresh(runtime, remote, node_size) == 0);
    CHECK(std::memcmp(remote, transport.nodes[1].data(), node_size) == 0);
    fill_pattern(remote, node_size, 173);
    REQUIRE(pgas_x86_bulk_flush(runtime, remote, node_size) == 0);
    CHECK(std::memcmp(remote, transport.nodes[1].data(), node_size) == 0);
    pgas_x86_runtime_destroy(runtime);
}

TEST_CASE("bulk range lock spans refresh native update and flush",
          "[pgas][x86][bulk][sync][thread]")
{
    std::vector<uint8_t> shadow(3 * node_size, 0x11);
    bulk_transport_state transport;
    auto *runtime = make_bulk_runtime(shadow, transport);
    REQUIRE(runtime != nullptr);
    auto *remote = shadow.data() + node_size + 256;
    std::array<uint8_t, 64> competing{};
    competing.fill(0x77);
    transport.nodes[1].at(256) = 0x31;

    pgas_x86_bulk_lock lock{};
    const pgas_x86_bulk_range range{
        reinterpret_cast<uint64_t>(remote), competing.size()
    };
    REQUIRE(pgas_x86_bulk_lock_ranges(runtime, &range, 1, lock) == 0);
    REQUIRE(lock.active);
    REQUIRE(pgas_x86_bulk_refresh_locked(runtime, remote,
                                         competing.size()) == 0);
    CHECK(remote[0] == 0x31);

    std::atomic<bool> started{};
    std::atomic<bool> completed{};
    std::atomic<int> contender_status{ -1 };
    std::thread contender([&] {
        started.store(true, std::memory_order_release);
        contender_status = pgas_x86_bulk_copy(
            runtime, remote, competing.data(), competing.size());
        completed.store(true, std::memory_order_release);
    });
    while (!started.load(std::memory_order_acquire))
        std::this_thread::yield();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    CHECK_FALSE(completed.load(std::memory_order_acquire));

    std::memset(remote, 0x42, competing.size());
    REQUIRE(pgas_x86_bulk_flush_locked(runtime, remote,
                                       competing.size()) == 0);
    pgas_x86_bulk_unlock_ranges(lock);
    contender.join();
    CHECK(completed.load(std::memory_order_acquire));
    CHECK(contender_status == 0);
    CHECK(std::memcmp(transport.nodes[1].data() + 256,
                      competing.data(), competing.size()) == 0);

    pgas_x86_bulk_lock overflow{};
    const pgas_x86_bulk_range invalid{ UINT64_MAX - 3, 8 };
    CHECK(pgas_x86_bulk_lock_ranges(runtime, &invalid, 1, overflow) ==
          -EOVERFLOW);
    pgas_x86_runtime_destroy(runtime);
}
