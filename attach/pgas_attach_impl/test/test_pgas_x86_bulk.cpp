// SPDX-License-Identifier: MIT
#include <catch2/catch_test_macros.hpp>

#include "pgas_x86_bulk.hpp"

#include <cstdint>
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
