// SPDX-License-Identifier: MIT
#include "pgas_x86_replay.hpp"

#include <algorithm>
#include <cerrno>
#include <limits>

namespace bpftime::attach {

namespace {

constexpr uint64_t cache_line_size = 64;
constexpr uint8_t maximum_operand_width = 64;

int validate_config(const pgas_x86_runtime_config &config,
                    uint64_t &region_end, uint64_t &node_size)
{
    if (config.pgas_size == 0 || config.num_nodes == 0 ||
        config.local_node_id >= config.num_nodes)
        return -EINVAL;
    if (__builtin_add_overflow(config.pgas_base, config.pgas_size,
                               &region_end))
        return -EOVERFLOW;
    node_size = config.pgas_size / config.num_nodes;
    return node_size == 0 ? -EINVAL : 0;
}

int append_lane(pgas_x86_replay_plan &plan,
                const pgas_x86_runtime_config &config, uint64_t region_end,
                uint64_t node_size, size_t lane_index, uint64_t address,
                uint8_t width, uint16_t operand_offset)
{
    const auto range = pgas_x86_classify_range(
        address, width, config.pgas_base, config.pgas_size);
    if (range == pgas_x86_range_result::overflow)
        return -EOVERFLOW;
    if (range != pgas_x86_range_result::inside)
        return -ERANGE;

    auto &lane = plan.lanes[lane_index];
    lane.address = address;
    lane.byte_offset = operand_offset;
    lane.width = width;
    lane.lane = static_cast<uint8_t>(lane_index);
    lane.active = true;
    ++plan.active_lanes;

    uint64_t cursor = address;
    uint64_t access_end{};
    if (__builtin_add_overflow(address, static_cast<uint64_t>(width),
                               &access_end))
        return -EOVERFLOW;

    while (cursor < access_end) {
        if (plan.fragment_count >= plan.fragments.size())
            return -E2BIG;

        const uint64_t region_offset = cursor - config.pgas_base;
        uint64_t node = region_offset / node_size;
        if (node >= config.num_nodes)
            node = config.num_nodes - 1;

        const uint64_t node_base = config.pgas_base + node * node_size;
        const uint64_t node_end =
            node + 1 == config.num_nodes ? region_end : node_base + node_size;
        const uint64_t line = cursor & ~(cache_line_size - 1);
        const uint64_t line_end = line + cache_line_size;
        const uint64_t fragment_end =
            std::min({ access_end, node_end, line_end });
        if (fragment_end <= cursor)
            return -EOVERFLOW;

        auto &fragment = plan.fragments[plan.fragment_count++];
        fragment.address = cursor;
        fragment.byte_offset = static_cast<uint16_t>(
            operand_offset + (cursor - address));
        fragment.size = static_cast<uint8_t>(fragment_end - cursor);
        fragment.node = static_cast<uint16_t>(node);
        fragment.line = line;
        fragment.remote = node != config.local_node_id;
        lane.remote = lane.remote || fragment.remote;
        plan.lock_lines[plan.lock_count++] = line;
        cursor = fragment_end;
    }

    return 0;
}

void finalize_locks(pgas_x86_replay_plan &plan)
{
    auto begin = plan.lock_lines.begin();
    auto end = begin + plan.lock_count;
    std::sort(begin, end);
    plan.lock_count = static_cast<uint16_t>(std::unique(begin, end) - begin);
}

} // namespace

pgas_x86_replay_plan
pgas_x86_plan_contiguous(const pgas_x86_runtime_config &config,
                         uint64_t address, uint8_t width)
{
    pgas_x86_replay_plan plan{};
    plan.lane_count = 1;
    if (width == 0 || width > maximum_operand_width) {
        plan.status = -EINVAL;
        return plan;
    }

    uint64_t region_end{};
    uint64_t node_size{};
    plan.status = validate_config(config, region_end, node_size);
    if (plan.status != 0)
        return plan;

    plan.status = append_lane(plan, config, region_end, node_size, 0,
                              address, width, 0);
    if (plan.status == 0)
        finalize_locks(plan);
    return plan;
}

pgas_x86_replay_plan
pgas_x86_plan_lanes(const pgas_x86_runtime_config &config,
                    const uint64_t *addresses, size_t lane_count,
                    uint8_t lane_width, uint64_t active_mask)
{
    pgas_x86_replay_plan plan{};
    if (lane_count > pgas_x86_max_replay_lanes) {
        plan.status = -E2BIG;
        return plan;
    }
    plan.lane_count = static_cast<uint16_t>(lane_count);
    if ((lane_count != 0 && addresses == nullptr) || lane_width == 0 ||
        lane_width > maximum_operand_width) {
        plan.status = -EINVAL;
        return plan;
    }

    uint64_t region_end{};
    uint64_t node_size{};
    plan.status = validate_config(config, region_end, node_size);
    if (plan.status != 0)
        return plan;

    for (size_t i = 0; i < lane_count; ++i) {
        auto &lane = plan.lanes[i];
        lane.address = addresses[i];
        lane.byte_offset = static_cast<uint16_t>(i * lane_width);
        lane.width = lane_width;
        lane.lane = static_cast<uint8_t>(i);
        if ((active_mask & (UINT64_C(1) << i)) == 0)
            continue;

        plan.status = append_lane(
            plan, config, region_end, node_size, i, addresses[i], lane_width,
            static_cast<uint16_t>(i * lane_width));
        if (plan.status != 0)
            return plan;
    }

    finalize_locks(plan);
    return plan;
}

} // namespace bpftime::attach
