// SPDX-License-Identifier: MIT
#include "pgas_x86_replay.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
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
    const auto fail = [&](int error) {
        plan.failure_address = address;
        plan.failure_lane = static_cast<uint8_t>(lane_index);
        return error;
    };
    const auto range = pgas_x86_classify_range(
        address, width, config.pgas_base, config.pgas_size);
    if (range == pgas_x86_range_result::overflow)
        return fail(-EOVERFLOW);
    if (range != pgas_x86_range_result::inside)
        return fail(-ERANGE);

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
        return fail(-EOVERFLOW);

    while (cursor < access_end) {
        if (plan.fragment_count >= plan.fragments.size())
            return fail(-E2BIG);

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
            return fail(-EOVERFLOW);

        auto &fragment = plan.fragments[plan.fragment_count++];
        fragment.address = cursor;
        fragment.byte_offset = static_cast<uint16_t>(
            operand_offset + (cursor - address));
        fragment.size = static_cast<uint8_t>(fragment_end - cursor);
        fragment.node = static_cast<uint16_t>(node);
        fragment.line = line;
        fragment.lane = static_cast<uint8_t>(lane_index);
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

bool access_reads_shadow(pgas_x86_access_class access)
{
    return access == pgas_x86_access_class::read ||
           access == pgas_x86_access_class::read_modify_write ||
           access == pgas_x86_access_class::prefetch;
}

bool access_writes_shadow(pgas_x86_access_class access)
{
    return access == pgas_x86_access_class::write ||
           access == pgas_x86_access_class::read_modify_write;
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

int pgas_x86_replay_prepare(pgas_x86_runtime *runtime,
                            pgas_x86_replay_transaction &transaction,
                            const pgas_x86_replay_plan &plan,
                            pgas_x86_access_class access)
{
    if (runtime == nullptr || transaction.active || plan.status != 0 ||
        plan.fragment_count > plan.fragments.size() ||
        plan.lock_count > plan.lock_lines.size() ||
        (!access_reads_shadow(access) && !access_writes_shadow(access)))
        return -EINVAL;

    transaction.plan = plan;
    transaction.access = access;
    transaction.runtime = runtime;
    transaction.acquired_locks = 0;
    transaction.lock_contentions = 0;
    transaction.failure_address = 0;
    transaction.failure_node = UINT16_MAX;
    transaction.failure_fragment = UINT16_MAX;
    transaction.failure_lane = UINT8_MAX;
    transaction.status = 0;
    transaction.failed = false;

    int result = pgas_x86_runtime_lock_lines(
        runtime, plan.lock_lines.data(), plan.lock_count,
        transaction.lock_stripes.data(), transaction.lock_stripes.size(),
        transaction.acquired_locks, &transaction.lock_contentions);
    if (result != 0) {
        transaction.status = result;
        transaction.failed = true;
        transaction.runtime = nullptr;
        return result;
    }
    transaction.active = true;

    if (!access_reads_shadow(access))
        return 0;

    for (size_t i = 0; i < plan.fragment_count; ++i) {
        const auto &fragment = plan.fragments[i];
        const size_t staging_end =
            static_cast<size_t>(fragment.byte_offset) + fragment.size;
        if (staging_end > transaction.staging.size()) {
            result = -E2BIG;
            transaction.failure_address = fragment.address;
            transaction.failure_node = fragment.node;
            transaction.failure_fragment = static_cast<uint16_t>(i);
            transaction.failure_lane = fragment.lane;
            break;
        }
        if (!fragment.remote)
            continue;
        result = pgas_x86_runtime_read(
            runtime, fragment.node, fragment.address,
            transaction.staging.data() + fragment.byte_offset,
            fragment.size);
        if (result != 0) {
            transaction.failure_address = fragment.address;
            transaction.failure_node = fragment.node;
            transaction.failure_fragment = static_cast<uint16_t>(i);
            transaction.failure_lane = fragment.lane;
            break;
        }
    }

    if (result == 0) {
        for (size_t i = 0; i < plan.fragment_count; ++i) {
            const auto &fragment = plan.fragments[i];
            if (!fragment.remote)
                continue;
            std::memcpy(reinterpret_cast<void *>(fragment.address),
                        transaction.staging.data() + fragment.byte_offset,
                        fragment.size);
        }
        return 0;
    }

    transaction.status = result;
    transaction.failed = true;
    pgas_x86_replay_abort(transaction);
    return result;
}

int pgas_x86_replay_commit(pgas_x86_replay_transaction &transaction)
{
    if (!transaction.active || transaction.runtime == nullptr)
        return -EINVAL;
    if (transaction.failed)
        return transaction.status != 0 ? transaction.status : -EIO;

    if (access_writes_shadow(transaction.access)) {
        for (size_t i = 0; i < transaction.plan.fragment_count; ++i) {
            const auto &fragment = transaction.plan.fragments[i];
            if (!fragment.remote)
                continue;
            const int result = pgas_x86_runtime_write(
                transaction.runtime, fragment.node, fragment.address,
                reinterpret_cast<const void *>(fragment.address),
                fragment.size);
            if (result != 0) {
                transaction.status = result;
                transaction.failed = true;
                transaction.failure_address = fragment.address;
                transaction.failure_node = fragment.node;
                transaction.failure_fragment = static_cast<uint16_t>(i);
                transaction.failure_lane = fragment.lane;
                return result;
            }
        }
    }

    pgas_x86_replay_abort(transaction);
    return 0;
}

void pgas_x86_replay_abort(pgas_x86_replay_transaction &transaction)
{
    if (transaction.active && transaction.runtime != nullptr) {
        pgas_x86_runtime_unlock_lines(
            transaction.runtime, transaction.lock_stripes.data(),
            transaction.acquired_locks);
    }
    transaction.acquired_locks = 0;
    transaction.active = false;
    transaction.runtime = nullptr;
}

} // namespace bpftime::attach
