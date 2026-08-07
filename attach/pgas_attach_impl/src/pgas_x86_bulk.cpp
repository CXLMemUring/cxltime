// SPDX-License-Identifier: MIT
#include "pgas_x86_bulk.hpp"

#include <algorithm>
#include <cerrno>
#include <limits>

namespace bpftime::attach {

namespace {

struct endpoint_classification {
    uint16_t node{};
    bool remote{};
    uint64_t boundary_distance{};
};

bool config_bounds(const pgas_x86_runtime_config &config, uint64_t &end,
                   uint64_t &node_size)
{
    if (config.pgas_size == 0 || config.num_nodes == 0 ||
        config.local_node_id >= config.num_nodes ||
        __builtin_add_overflow(config.pgas_base, config.pgas_size, &end))
        return false;
    node_size = config.pgas_size / config.num_nodes;
    return node_size != 0;
}

endpoint_classification classify_forward(const pgas_x86_runtime_config &config,
                                         uint64_t end, uint64_t node_size,
                                         uint64_t address)
{
    endpoint_classification result{ config.local_node_id, false,
                                    std::numeric_limits<uint64_t>::max() };
    if (address < config.pgas_base) {
        result.boundary_distance = config.pgas_base - address;
        return result;
    }
    if (address >= end)
        return result;

    uint64_t node = (address - config.pgas_base) / node_size;
    if (node >= config.num_nodes)
        node = config.num_nodes - 1;
    const uint64_t node_end =
        node + 1 == config.num_nodes
            ? end
            : config.pgas_base + (node + 1) * node_size;
    result.node = static_cast<uint16_t>(node);
    result.remote = result.node != config.local_node_id;
    result.boundary_distance = node_end - address;
    return result;
}

endpoint_classification classify_backward(
    const pgas_x86_runtime_config &config, uint64_t end, uint64_t node_size,
    uint64_t cursor_end)
{
    endpoint_classification result{ config.local_node_id, false,
                                    std::numeric_limits<uint64_t>::max() };
    if (cursor_end == 0) {
        result.boundary_distance = 0;
        return result;
    }
    const uint64_t address = cursor_end - 1;
    if (address < config.pgas_base) {
        result.boundary_distance = cursor_end;
        return result;
    }
    if (address >= end) {
        result.boundary_distance = cursor_end - end;
        return result;
    }

    uint64_t node = (address - config.pgas_base) / node_size;
    if (node >= config.num_nodes)
        node = config.num_nodes - 1;
    const uint64_t node_base = config.pgas_base + node * node_size;
    result.node = static_cast<uint16_t>(node);
    result.remote = result.node != config.local_node_id;
    result.boundary_distance = cursor_end - node_base;
    return result;
}

} // namespace

pgas_x86_bulk_plan pgas_x86_plan_bulk(pgas_x86_bulk_kind kind,
                                      uint64_t destination, uint64_t source,
                                      uint64_t size)
{
    pgas_x86_bulk_plan plan{};
    plan.kind = kind;
    plan.destination = destination;
    plan.source = source;
    plan.total_size = size;

    uint64_t destination_end{};
    if (__builtin_add_overflow(destination, size, &destination_end)) {
        plan.status = -EOVERFLOW;
        return plan;
    }
    if (kind != pgas_x86_bulk_kind::set) {
        uint64_t source_end{};
        if (__builtin_add_overflow(source, size, &source_end)) {
            plan.status = -EOVERFLOW;
            return plan;
        }
        if (kind == pgas_x86_bulk_kind::move && destination > source &&
            destination < source_end)
            plan.direction = pgas_x86_copy_direction::backward;
    }
    return plan;
}

bool pgas_x86_bulk_next(const pgas_x86_runtime_config &config,
                        const pgas_x86_bulk_plan &plan, uint64_t completed,
                        pgas_x86_bulk_chunk &chunk)
{
    chunk = {};
    if (plan.status != 0 || completed >= plan.total_size ||
        plan.chunk_size == 0)
        return false;

    uint64_t region_end{};
    uint64_t node_size{};
    if (!config_bounds(config, region_end, node_size))
        return false;

    uint64_t size = std::min<uint64_t>(plan.chunk_size,
                                       plan.total_size - completed);
    endpoint_classification destination_class{};
    endpoint_classification source_class{ config.local_node_id, false,
                                           std::numeric_limits<uint64_t>::max() };

    if (plan.direction == pgas_x86_copy_direction::forward) {
        uint64_t destination{};
        uint64_t source{};
        if (__builtin_add_overflow(plan.destination, completed, &destination) ||
            (plan.kind != pgas_x86_bulk_kind::set &&
             __builtin_add_overflow(plan.source, completed, &source)))
            return false;
        destination_class =
            classify_forward(config, region_end, node_size, destination);
        if (plan.kind != pgas_x86_bulk_kind::set)
            source_class =
                classify_forward(config, region_end, node_size, source);
        size = std::min(
            { size, destination_class.boundary_distance,
              source_class.boundary_distance });
        chunk.destination = destination;
        chunk.source = source;
    } else {
        const uint64_t remaining = plan.total_size - completed;
        uint64_t destination_end{};
        uint64_t source_end{};
        if (__builtin_add_overflow(plan.destination, remaining,
                                   &destination_end) ||
            (plan.kind != pgas_x86_bulk_kind::set &&
             __builtin_add_overflow(plan.source, remaining, &source_end)))
            return false;
        destination_class = classify_backward(config, region_end, node_size,
                                               destination_end);
        if (plan.kind != pgas_x86_bulk_kind::set)
            source_class = classify_backward(config, region_end, node_size,
                                              source_end);
        size = std::min(
            { size, destination_class.boundary_distance,
              source_class.boundary_distance });
        if (size == 0)
            return false;
        chunk.destination = destination_end - size;
        chunk.source = source_end - size;
    }

    if (size == 0 || size > std::numeric_limits<uint32_t>::max())
        return false;
    chunk.size = static_cast<uint32_t>(size);
    chunk.destination_node = destination_class.node;
    chunk.source_node = source_class.node;
    chunk.destination_remote = destination_class.remote;
    chunk.source_remote = source_class.remote;
    return true;
}

} // namespace bpftime::attach
