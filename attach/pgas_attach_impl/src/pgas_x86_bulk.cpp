// SPDX-License-Identifier: MIT
#include "pgas_x86_bulk.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cerrno>
#include <cstring>
#include <limits>

namespace bpftime::attach {

namespace {

struct endpoint_classification {
    uint16_t node{};
    bool remote{};
    uint64_t boundary_distance{};
};

constexpr size_t cache_line_size = 64;
constexpr size_t maximum_bulk_chunk = 64 * 1024;
constexpr size_t maximum_bulk_lines =
    2 * (maximum_bulk_chunk / cache_line_size + 1);

thread_local std::array<std::byte, maximum_bulk_chunk> bulk_staging;

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

bool address_in_pgas(const pgas_x86_runtime_config &config, uint64_t address)
{
    uint64_t end{};
    return !__builtin_add_overflow(config.pgas_base, config.pgas_size, &end) &&
           address >= config.pgas_base && address < end;
}

bool append_lines(const pgas_x86_runtime_config &config, uint64_t address,
                  size_t size,
                  std::array<uint64_t, maximum_bulk_lines> &lines,
                  size_t &line_count)
{
    if (size == 0 || !address_in_pgas(config, address))
        return true;
    uint64_t last{};
    if (__builtin_add_overflow(address, static_cast<uint64_t>(size - 1),
                               &last))
        return false;
    uint64_t line = address & ~(uint64_t(cache_line_size) - 1);
    const uint64_t last_line = last & ~(uint64_t(cache_line_size) - 1);
    while (true) {
        if (line_count == lines.size())
            return false;
        lines[line_count++] = line;
        if (line == last_line)
            return true;
        line += cache_line_size;
    }
}

class bulk_lock_guard {
  public:
    explicit bulk_lock_guard(pgas_x86_runtime *runtime) : runtime_(runtime) {}
    bulk_lock_guard(const bulk_lock_guard &) = delete;
    bulk_lock_guard &operator=(const bulk_lock_guard &) = delete;
    ~bulk_lock_guard()
    {
        if (acquired_ != 0)
            pgas_x86_runtime_unlock_lines(runtime_, stripes_.data(),
                                          acquired_);
    }

    int acquire(const pgas_x86_runtime_config &config,
                const pgas_x86_bulk_chunk &chunk,
                pgas_x86_bulk_kind kind)
    {
        std::array<uint64_t, maximum_bulk_lines> lines{};
        size_t line_count = 0;
        if (!append_lines(config, chunk.destination, chunk.size, lines,
                          line_count) ||
            (kind != pgas_x86_bulk_kind::set &&
             !append_lines(config, chunk.source, chunk.size, lines,
                           line_count)))
            return -E2BIG;
        return pgas_x86_runtime_lock_lines(
            runtime_, lines.data(), line_count, stripes_.data(),
            stripes_.size(), acquired_);
    }

  private:
    pgas_x86_runtime *runtime_{};
    std::array<uint16_t, maximum_bulk_lines> stripes_{};
    uint16_t acquired_{};
};

int execute_bulk(pgas_x86_runtime *runtime, pgas_x86_bulk_kind kind,
                 void *destination, const void *source, unsigned char value,
                 size_t size, bool internal_shadow_destination = false)
{
    if (size == 0)
        return 0;
    if (runtime == nullptr || destination == nullptr ||
        (kind != pgas_x86_bulk_kind::set && source == nullptr))
        return -EINVAL;

    pgas_x86_runtime_config config{};
    int result = pgas_x86_runtime_get_config(runtime, config);
    if (result != 0)
        return result;
    const auto plan = pgas_x86_plan_bulk(
        kind, reinterpret_cast<uint64_t>(destination),
        reinterpret_cast<uint64_t>(source), size);
    if (plan.status != 0)
        return plan.status;

    uint64_t completed = 0;
    pgas_x86_bulk_chunk chunk{};
    while (pgas_x86_bulk_next(config, plan, completed, chunk)) {
        bulk_lock_guard locks(runtime);
        result = locks.acquire(config, chunk, kind);
        if (result != 0)
            return result;

        auto *staging = bulk_staging.data();
        if (kind == pgas_x86_bulk_kind::set) {
            std::memset(staging, value, chunk.size);
        } else if (chunk.source_remote) {
            result = pgas_x86_runtime_read(runtime, chunk.source_node,
                                           chunk.source, staging, chunk.size);
            if (result != 0)
                return result;
            std::memcpy(pgas_x86_runtime_shadow_write_pointer(
                            runtime, chunk.source, chunk.size), staging,
                        chunk.size);
        } else {
            std::memcpy(staging,
                        reinterpret_cast<const void *>(chunk.source),
                        chunk.size);
        }

        void *shadow_destination = reinterpret_cast<void *>(chunk.destination);
        if (internal_shadow_destination)
            shadow_destination = pgas_x86_runtime_shadow_write_pointer(
                runtime, chunk.destination, chunk.size);
        std::memcpy(shadow_destination, staging,
                    chunk.size);
        if (chunk.destination_remote) {
            result = pgas_x86_runtime_write(
                runtime, chunk.destination_node, chunk.destination, staging,
                chunk.size);
            if (result != 0)
                return result;
        }
        completed += chunk.size;
    }
    return completed == size ? 0 : -ERANGE;
}

int execute_sync(pgas_x86_runtime *runtime, void *address, size_t size,
                 bool refresh, bool acquire_chunk_locks)
{
    if (size == 0)
        return 0;
    if (runtime == nullptr || address == nullptr)
        return -EINVAL;
    pgas_x86_runtime_config config{};
    int result = pgas_x86_runtime_get_config(runtime, config);
    if (result != 0)
        return result;
    const auto plan = pgas_x86_plan_bulk(
        pgas_x86_bulk_kind::set, reinterpret_cast<uint64_t>(address), 0,
        size);
    if (plan.status != 0)
        return plan.status;
    uint64_t completed = 0;
    pgas_x86_bulk_chunk chunk{};
    while (pgas_x86_bulk_next(config, plan, completed, chunk)) {
        bulk_lock_guard locks(runtime);
        if (acquire_chunk_locks) {
            result = locks.acquire(config, chunk, pgas_x86_bulk_kind::set);
            if (result != 0)
                return result;
        }
        if (chunk.destination_remote) {
            if (refresh) {
                result = pgas_x86_runtime_read(
                    runtime, chunk.destination_node, chunk.destination,
                    bulk_staging.data(), chunk.size);
                if (result == 0)
                    std::memcpy(pgas_x86_runtime_shadow_write_pointer(
                                    runtime, chunk.destination, chunk.size),
                                bulk_staging.data(), chunk.size);
            } else {
                std::memcpy(bulk_staging.data(),
                            reinterpret_cast<const void *>(chunk.destination),
                            chunk.size);
                result = pgas_x86_runtime_write(
                    runtime, chunk.destination_node, chunk.destination,
                    bulk_staging.data(), chunk.size);
            }
            if (result != 0)
                return result;
        }
        completed += chunk.size;
    }
    return completed == size ? 0 : -ERANGE;
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

int pgas_x86_bulk_copy(pgas_x86_runtime *runtime, void *destination,
                       const void *source, size_t size)
{
    return execute_bulk(runtime, pgas_x86_bulk_kind::copy, destination, source,
                        0, size);
}

int pgas_x86_bulk_seed(pgas_x86_runtime *runtime, void *destination,
                       const void *source, size_t size)
{
    return execute_bulk(runtime, pgas_x86_bulk_kind::copy, destination, source,
                        0, size, true);
}

int pgas_x86_bulk_move(pgas_x86_runtime *runtime, void *destination,
                       const void *source, size_t size)
{
    return execute_bulk(runtime, pgas_x86_bulk_kind::move, destination, source,
                        0, size);
}

int pgas_x86_bulk_set(pgas_x86_runtime *runtime, void *destination,
                      unsigned char value, size_t size)
{
    return execute_bulk(runtime, pgas_x86_bulk_kind::set, destination, nullptr,
                        value, size);
}

int pgas_x86_bulk_refresh(pgas_x86_runtime *runtime, void *address,
                          size_t size)
{
    return execute_sync(runtime, address, size, true, true);
}

int pgas_x86_bulk_flush(pgas_x86_runtime *runtime, const void *address,
                        size_t size)
{
    return execute_sync(runtime, const_cast<void *>(address), size, false,
                        true);
}

int pgas_x86_bulk_lock_ranges(pgas_x86_runtime *runtime,
                              const pgas_x86_bulk_range *ranges,
                              size_t range_count,
                              pgas_x86_bulk_lock &lock)
{
    if (runtime == nullptr || (range_count != 0 && ranges == nullptr) ||
        lock.active)
        return -EINVAL;
    pgas_x86_runtime_config config{};
    int result = pgas_x86_runtime_get_config(runtime, config);
    if (result != 0)
        return result;
    uint64_t pgas_end{};
    if (__builtin_add_overflow(config.pgas_base, config.pgas_size,
                               &pgas_end))
        return -EOVERFLOW;

    constexpr size_t stripe_count = 4096;
    std::array<bool, stripe_count> seen{};
    std::array<uint64_t, stripe_count> lines{};
    size_t line_count = 0;
    for (size_t range_index = 0;
         range_index < range_count && line_count != stripe_count;
         ++range_index) {
        const auto &range = ranges[range_index];
        if (range.size == 0)
            continue;
        uint64_t range_end{};
        if (__builtin_add_overflow(range.address, range.size, &range_end))
            return -EOVERFLOW;
        uint64_t cursor = std::max(range.address, config.pgas_base);
        const uint64_t clipped_end = std::min(range_end, pgas_end);
        if (cursor >= clipped_end)
            continue;
        cursor &= ~(uint64_t(cache_line_size) - 1);
        const uint64_t last =
            (clipped_end - 1) & ~(uint64_t(cache_line_size) - 1);
        for (;;) {
            const size_t stripe = static_cast<size_t>(
                (cursor / cache_line_size) % stripe_count);
            if (!seen[stripe]) {
                seen[stripe] = true;
                lines[line_count++] = cursor;
                if (line_count == stripe_count)
                    break;
            }
            if (cursor == last)
                break;
            cursor += cache_line_size;
        }
    }
    lock.runtime = runtime;
    lock.acquired = 0;
    lock.active = true;
    result = pgas_x86_runtime_lock_lines(
        runtime, lines.data(), line_count, lock.stripes.data(),
        lock.stripes.size(), lock.acquired);
    if (result != 0) {
        pgas_x86_bulk_unlock_ranges(lock);
        return result;
    }
    return 0;
}

void pgas_x86_bulk_unlock_ranges(pgas_x86_bulk_lock &lock)
{
    if (lock.active)
        pgas_x86_runtime_unlock_lines(lock.runtime, lock.stripes.data(),
                                      lock.acquired);
    lock.runtime = nullptr;
    lock.acquired = 0;
    lock.active = false;
}

int pgas_x86_bulk_refresh_locked(pgas_x86_runtime *runtime, void *address,
                                 size_t size)
{
    return execute_sync(runtime, address, size, true, false);
}

int pgas_x86_bulk_flush_locked(pgas_x86_runtime *runtime,
                               const void *address, size_t size)
{
    return execute_sync(runtime, const_cast<void *>(address), size, false,
                        false);
}

} // namespace bpftime::attach
