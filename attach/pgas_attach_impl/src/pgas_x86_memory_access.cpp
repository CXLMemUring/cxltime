// SPDX-License-Identifier: MIT
#include "pgas_x86_memory_access.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <new>
#include <thread>

#include <sys/syscall.h>
#include <unistd.h>

namespace bpftime::attach {

namespace {

constexpr size_t cache_line_size = 64;
constexpr size_t maximum_access_width = 64;
constexpr size_t lock_stripe_count = 4096;

bool checked_end(uint64_t start, size_t width, uint64_t &end)
{
    return !__builtin_add_overflow(start, static_cast<uint64_t>(width), &end);
}

uint64_t current_thread_id()
{
    return static_cast<uint64_t>(syscall(SYS_gettid));
}

} // namespace

struct pgas_x86_runtime {
    explicit pgas_x86_runtime(const pgas_x86_runtime_config &runtime_config)
        : config(runtime_config)
    {
        for (auto &lock : line_locks)
            lock.clear(std::memory_order_relaxed);
    }

    pgas_x86_runtime_config config;
    std::array<std::atomic_flag, lock_stripe_count> line_locks{};
};

pgas_x86_range_result pgas_x86_classify_range(uint64_t address,
                                               size_t width,
                                               uint64_t base,
                                               uint64_t region_size)
{
    if (width == 0 || width > maximum_access_width)
        return pgas_x86_range_result::overflow;

    uint64_t access_end{};
    uint64_t region_end{};
    if (!checked_end(address, width, access_end) ||
        __builtin_add_overflow(base, region_size, &region_end))
        return pgas_x86_range_result::overflow;

    if (region_size == 0 || access_end <= base || address >= region_end)
        return pgas_x86_range_result::outside;

    if (address < base || access_end > region_end)
        return pgas_x86_range_result::partial;

    return pgas_x86_range_result::inside;
}

pgas_x86_segments pgas_x86_split_cachelines(uint64_t address, size_t width)
{
    pgas_x86_segments result{};
    uint64_t access_end{};
    if (width == 0 || width > maximum_access_width ||
        !checked_end(address, width, access_end))
        return result;

    const size_t line_offset = address % cache_line_size;
    const size_t first_size =
        std::min(width, cache_line_size - line_offset);

    result.value[0] = { address, 0, static_cast<uint8_t>(first_size) };
    result.count = 1;

    const size_t second_size = width - first_size;
    if (second_size != 0) {
        result.value[1] = { address + first_size,
                            static_cast<uint8_t>(first_size),
                            static_cast<uint8_t>(second_size) };
        result.count = 2;
    }

    return result;
}

namespace {

int report_failure(pgas_x86_runtime *runtime, pgas_x86_access_event *event,
                   uint8_t segment_index, int error)
{
    if (runtime == nullptr || event == nullptr || event->descriptor == nullptr)
        return error;

    const auto &descriptor = *event->descriptor;
    pgas_x86_failure failure{};
    failure.thread_id = current_thread_id();
    failure.instruction_address = descriptor.instruction_address;
    failure.instruction_id = descriptor.instruction_id;
    std::memcpy(failure.mnemonic, descriptor.mnemonic,
                sizeof(failure.mnemonic));
    failure.access_class = descriptor.access_class;
    failure.effective_address = event->effective_address;
    failure.width = descriptor.width;
    failure.segment_index = segment_index;
    failure.target_node = event->target_node;
    failure.transport_error = error;
    if (runtime->config.fail != nullptr)
        runtime->config.fail(runtime->config.fail_opaque, failure);
    return error;
}

void release_locks(pgas_x86_access_event *event)
{
    if (event == nullptr || !event->locks_held || event->runtime == nullptr)
        return;

    for (size_t i = event->lock_count; i != 0; --i) {
        event->runtime->line_locks[event->lock_stripes[i - 1]].clear(
            std::memory_order_release);
    }
    event->lock_count = 0;
    event->locks_held = false;
    event->runtime = nullptr;
}

int prepare_access(pgas_x86_runtime *runtime, pgas_x86_access_event *event,
                   pgas_x86_access_class expected_class,
                   uint64_t &node_base)
{
    if (runtime == nullptr || event == nullptr || event->descriptor == nullptr)
        return -EINVAL;
    if (event->locks_held)
        return report_failure(runtime, event, UINT8_MAX, -EBUSY);

    const auto &descriptor = *event->descriptor;
    if (descriptor.access_class != expected_class)
        return report_failure(runtime, event, UINT8_MAX, -EINVAL);

    const auto range = pgas_x86_classify_range(
        event->effective_address, descriptor.width, runtime->config.pgas_base,
        runtime->config.pgas_size);
    if (range != pgas_x86_range_result::inside) {
        const int error = range == pgas_x86_range_result::overflow
                              ? -EOVERFLOW
                              : -ERANGE;
        return report_failure(runtime, event, UINT8_MAX, error);
    }

    if (runtime->config.num_nodes == 0)
        return report_failure(runtime, event, UINT8_MAX, -EINVAL);
    const uint64_t node_size =
        runtime->config.pgas_size / runtime->config.num_nodes;
    if (node_size == 0)
        return report_failure(runtime, event, UINT8_MAX, -EINVAL);

    const uint64_t offset =
        event->effective_address - runtime->config.pgas_base;
    uint64_t node = offset / node_size;
    if (node >= runtime->config.num_nodes)
        node = runtime->config.num_nodes - 1;
    event->target_node = static_cast<uint16_t>(node);
    node_base = runtime->config.pgas_base + node * node_size;

    const uint64_t node_end =
        node + 1 == runtime->config.num_nodes
            ? runtime->config.pgas_base + runtime->config.pgas_size
            : node_base + node_size;
    uint64_t access_end{};
    if (!checked_end(event->effective_address, descriptor.width, access_end) ||
        access_end > node_end)
        return report_failure(runtime, event, UINT8_MAX, -ERANGE);

    event->segments =
        pgas_x86_split_cachelines(event->effective_address, descriptor.width);
    if (event->segments.count == 0)
        return report_failure(runtime, event, UINT8_MAX, -EOVERFLOW);

    event->runtime = runtime;
    event->lock_count = 0;
    for (size_t i = 0; i < event->segments.count; ++i) {
        const uint64_t cache_line =
            event->segments.value[i].address / cache_line_size;
        const auto stripe =
            static_cast<uint16_t>(cache_line % lock_stripe_count);
        if (event->lock_count != 0 &&
            event->lock_stripes[event->lock_count - 1] == stripe)
            continue;
        while (runtime->line_locks[stripe].test_and_set(
            std::memory_order_acquire))
            std::this_thread::yield();
        event->lock_stripes[event->lock_count++] = stripe;
    }
    event->locks_held = true;
    return 0;
}

} // namespace

pgas_x86_runtime *
pgas_x86_runtime_create(const pgas_x86_runtime_config &config)
{
    uint64_t region_end{};
    if (config.pgas_size == 0 || config.num_nodes == 0 ||
        config.transport.read == nullptr || config.transport.write == nullptr ||
        __builtin_add_overflow(config.pgas_base, config.pgas_size, &region_end))
        return nullptr;
    return new (std::nothrow) pgas_x86_runtime(config);
}

void pgas_x86_runtime_destroy(pgas_x86_runtime *runtime)
{
    delete runtime;
}

int pgas_x86_begin_load(pgas_x86_runtime *runtime,
                        pgas_x86_access_event *event)
{
    uint64_t node_base{};
    int result = prepare_access(runtime, event, pgas_x86_access_class::read,
                                node_base);
    if (result != 0)
        return result;

    if (event->target_node != runtime->config.local_node_id) {
        std::array<uint8_t, maximum_access_width> buffer{};
        for (size_t i = 0; i < event->segments.count; ++i) {
            const auto &segment = event->segments.value[i];
            result = runtime->config.transport.read(
                runtime->config.transport.opaque, event->target_node,
                segment.address - node_base, buffer.data() + segment.offset,
                segment.size);
            if (result != 0) {
                report_failure(runtime, event, static_cast<uint8_t>(i), result);
                release_locks(event);
                return result;
            }
        }
        std::memcpy(reinterpret_cast<void *>(event->effective_address),
                    buffer.data(), event->descriptor->width);
    }
    return 0;
}

int pgas_x86_begin_store(pgas_x86_runtime *runtime,
                         pgas_x86_access_event *event, const void *source,
                         size_t source_size)
{
    if (event == nullptr || event->descriptor == nullptr || source == nullptr ||
        source_size != event->descriptor->width)
        return report_failure(runtime, event, UINT8_MAX, -EINVAL);

    uint64_t node_base{};
    int result = prepare_access(runtime, event, pgas_x86_access_class::write,
                                node_base);
    if (result != 0)
        return result;

    if (event->target_node != runtime->config.local_node_id) {
        const auto *bytes = static_cast<const uint8_t *>(source);
        for (size_t i = 0; i < event->segments.count; ++i) {
            const auto &segment = event->segments.value[i];
            result = runtime->config.transport.write(
                runtime->config.transport.opaque, event->target_node,
                segment.address - node_base, bytes + segment.offset,
                segment.size);
            if (result != 0) {
                report_failure(runtime, event, static_cast<uint8_t>(i), result);
                release_locks(event);
                return result;
            }
        }
    }
    return 0;
}

void pgas_x86_finish_access(pgas_x86_access_event *event)
{
    release_locks(event);
}

int pgas_x86_runtime_lock_lines(pgas_x86_runtime *runtime,
                                const uint64_t *lines, size_t line_count,
                                uint16_t *stripes, size_t stripe_capacity,
                                uint16_t &acquired)
{
    acquired = 0;
    if (runtime == nullptr || (line_count != 0 && lines == nullptr) ||
        (line_count != 0 && stripes == nullptr) ||
        line_count > stripe_capacity || line_count > lock_stripe_count)
        return -EINVAL;

    for (size_t i = 0; i < line_count; ++i) {
        const uint64_t cache_line = lines[i] / cache_line_size;
        stripes[i] =
            static_cast<uint16_t>(cache_line % lock_stripe_count);
    }
    std::sort(stripes, stripes + line_count);
    const auto *unique_end = std::unique(stripes, stripes + line_count);
    const size_t unique_count = unique_end - stripes;
    for (size_t i = 0; i < unique_count; ++i) {
        while (runtime->line_locks[stripes[i]].test_and_set(
            std::memory_order_acquire))
            std::this_thread::yield();
        ++acquired;
    }
    return 0;
}

void pgas_x86_runtime_unlock_lines(pgas_x86_runtime *runtime,
                                   const uint16_t *stripes,
                                   uint16_t acquired)
{
    if (runtime == nullptr || stripes == nullptr)
        return;
    while (acquired != 0) {
        --acquired;
        runtime->line_locks[stripes[acquired]].clear(
            std::memory_order_release);
    }
}

namespace {

int translate_transport_address(pgas_x86_runtime *runtime, uint16_t node,
                                uint64_t address, size_t size,
                                uint64_t &node_offset)
{
    if (runtime == nullptr || size == 0 || node >= runtime->config.num_nodes)
        return -EINVAL;
    const uint64_t node_size =
        runtime->config.pgas_size / runtime->config.num_nodes;
    if (node_size == 0)
        return -EINVAL;
    const uint64_t node_base =
        runtime->config.pgas_base + static_cast<uint64_t>(node) * node_size;
    const uint64_t node_end =
        node + 1 == runtime->config.num_nodes
            ? runtime->config.pgas_base + runtime->config.pgas_size
            : node_base + node_size;
    uint64_t access_end{};
    if (__builtin_add_overflow(address, static_cast<uint64_t>(size),
                               &access_end))
        return -EOVERFLOW;
    if (address < node_base || access_end > node_end)
        return -ERANGE;
    node_offset = address - node_base;
    return 0;
}

} // namespace

int pgas_x86_runtime_read(pgas_x86_runtime *runtime, uint16_t node,
                          uint64_t address, void *destination, size_t size)
{
    if (destination == nullptr)
        return -EINVAL;
    uint64_t node_offset{};
    const int result = translate_transport_address(
        runtime, node, address, size, node_offset);
    if (result != 0)
        return result;
    return runtime->config.transport.read(runtime->config.transport.opaque,
                                          node, node_offset, destination,
                                          size);
}

int pgas_x86_runtime_write(pgas_x86_runtime *runtime, uint16_t node,
                           uint64_t address, const void *source, size_t size)
{
    if (source == nullptr)
        return -EINVAL;
    uint64_t node_offset{};
    const int result = translate_transport_address(
        runtime, node, address, size, node_offset);
    if (result != 0)
        return result;
    return runtime->config.transport.write(runtime->config.transport.opaque,
                                           node, node_offset, source, size);
}

} // namespace bpftime::attach
