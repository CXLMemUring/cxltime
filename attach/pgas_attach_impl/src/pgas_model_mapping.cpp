// SPDX-License-Identifier: MIT
#include "pgas_model_mapping.hpp"

#include "pgas_x86_bulk.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <sys/stat.h>
#include <unistd.h>

namespace bpftime::attach {

namespace {

constexpr size_t maximum_seed_chunk = 64 * 1024;
thread_local std::array<std::byte, maximum_seed_chunk> seed_buffer;

bool add_overflow(uint64_t left, uint64_t right, uint64_t &result)
{
    return __builtin_add_overflow(left, right, &result);
}

uint64_t overlap_size(uint64_t begin, uint64_t end,
                      uint64_t range_begin, uint64_t range_end)
{
    const uint64_t low = std::max(begin, range_begin);
    const uint64_t high = std::min(end, range_end);
    return high > low ? high - low : 0;
}

} // namespace

int pgas_model_mapper::configure(const pgas_model_mapping_config &config)
{
    std::lock_guard guard(mutex_);
    if (!views_.empty())
        return -EBUSY;

    if (config.file.empty() || config.runtime == nullptr ||
        config.arena_size == 0 || config.page_size == 0 ||
        (config.page_size & (config.page_size - 1)) != 0 ||
        config.seed_chunk_size == 0 ||
        config.seed_chunk_size > maximum_seed_chunk ||
        (config.arena_base & (config.page_size - 1)) != 0)
        return -EINVAL;

    char resolved[PATH_MAX];
    if (realpath(config.file.c_str(), resolved) == nullptr)
        return -errno;
    struct stat file_status{};
    if (stat(resolved, &file_status) != 0)
        return -errno;
    if (!S_ISREG(file_status.st_mode) || file_status.st_size < 0)
        return -EINVAL;

    pgas_x86_runtime_config runtime_config{};
    int result = pgas_x86_runtime_get_config(config.runtime, runtime_config);
    if (result != 0)
        return result;
    uint64_t arena_end{};
    uint64_t pgas_end{};
    if (add_overflow(config.arena_base, config.arena_size, arena_end) ||
        add_overflow(runtime_config.pgas_base, runtime_config.pgas_size,
                     pgas_end))
        return -EOVERFLOW;
    if (config.arena_base < runtime_config.pgas_base || arena_end > pgas_end)
        return -ENOSPC;
    if (static_cast<uint64_t>(file_status.st_size) > config.arena_size)
        return -ENOSPC;

    pgas_model_mapping_config accepted = config;
    accepted.file = resolved;
    config_ = std::move(accepted);
    runtime_config_ = runtime_config;
    device_ = file_status.st_dev;
    inode_ = file_status.st_ino;
    file_size_ = static_cast<uint64_t>(file_status.st_size);
    inventory_ = {};
    poisoned_ = false;
    configured_ = true;
    return 0;
}

bool pgas_model_mapper::matches_fd_locked(int fd) const
{
    if (!configured_ || fd < 0)
        return false;
    struct stat status{};
    return fstat(fd, &status) == 0 && status.st_dev == device_ &&
           status.st_ino == inode_;
}

bool pgas_model_mapper::matches_fd(int fd) const
{
    std::lock_guard guard(mutex_);
    return matches_fd_locked(fd);
}

void pgas_model_mapper::reject_locked(int error, int &error_out)
{
    if (inventory_.rejected_mappings != UINT64_MAX)
        ++inventory_.rejected_mappings;
    error_out = error;
}

bool pgas_model_mapper::account_view_locked(uint64_t address,
                                           uint64_t length, bool add)
{
    const uint64_t node_size = runtime_config_.pgas_size /
                               runtime_config_.num_nodes;
    uint64_t end{};
    uint64_t pgas_end{};
    if (node_size == 0 || add_overflow(address, length, end) ||
        add_overflow(runtime_config_.pgas_base, runtime_config_.pgas_size,
                     pgas_end))
        return false;
    const uint64_t node0_begin = runtime_config_.pgas_base;
    const uint64_t node0_end = node0_begin + node_size;
    const uint64_t node1_begin = node0_end;
    const uint64_t node1_end = runtime_config_.num_nodes == 2
        ? pgas_end
        : (runtime_config_.num_nodes > 2 ? node1_begin + node_size
                                         : node1_begin);
    const uint64_t node0 = overlap_size(address, end, node0_begin, node0_end);
    const uint64_t node1 = overlap_size(address, end, node1_begin, node1_end);
    if (add) {
        uint64_t mapped{};
        uint64_t node0_total{};
        uint64_t node1_total{};
        if (add_overflow(inventory_.mapped_bytes, length, mapped) ||
            add_overflow(inventory_.node0_model_bytes, node0, node0_total) ||
            add_overflow(inventory_.node1_model_bytes, node1, node1_total))
            return false;
        inventory_.mapped_bytes = mapped;
        inventory_.node0_model_bytes = node0_total;
        inventory_.node1_model_bytes = node1_total;
    } else {
        if (inventory_.mapped_bytes < length ||
            inventory_.node0_model_bytes < node0 ||
            inventory_.node1_model_bytes < node1)
            return false;
        inventory_.mapped_bytes -= length;
        inventory_.node0_model_bytes -= node0;
        inventory_.node1_model_bytes -= node1;
    }
    return true;
}

void *pgas_model_mapper::map_fd(int fd, size_t length, off_t offset,
                                int &error)
{
    std::lock_guard guard(mutex_);
    error = 0;
    if (poisoned_) {
        reject_locked(EIO, error);
        return nullptr;
    }
    if (!matches_fd_locked(fd)) {
        reject_locked(EBADF, error);
        return nullptr;
    }
    if (length == 0 || offset < 0 ||
        (static_cast<uint64_t>(offset) & (config_.page_size - 1)) != 0) {
        reject_locked(EINVAL, error);
        return nullptr;
    }
    uint64_t file_end{};
    if (add_overflow(static_cast<uint64_t>(offset), length, file_end)) {
        reject_locked(EOVERFLOW, error);
        return nullptr;
    }
    if (file_end > file_size_) {
        reject_locked(EOVERFLOW, error);
        return nullptr;
    }
    if (file_end > config_.arena_size) {
        reject_locked(ENOSPC, error);
        return nullptr;
    }
    uint64_t address{};
    if (add_overflow(config_.arena_base, static_cast<uint64_t>(offset),
                     address)) {
        reject_locked(EOVERFLOW, error);
        return nullptr;
    }

    auto existing = std::find_if(
        views_.begin(), views_.end(), [&](const pgas_model_view &view) {
            return view.offset == offset && view.length == length &&
                   reinterpret_cast<uint64_t>(view.address) == address;
        });
    if (existing != views_.end()) {
        if (existing->references == UINT32_MAX) {
            reject_locked(EOVERFLOW, error);
            return nullptr;
        }
        ++existing->references;
        return existing->address;
    }
    if (inventory_.views == UINT32_MAX ||
        length > UINT64_MAX - inventory_.seeded_bytes ||
        !account_view_locked(address, length, true)) {
        reject_locked(EOVERFLOW, error);
        return nullptr;
    }
    // Reserve inventory atomically before any remote mutation.  Roll it back
    // on failure; seeded_bytes is published only after the entire view lands.
    account_view_locked(address, length, false);

    // Validate the complete file interval before publishing its first chunk.
    // This keeps truncation/short-read failures from partially changing an
    // existing overlapping view while retaining bounded staging memory.
    uint64_t validated{};
    while (validated < length) {
        const size_t chunk = static_cast<size_t>(std::min<uint64_t>(
            config_.seed_chunk_size, length - validated));
        size_t received{};
        while (received < chunk) {
            const ssize_t count = pread(
                fd, seed_buffer.data() + received, chunk - received,
                offset + static_cast<off_t>(validated + received));
            if (count < 0 && errno == EINTR)
                continue;
            if (count <= 0) {
                reject_locked(count == 0 ? EIO : errno, error);
                return nullptr;
            }
            received += static_cast<size_t>(count);
        }
        validated += chunk;
    }

    uint64_t completed{};
    while (completed < length) {
        const size_t chunk = static_cast<size_t>(std::min<uint64_t>(
            config_.seed_chunk_size, length - completed));
        size_t received{};
        while (received < chunk) {
            const ssize_t count = pread(
                fd, seed_buffer.data() + received, chunk - received,
                offset + static_cast<off_t>(completed + received));
            if (count < 0 && errno == EINTR)
                continue;
            if (count <= 0) {
                poisoned_ = true;
                inventory_.seeded_bytes += completed;
                reject_locked(count == 0 ? EIO : errno, error);
                return nullptr;
            }
            received += static_cast<size_t>(count);
        }
        const int result = pgas_x86_bulk_seed(
            config_.runtime, reinterpret_cast<void *>(address + completed),
            seed_buffer.data(), chunk);
        if (result != 0) {
            poisoned_ = true;
            inventory_.seeded_bytes += completed;
            reject_locked(result < 0 ? -result : result, error);
            return nullptr;
        }
        completed += chunk;
    }

    views_.push_back({ device_, inode_, offset, length,
                       reinterpret_cast<void *>(address), 1 });
    ++inventory_.views;
    inventory_.seeded_bytes += length;
    if (!account_view_locked(address, length, true)) {
        views_.pop_back();
        --inventory_.views;
        poisoned_ = true;
        reject_locked(EOVERFLOW, error);
        return nullptr;
    }
    return reinterpret_cast<void *>(address);
}

bool pgas_model_mapper::unmap(void *address, size_t length, int &error)
{
    std::lock_guard guard(mutex_);
    error = 0;
    const auto view = std::find_if(
        views_.begin(), views_.end(), [&](const pgas_model_view &candidate) {
            return candidate.address == address && candidate.length == length;
        });
    if (view == views_.end()) {
        error = EINVAL;
        return false;
    }
    if (--view->references != 0)
        return true;
    if (!account_view_locked(reinterpret_cast<uint64_t>(view->address),
                             view->length, false)) {
        error = EOVERFLOW;
        poisoned_ = true;
        return false;
    }
    views_.erase(view);
    --inventory_.views;
    return true;
}

pgas_model_inventory pgas_model_mapper::inventory() const
{
    std::lock_guard guard(mutex_);
    return inventory_;
}

pgas_model_mapper &pgas_global_model_mapper()
{
    static pgas_model_mapper mapper;
    return mapper;
}

} // namespace bpftime::attach

extern "C" {

void *pgas_model_map(int fd, size_t length, off_t offset, int *error_out)
{
    int error{};
    void *result = bpftime::attach::pgas_global_model_mapper().map_fd(
        fd, length, offset, error);
    if (error_out != nullptr)
        *error_out = error;
    return result;
}

int pgas_model_unmap(void *address, size_t length)
{
    int error{};
    return bpftime::attach::pgas_global_model_mapper().unmap(
        address, length, error) ? 0 : -error;
}

int pgas_model_get_inventory(struct pgas_model_inventory_c *out)
{
    if (out == nullptr)
        return -EINVAL;
    const auto inventory =
        bpftime::attach::pgas_global_model_mapper().inventory();
    *out = { inventory.mapped_bytes, inventory.seeded_bytes,
             inventory.node0_model_bytes, inventory.node1_model_bytes,
             inventory.rejected_mappings, inventory.dram_fallbacks,
             inventory.views };
    return 0;
}

} // extern "C"
