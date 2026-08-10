// SPDX-License-Identifier: MIT
#pragma once

#include "pgas_model_mapping.h"
#include "pgas_x86_memory_access.hpp"

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <sys/types.h>
#include <vector>

namespace bpftime::attach {

struct pgas_model_mapping_config {
    std::string file;
    uint64_t arena_base{};
    uint64_t arena_size{};
    size_t page_size{};
    size_t seed_chunk_size{ 64 * 1024 };
    pgas_x86_runtime *runtime{};
};

struct pgas_model_view {
    dev_t device{};
    ino_t inode{};
    off_t offset{};
    size_t length{};
    void *address{};
    uint32_t references{};
};

struct pgas_model_interval {
    uint64_t begin{};
    uint64_t end{};
};

struct pgas_model_inventory {
    uint64_t mapped_bytes{};
    uint64_t seeded_bytes{};
    uint64_t node0_model_bytes{};
    uint64_t node1_model_bytes{};
    uint64_t rejected_mappings{};
    uint64_t dram_fallbacks{};
    uint64_t refresh_calls{};
    uint64_t refresh_requested_bytes{};
    uint64_t refreshed_bytes{};
    uint64_t refresh_failures{};
    uint32_t views{};
};

class pgas_model_mapper {
  public:
    int configure(const pgas_model_mapping_config &config);
    bool matches_fd(int fd) const;
    void *map_fd(int fd, size_t length, off_t offset, int &error);
    bool unmap(void *address, size_t length, int &error);
    int refresh_all();
    pgas_model_inventory inventory() const;

  private:
    bool matches_fd_locked(int fd) const;
    void reject_locked(int error, int &error_out);
    bool account_view_locked(uint64_t address, uint64_t length, bool add);
    bool account_seeded_locked(uint64_t offset, uint64_t length);

    mutable std::mutex mutex_;
    pgas_model_mapping_config config_{};
    pgas_x86_runtime_config runtime_config_{};
    dev_t device_{};
    ino_t inode_{};
    uint64_t file_size_{};
    bool configured_{};
    bool poisoned_{};
    std::vector<pgas_model_view> views_;
    std::vector<pgas_model_interval> seeded_intervals_;
    pgas_model_inventory inventory_{};
};

pgas_model_mapper &pgas_global_model_mapper();

} // namespace bpftime::attach
