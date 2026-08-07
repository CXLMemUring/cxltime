// SPDX-License-Identifier: MIT
// Integration between PGAS attach hooks and CXLMemSim client
// This enables transparent ld/st hooking that routes to CXLMemSim server

#ifndef _PGAS_CXLMEMSIM_INTEGRATION_HPP
#define _PGAS_CXLMEMSIM_INTEGRATION_HPP

#include "pgas_attach_impl.hpp"
#include "pgas_x86_memory_access.hpp"
#include "cxlmemsim_client.h"
#include <memory>
#include <atomic>
#include <unordered_map>
#include <mutex>

namespace bpftime {
namespace attach {

// CXLMemSim connection manager for remote nodes
class cxlmemsim_connection_manager {
public:
    static cxlmemsim_connection_manager& instance() {
        static cxlmemsim_connection_manager mgr;
        return mgr;
    }

    // Initialize connections to CXLMemSim servers
    int init(const std::vector<pgas_node_info>& nodes, uint16_t local_node_id,
             bool eager_connect = false);

    // Get connection for a specific node
    cxlmemsim_ctx_t* get_connection(uint16_t node_id);

    // Check if node is local
    bool is_local(uint16_t node_id) const {
        return node_id == local_node_id_;
    }

    // Get local node ID
    uint16_t local_node_id() const { return local_node_id_; }

    // Shutdown all connections
    void shutdown();

    // Statistics
    struct stats {
        uint64_t local_reads = 0;
        uint64_t local_writes = 0;
        uint64_t remote_reads = 0;
        uint64_t remote_writes = 0;
        uint64_t remote_bytes_read = 0;
        uint64_t remote_bytes_written = 0;
        uint64_t total_remote_latency_ns = 0;
    };

    stats get_stats() const;
    void reset_stats();

private:
    cxlmemsim_connection_manager() = default;
    ~cxlmemsim_connection_manager() { shutdown(); }

    int connect_node_locked(uint16_t node_id);

    std::unordered_map<uint16_t, pgas_node_info> node_configs_;
    std::unordered_map<uint16_t, std::unique_ptr<cxlmemsim_ctx_t>> connections_;
    uint16_t local_node_id_ = 0;
    mutable std::mutex mutex_;

    // Statistics
    mutable stats stats_;
    mutable std::mutex stats_mutex_;

    friend class pgas_cxlmemsim_hooker;
};

// PGAS hooker with CXLMemSim integration
class pgas_cxlmemsim_hooker {
public:
    // Configuration for hooking
    struct config {
        uint16_t local_node_id = 0;
        uint16_t num_nodes = 2;
        uint64_t pgas_base_addr = 0;
        uint64_t pgas_region_size = 0;
        std::vector<pgas_node_info> nodes;

        // Hook targets (functions to intercept)
        bool hook_memcpy = true;
        bool hook_memmove = true;
        bool hook_memset = true;
        bool hook_custom_functions = false;

        // Behavior options
        bool enable_local_cache = false;
        bool enable_statistics = true;
        bool eager_connect = false;
        bool use_node_local_offsets = true;
    };

    static pgas_cxlmemsim_hooker& instance() {
        static pgas_cxlmemsim_hooker hooker;
        return hooker;
    }

    // Initialize the hooker
    int init(const config& cfg);

    // Install hooks
    int install_hooks();

    // Remove hooks
    void remove_hooks();

    // Manual remote access (for direct use without hooking)
    int remote_read(uint16_t node_id, uint64_t addr, void* dest, size_t size);
    int remote_write(uint16_t node_id, uint64_t addr, const void* src, size_t size);

    // Address translation
    uint16_t addr_to_node(uint64_t addr) const;
    uint64_t translate_addr(uint64_t local_addr, uint16_t target_node) const;

    // Check if address is in PGAS region
    bool is_pgas_addr(uint64_t addr) const {
        return addr >= config_.pgas_base_addr &&
               addr < config_.pgas_base_addr + config_.pgas_region_size;
    }

    // Get configuration
    const config& get_config() const { return config_; }
    pgas_x86_runtime *acquire_x86_runtime();
    void release_x86_runtime_user(pgas_x86_runtime *runtime);
    bool touches_pgas(uint64_t address, size_t size) const;
    void release_x86_runtime();

    // Print statistics
    void print_stats() const;

private:
    pgas_cxlmemsim_hooker() = default;
    ~pgas_cxlmemsim_hooker() { remove_hooks(); release_x86_runtime(); }

    config config_;
    std::unique_ptr<pgas_attach_impl> attach_impl_;
    bool initialized_ = false;
    bool hooks_installed_ = false;
    pgas_x86_runtime *x86_runtime_ = nullptr;
    std::atomic<uint64_t> x86_runtime_users_{};
    std::atomic<bool> x86_runtime_accepting_{};
};

// Override callback that routes to CXLMemSim
// Called from Frida hooks when remote access is detected
int pgas_remote_memcpy_handler(void* dest, const void* src, size_t n,
                                uint16_t target_node, bool dest_is_remote);

int pgas_remote_memset_handler(void* s, int c, size_t n, uint16_t target_node);

// Helper functions for setting up hooks easily
namespace hooks {

// Initialize PGAS hooking with CXLMemSim backend
// config_file: Path to PGAS/CXLMemSim configuration file
int init_from_config(const std::string& config_file);

// Initialize with manual configuration
int init(uint16_t local_node_id, uint16_t num_nodes,
         const std::vector<std::pair<std::string, int>>& server_addresses,
         uint64_t pgas_base_addr, uint64_t pgas_size);

// Start intercepting memory operations
int start();

// Stop intercepting
void stop();

// Check if hooking is active
bool is_active();

// Get statistics
cxlmemsim_connection_manager::stats get_stats();

// Finalize and cleanup
void finalize();

} // namespace hooks

pgas_x86_transport pgas_cxlmemsim_x86_transport();
pgas_x86_runtime *pgas_cxlmemsim_acquire_x86_runtime();
void pgas_cxlmemsim_release_x86_runtime_user(pgas_x86_runtime *runtime);

} // namespace attach
} // namespace bpftime

// C interface for easier integration
extern "C" {

// Initialize PGAS CXLMemSim hooking
int pgas_hook_init(const char* config_file);

// Start hooks
int pgas_hook_start(void);

// Stop hooks
void pgas_hook_stop(void);

// Manual remote operations
int pgas_hook_remote_read(uint16_t node_id, uint64_t addr,
                           void* dest, size_t size);
int pgas_hook_remote_write(uint16_t node_id, uint64_t addr,
                            const void* src, size_t size);

// Finalize
void pgas_hook_finalize(void);

// Statistics
void pgas_hook_print_stats(void);

} // extern "C"

#endif // _PGAS_CXLMEMSIM_INTEGRATION_HPP
