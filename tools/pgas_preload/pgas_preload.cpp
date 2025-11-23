// SPDX-License-Identifier: MIT
// PGAS LD_PRELOAD library for memcached
// Usage: LD_PRELOAD=libpgas_preload.so memcached [options]

#include "pgas_attach_impl.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <unistd.h>
#include <atomic>
#include <mutex>
#include <fstream>
#include <sstream>

using namespace bpftime::attach;

// Global state
static pgas_attach_impl *g_pgas_impl = nullptr;
static std::mutex g_mutex;
static bool g_initialized = false;

// Configuration
static uint16_t g_local_node_id = 0;
static uint16_t g_num_nodes = 1;
static uint64_t g_pgas_base = 0;
static uint64_t g_pgas_size = 1ULL << 30;  // 1GB default
static bool g_verbose = false;
static bool g_enable_stats = true;

// Statistics
static std::atomic<uint64_t> g_total_memcpy{0};
static std::atomic<uint64_t> g_total_memmove{0};
static std::atomic<uint64_t> g_total_memset{0};
static std::atomic<uint64_t> g_total_malloc{0};
static std::atomic<uint64_t> g_total_free{0};
static std::atomic<uint64_t> g_bytes_copied{0};
static std::atomic<uint64_t> g_local_accesses{0};
static std::atomic<uint64_t> g_remote_accesses{0};

// Hook IDs
static int g_memcpy_hook_id = -1;
static int g_memmove_hook_id = -1;
static int g_memset_hook_id = -1;

// Original function pointers (for fallback)
typedef void* (*memcpy_fn)(void*, const void*, size_t);
typedef void* (*memmove_fn)(void*, const void*, size_t);
typedef void* (*memset_fn)(void*, int, size_t);
typedef void* (*malloc_fn)(size_t);
typedef void (*free_fn)(void*);

static memcpy_fn orig_memcpy = nullptr;
static memmove_fn orig_memmove = nullptr;
static memset_fn orig_memset = nullptr;
static malloc_fn orig_malloc = nullptr;
static free_fn orig_free = nullptr;

// Load configuration from environment or file
static void load_config() {
    // Environment variables
    const char *env_node = getenv("PGAS_NODE_ID");
    if (env_node) {
        g_local_node_id = atoi(env_node);
    }

    const char *env_nodes = getenv("PGAS_NUM_NODES");
    if (env_nodes) {
        g_num_nodes = atoi(env_nodes);
    }

    const char *env_base = getenv("PGAS_BASE_ADDR");
    if (env_base) {
        g_pgas_base = strtoull(env_base, nullptr, 0);
    }

    const char *env_size = getenv("PGAS_SIZE");
    if (env_size) {
        g_pgas_size = strtoull(env_size, nullptr, 0);
    }

    const char *env_verbose = getenv("PGAS_VERBOSE");
    if (env_verbose && strcmp(env_verbose, "1") == 0) {
        g_verbose = true;
    }

    const char *env_stats = getenv("PGAS_STATS");
    if (env_stats && strcmp(env_stats, "0") == 0) {
        g_enable_stats = false;
    }

    // Config file (optional)
    const char *config_file = getenv("PGAS_CONFIG");
    if (config_file) {
        std::ifstream ifs(config_file);
        if (ifs.is_open()) {
            std::string line;
            while (std::getline(ifs, line)) {
                if (line.empty() || line[0] == '#') continue;

                std::istringstream iss(line);
                std::string key, value;
                if (std::getline(iss, key, '=') && std::getline(iss, value)) {
                    if (key == "node_id") g_local_node_id = atoi(value.c_str());
                    else if (key == "num_nodes") g_num_nodes = atoi(value.c_str());
                    else if (key == "base_addr") g_pgas_base = strtoull(value.c_str(), nullptr, 0);
                    else if (key == "size") g_pgas_size = strtoull(value.c_str(), nullptr, 0);
                    else if (key == "verbose") g_verbose = (value == "1" || value == "true");
                }
            }
        }
    }
}

// PGAS callback for memcpy
static int pgas_memcpy_callback(void *memory, size_t mem_size, uint64_t *ret) {
    (void)mem_size;
    (void)ret;
    auto *ctx = (pgas_memory_context *)memory;

    g_total_memcpy++;
    g_bytes_copied += ctx->size;

    if (ctx->is_remote) {
        g_remote_accesses++;
        if (g_verbose) {
            fprintf(stderr, "[PGAS] Remote memcpy: %p <- %p (%zu bytes) -> node %d\n",
                    ctx->address, ctx->data, ctx->size, ctx->target_node);
        }
        // TODO: Implement actual remote memory copy via CXL/RDMA
        // For now, the override handler performs local copy
    } else {
        g_local_accesses++;
    }

    return 0;
}

// PGAS callback for memmove
static int pgas_memmove_callback(void *memory, size_t mem_size, uint64_t *ret) {
    (void)mem_size;
    (void)ret;
    auto *ctx = (pgas_memory_context *)memory;

    g_total_memmove++;
    g_bytes_copied += ctx->size;

    if (ctx->is_remote) {
        g_remote_accesses++;
        if (g_verbose) {
            fprintf(stderr, "[PGAS] Remote memmove: %p <- %p (%zu bytes) -> node %d\n",
                    ctx->address, ctx->data, ctx->size, ctx->target_node);
        }
    } else {
        g_local_accesses++;
    }

    return 0;
}

// PGAS callback for memset
static int pgas_memset_callback(void *memory, size_t mem_size, uint64_t *ret) {
    (void)mem_size;
    (void)ret;
    auto *ctx = (pgas_memory_context *)memory;

    g_total_memset++;

    if (ctx->is_remote) {
        g_remote_accesses++;
        if (g_verbose) {
            fprintf(stderr, "[PGAS] Remote memset: %p (%zu bytes) -> node %d\n",
                    ctx->address, ctx->size, ctx->target_node);
        }
    } else {
        g_local_accesses++;
    }

    return 0;
}

// Print statistics
static void print_stats() {
    if (!g_enable_stats) return;

    fprintf(stderr, "\n=== PGAS Statistics ===\n");
    fprintf(stderr, "Node ID: %d / %d\n", g_local_node_id, g_num_nodes);
    fprintf(stderr, "memcpy calls: %lu\n", g_total_memcpy.load());
    fprintf(stderr, "memmove calls: %lu\n", g_total_memmove.load());
    fprintf(stderr, "memset calls: %lu\n", g_total_memset.load());
    fprintf(stderr, "Total bytes copied: %lu\n", g_bytes_copied.load());
    fprintf(stderr, "Local accesses: %lu\n", g_local_accesses.load());
    fprintf(stderr, "Remote accesses: %lu\n", g_remote_accesses.load());

    if (g_local_accesses + g_remote_accesses > 0) {
        double remote_pct = 100.0 * g_remote_accesses /
                           (g_local_accesses + g_remote_accesses);
        fprintf(stderr, "Remote access ratio: %.2f%%\n", remote_pct);
    }
    fprintf(stderr, "========================\n\n");
}

// Initialize PGAS hooks
static void init_pgas() {
    std::lock_guard<std::mutex> lock(g_mutex);

    if (g_initialized) return;

    // Load configuration
    load_config();

    fprintf(stderr, "[PGAS] Initializing PGAS preload library\n");
    fprintf(stderr, "[PGAS] Node: %d/%d, Base: 0x%lx, Size: %lu MB\n",
            g_local_node_id, g_num_nodes, g_pgas_base, g_pgas_size / (1024*1024));

    // Get original function pointers
    orig_memcpy = (memcpy_fn)dlsym(RTLD_NEXT, "memcpy");
    orig_memmove = (memmove_fn)dlsym(RTLD_NEXT, "memmove");
    orig_memset = (memset_fn)dlsym(RTLD_NEXT, "memset");
    orig_malloc = (malloc_fn)dlsym(RTLD_NEXT, "malloc");
    orig_free = (free_fn)dlsym(RTLD_NEXT, "free");

    // Create PGAS implementation
    g_pgas_impl = new pgas_attach_impl();
    g_pgas_impl->set_pgas_region(g_pgas_base, g_pgas_size);

    // Get addresses to hook
    void *memcpy_addr = dlsym(RTLD_DEFAULT, "memcpy");
    void *memmove_addr = dlsym(RTLD_DEFAULT, "memmove");
    void *memset_addr = dlsym(RTLD_DEFAULT, "memset");

    // Create memcpy hook
    if (memcpy_addr) {
        pgas_attach_private_data priv;
        priv.target_address = memcpy_addr;
        priv.op_type = pgas_op_type::MEMCPY;
        priv.local_node_id = g_local_node_id;
        priv.num_nodes = g_num_nodes;
        priv.pgas_base_addr = g_pgas_base;
        priv.pgas_size = g_pgas_size;

        g_memcpy_hook_id = g_pgas_impl->create_attach_with_ebpf_callback(
            pgas_memcpy_callback, priv, ATTACH_PGAS_MEMCPY);

        if (g_memcpy_hook_id >= 0) {
            fprintf(stderr, "[PGAS] Hooked memcpy at %p\n", memcpy_addr);
        }
    }

    // Create memmove hook
    if (memmove_addr && memmove_addr != memcpy_addr) {
        pgas_attach_private_data priv;
        priv.target_address = memmove_addr;
        priv.op_type = pgas_op_type::MEMMOVE;
        priv.local_node_id = g_local_node_id;
        priv.num_nodes = g_num_nodes;
        priv.pgas_base_addr = g_pgas_base;
        priv.pgas_size = g_pgas_size;

        g_memmove_hook_id = g_pgas_impl->create_attach_with_ebpf_callback(
            pgas_memmove_callback, priv, ATTACH_PGAS_MEMMOVE);

        if (g_memmove_hook_id >= 0) {
            fprintf(stderr, "[PGAS] Hooked memmove at %p\n", memmove_addr);
        }
    }

    // Create memset hook
    if (memset_addr) {
        pgas_attach_private_data priv;
        priv.target_address = memset_addr;
        priv.op_type = pgas_op_type::MEMSET;
        priv.local_node_id = g_local_node_id;
        priv.num_nodes = g_num_nodes;
        priv.pgas_base_addr = g_pgas_base;
        priv.pgas_size = g_pgas_size;

        g_memset_hook_id = g_pgas_impl->create_attach_with_ebpf_callback(
            pgas_memset_callback, priv, ATTACH_PGAS_MEMSET);

        if (g_memset_hook_id >= 0) {
            fprintf(stderr, "[PGAS] Hooked memset at %p\n", memset_addr);
        }
    }

    g_initialized = true;
    fprintf(stderr, "[PGAS] Initialization complete\n");
}

// Cleanup PGAS hooks
static void cleanup_pgas() {
    std::lock_guard<std::mutex> lock(g_mutex);

    if (!g_initialized) return;

    fprintf(stderr, "[PGAS] Shutting down...\n");

    // Print statistics
    print_stats();

    // Detach hooks
    if (g_pgas_impl) {
        if (g_memcpy_hook_id >= 0) {
            g_pgas_impl->detach_by_id(g_memcpy_hook_id);
        }
        if (g_memmove_hook_id >= 0) {
            g_pgas_impl->detach_by_id(g_memmove_hook_id);
        }
        if (g_memset_hook_id >= 0) {
            g_pgas_impl->detach_by_id(g_memset_hook_id);
        }

        delete g_pgas_impl;
        g_pgas_impl = nullptr;
    }

    g_initialized = false;
    fprintf(stderr, "[PGAS] Shutdown complete\n");
}

// Library constructor - called when library is loaded
__attribute__((constructor))
static void pgas_preload_init() {
    init_pgas();
}

// Library destructor - called when library is unloaded
__attribute__((destructor))
static void pgas_preload_fini() {
    cleanup_pgas();
}

// Signal handler for graceful shutdown
extern "C" void pgas_signal_handler(int sig) {
    fprintf(stderr, "[PGAS] Received signal %d\n", sig);
    print_stats();
}

// API for runtime control
extern "C" {

// Get current statistics
void pgas_get_stats(uint64_t *memcpy_calls, uint64_t *memmove_calls,
                    uint64_t *memset_calls, uint64_t *bytes_copied,
                    uint64_t *local_accesses, uint64_t *remote_accesses) {
    if (memcpy_calls) *memcpy_calls = g_total_memcpy.load();
    if (memmove_calls) *memmove_calls = g_total_memmove.load();
    if (memset_calls) *memset_calls = g_total_memset.load();
    if (bytes_copied) *bytes_copied = g_bytes_copied.load();
    if (local_accesses) *local_accesses = g_local_accesses.load();
    if (remote_accesses) *remote_accesses = g_remote_accesses.load();
}

// Reset statistics
void pgas_reset_stats() {
    g_total_memcpy = 0;
    g_total_memmove = 0;
    g_total_memset = 0;
    g_bytes_copied = 0;
    g_local_accesses = 0;
    g_remote_accesses = 0;
}

// Print statistics to stderr
void pgas_print_stats() {
    print_stats();
}

// Check if PGAS is initialized
int pgas_is_initialized() {
    return g_initialized ? 1 : 0;
}

// Get node configuration
void pgas_get_config(uint16_t *node_id, uint16_t *num_nodes,
                     uint64_t *base_addr, uint64_t *size) {
    if (node_id) *node_id = g_local_node_id;
    if (num_nodes) *num_nodes = g_num_nodes;
    if (base_addr) *base_addr = g_pgas_base;
    if (size) *size = g_pgas_size;
}

} // extern "C"
