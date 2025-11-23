// SPDX-License-Identifier: MIT
// PGAS Memory Hook Demo
// Demonstrates using Frida to intercept memory operations and route through PGAS

#include "pgas_attach_impl.hpp"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <dlfcn.h>
#include <atomic>

using namespace bpftime::attach;

// Statistics
static std::atomic<uint64_t> total_bytes_copied{0};
static std::atomic<uint64_t> local_ops{0};
static std::atomic<uint64_t> remote_ops{0};
static std::atomic<uint64_t> node_accesses[4] = {0, 0, 0, 0};

// PGAS configuration
static uint16_t local_node_id = 0;
static uint16_t num_nodes = 4;

// Simulated PGAS region (1GB starting at this address)
static uint64_t pgas_base = 0;
static uint64_t pgas_size = 1ULL << 30;  // 1GB

// Demo data structures
struct key_value_item {
    char key[64];
    char value[256];
    uint64_t cas_unique;
    uint32_t flags;
    uint32_t exptime;
};

// Simulated hash table for demo
#define HASH_TABLE_SIZE 1024
static key_value_item* hash_table[HASH_TABLE_SIZE];

// Simple hash function
static uint32_t hash_key(const char *key) {
    uint32_t hash = 5381;
    int c;
    while ((c = *key++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash % HASH_TABLE_SIZE;
}

// PGAS callback for memcpy operations
static int pgas_memcpy_callback(void *memory, size_t mem_size, uint64_t *ret) {
    auto *ctx = (pgas_memory_context *)memory;

    // Update statistics
    total_bytes_copied += ctx->size;

    if (ctx->is_remote) {
        remote_ops++;
        printf("[PGAS] Remote memcpy: %zu bytes to node %d\n",
               ctx->size, ctx->target_node);
    } else {
        local_ops++;
    }

    if (ctx->target_node < 4) {
        node_accesses[ctx->target_node]++;
    }

    return 0;
}

// PGAS callback for store operations
static int pgas_store_callback(void *memory, size_t mem_size, uint64_t *ret) {
    auto *ctx = (pgas_memory_context *)memory;

    printf("[PGAS] Store: addr=%p size=%zu node=%d %s\n",
           ctx->address, ctx->size, ctx->target_node,
           ctx->is_remote ? "(REMOTE)" : "(LOCAL)");

    return 0;
}

// Demo functions that will be hooked
void demo_store_item(const char *key, const char *value) {
    uint32_t bucket = hash_key(key);

    // Allocate item (in real PGAS, this would be remote allocation)
    auto *item = (key_value_item *)malloc(sizeof(key_value_item));

    // These memcpy calls will be intercepted by PGAS hooks
    memcpy(item->key, key, strlen(key) + 1);
    memcpy(item->value, value, strlen(value) + 1);

    item->cas_unique = rand();
    item->flags = 0;
    item->exptime = 0;

    // Free old item if exists
    if (hash_table[bucket]) {
        free(hash_table[bucket]);
    }

    hash_table[bucket] = item;
    printf("Stored: key='%s' value='%s' bucket=%d\n", key, value, bucket);
}

const char* demo_get_item(const char *key) {
    uint32_t bucket = hash_key(key);
    auto *item = hash_table[bucket];

    if (item && strcmp(item->key, key) == 0) {
        // This access will be intercepted
        static char result[256];
        memcpy(result, item->value, strlen(item->value) + 1);
        return result;
    }

    return nullptr;
}

void demo_bulk_copy(void *dest, const void *src, size_t n) {
    // Large bulk copy - will be intercepted and potentially split
    // across multiple nodes in a real PGAS implementation
    memcpy(dest, src, n);
}

int main(int argc, char *argv[]) {
    printf("=== PGAS Memory Hook Demo ===\n\n");

    // Parse command line arguments
    if (argc > 1) {
        local_node_id = atoi(argv[1]);
    }
    if (argc > 2) {
        num_nodes = atoi(argv[2]);
    }

    printf("Configuration:\n");
    printf("  Local node ID: %d\n", local_node_id);
    printf("  Total nodes: %d\n", num_nodes);
    printf("  PGAS region: 0x%lx - 0x%lx (%lu MB)\n",
           pgas_base, pgas_base + pgas_size, pgas_size / (1024*1024));
    printf("\n");

    // Initialize PGAS attach implementation
    pgas_attach_impl pgas_impl;
    pgas_impl.set_pgas_region(pgas_base, pgas_size);

    // Hook memcpy for PGAS interception
    printf("Installing PGAS hooks...\n");

    // Get address of memcpy
    void *memcpy_addr = dlsym(RTLD_DEFAULT, "memcpy");
    if (!memcpy_addr) {
        fprintf(stderr, "Failed to find memcpy\n");
        return 1;
    }

    // Create memcpy hook
    pgas_attach_private_data memcpy_priv;
    memcpy_priv.target_address = memcpy_addr;
    memcpy_priv.op_type = pgas_op_type::MEMCPY;
    memcpy_priv.local_node_id = local_node_id;
    memcpy_priv.num_nodes = num_nodes;
    memcpy_priv.pgas_base_addr = pgas_base;
    memcpy_priv.pgas_size = pgas_size;

    int memcpy_hook_id = pgas_impl.create_attach_with_ebpf_callback(
        pgas_memcpy_callback, memcpy_priv, ATTACH_PGAS_MEMCPY);

    if (memcpy_hook_id < 0) {
        fprintf(stderr, "Failed to create memcpy hook: %d\n", memcpy_hook_id);
        return 1;
    }

    printf("Installed memcpy hook (id=%d)\n\n", memcpy_hook_id);

    // Initialize hash table
    memset(hash_table, 0, sizeof(hash_table));

    // Demo: Store some key-value pairs
    printf("--- Storing items ---\n");
    demo_store_item("user:1001", "Alice");
    demo_store_item("user:1002", "Bob");
    demo_store_item("user:1003", "Charlie");
    demo_store_item("session:abc123", "user:1001");
    demo_store_item("cache:homepage", "<html>...</html>");
    printf("\n");

    // Demo: Retrieve items
    printf("--- Retrieving items ---\n");
    const char *value = demo_get_item("user:1001");
    if (value) {
        printf("Got user:1001 = '%s'\n", value);
    }

    value = demo_get_item("session:abc123");
    if (value) {
        printf("Got session:abc123 = '%s'\n", value);
    }
    printf("\n");

    // Demo: Bulk copy (simulates large data transfer)
    printf("--- Bulk copy operation ---\n");
    char *large_src = (char *)malloc(64 * 1024);
    char *large_dest = (char *)malloc(64 * 1024);
    memset(large_src, 'X', 64 * 1024);

    demo_bulk_copy(large_dest, large_src, 64 * 1024);
    printf("Bulk copied 64KB\n\n");

    free(large_src);
    free(large_dest);

    // Print statistics
    printf("=== PGAS Statistics ===\n");
    printf("Total bytes copied: %lu\n", total_bytes_copied.load());
    printf("Local operations: %lu\n", local_ops.load());
    printf("Remote operations: %lu\n", remote_ops.load());
    printf("\nPer-node access counts:\n");
    for (int i = 0; i < 4; i++) {
        printf("  Node %d: %lu accesses\n", i, node_accesses[i].load());
    }

    // Cleanup
    printf("\nCleaning up...\n");
    pgas_impl.detach_by_id(memcpy_hook_id);

    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        if (hash_table[i]) {
            free(hash_table[i]);
        }
    }

    printf("Done!\n");
    return 0;
}
