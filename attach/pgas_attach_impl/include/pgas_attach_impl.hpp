// SPDX-License-Identifier: MIT
// PGAS Attach Implementation using Frida for CXL memory operations
#ifndef _PGAS_ATTACH_IMPL_HPP
#define _PGAS_ATTACH_IMPL_HPP

#include "base_attach_impl.hpp"
#include "pgas_attach_private_data.hpp"
#include <frida-gum.h>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <functional>
#include <atomic>

namespace bpftime {
namespace attach {

// Forward declarations
class pgas_internal_attach_entry;

// PGAS memory context passed to callbacks
struct pgas_memory_context {
    void *address;          // Memory address being accessed
    size_t size;            // Size of access
    pgas_op_type op_type;   // Type of operation
    uint16_t target_node;   // Target node for this address
    uint16_t local_node;    // Local node ID
    void *data;             // Data buffer (for stores)
    uint64_t old_value;     // Old value (for CAS)
    uint64_t new_value;     // New value (for CAS/atomic ops)
    bool is_remote;         // True if accessing remote node
};

// Callback type for PGAS operations
using pgas_operation_callback = std::function<int(pgas_memory_context &ctx)>;

// PGAS attach entry (user-facing)
class pgas_attach_entry {
public:
    int id;
    pgas_op_type op_type;
    ebpf_run_callback ebpf_callback;
    pgas_operation_callback pgas_callback;

    pgas_attach_entry(int id, pgas_op_type op_type)
        : id(id), op_type(op_type) {}
};

// Internal attach entry for a hooked function
class pgas_internal_attach_entry {
public:
    void *function;
    GumInvocationListener *listener;
    std::vector<pgas_attach_entry*> user_attaches;

    // PGAS configuration
    uint16_t local_node_id;
    uint16_t num_nodes;
    uint64_t pgas_base_addr;
    uint64_t pgas_size;

    // Override state
    bool is_overrided;
    uint64_t user_ret;

    pgas_internal_attach_entry(void *func, uint16_t local_node, uint16_t num_nodes,
                                uint64_t base_addr, uint64_t size);
    ~pgas_internal_attach_entry();

    void add_attach(pgas_attach_entry *entry);
    void remove_attach(pgas_attach_entry *entry);
    bool has_attaches() const { return !user_attaches.empty(); }

    // Route address to node
    uint16_t route_to_node(uint64_t addr) const;

    // Execute callbacks
    void execute_load_callbacks(void *addr, size_t size, void *dest);
    void execute_store_callbacks(void *addr, size_t size, const void *src);
    void execute_memcpy_callbacks(void *dest, const void *src, size_t size);
};

// Main PGAS attach implementation
class pgas_attach_impl : public base_attach_impl {
public:
    pgas_attach_impl();
    ~pgas_attach_impl();

    // Base class interface
    int detach_by_id(int id) override;

    int create_attach_with_ebpf_callback(
        ebpf_run_callback &&cb,
        const attach_private_data &private_data,
        int attach_type) override;

    void register_custom_helpers(
        ebpf_helper_register_callback register_callback) override;

    // PGAS-specific methods
    int create_pgas_hook(
        const pgas_attach_private_data &priv,
        ebpf_run_callback &&cb);

    int create_load_hook(void *func_addr, uint16_t local_node, uint16_t num_nodes);
    int create_store_hook(void *func_addr, uint16_t local_node, uint16_t num_nodes);
    int create_memcpy_hook(void *func_addr, uint16_t local_node, uint16_t num_nodes);

    // Set PGAS memory region
    void set_pgas_region(uint64_t base_addr, uint64_t size);

    // Get statistics
    uint64_t get_local_accesses() const { return local_accesses.load(); }
    uint64_t get_remote_accesses() const { return remote_accesses.load(); }

private:
    GumInterceptor *interceptor;

    // User-facing attaches (id -> entry)
    std::unordered_map<int, std::unique_ptr<pgas_attach_entry>> attaches;

    // Internal attaches per function address
    std::unordered_map<void*, std::unique_ptr<pgas_internal_attach_entry>> internal_attaches;

    // PGAS configuration
    uint64_t pgas_base_addr;
    uint64_t pgas_size;
    uint16_t local_node_id;
    uint16_t num_nodes;

    // Statistics
    std::atomic<uint64_t> local_accesses{0};
    std::atomic<uint64_t> remote_accesses{0};

    std::mutex mutex;

    // Helper methods
    void *resolve_symbol(const std::string &module, const std::string &symbol);
    pgas_internal_attach_entry* get_or_create_internal_entry(
        void *addr, uint16_t local_node, uint16_t num_nodes);
};

// Attach type constants for PGAS
constexpr int ATTACH_PGAS_LOAD = 2001;
constexpr int ATTACH_PGAS_STORE = 2002;
constexpr int ATTACH_PGAS_ATOMIC = 2003;
constexpr int ATTACH_PGAS_MEMCPY = 2004;
constexpr int ATTACH_PGAS_MEMMOVE = 2005;
constexpr int ATTACH_PGAS_MEMSET = 2006;

} // namespace attach
} // namespace bpftime

#endif // _PGAS_ATTACH_IMPL_HPP
