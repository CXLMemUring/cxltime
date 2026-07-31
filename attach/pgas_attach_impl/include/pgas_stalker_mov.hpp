// SPDX-License-Identifier: MIT
// Frida Stalker-based mov instruction interception for CXL PGAS
//
// This uses GumStalker to JIT-recompile basic blocks at runtime.
// For every mov/movzx/movsxd/movabs that has a memory operand with an
// effective address in [pgas_base, pgas_base + pgas_size), a callout is
// inserted that routes the access through CXLMemSim.
//
// Stalker overhead is significant (~5-20x), so this should only be
// enabled for targeted code regions via gum_stalker_follow/unfollow
// or the activate/deactivate gate.

#ifndef _PGAS_STALKER_MOV_HPP
#define _PGAS_STALKER_MOV_HPP

#include <frida-gum.h>
#include <cstddef>
#include <cstdint>
#include <atomic>
#include <mutex>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handle
typedef struct pgas_stalker_ctx pgas_stalker_ctx_t;

// Configuration
typedef struct {
    uint64_t pgas_base_addr;       // Start of CXL address range
    uint64_t pgas_region_size;     // Size of CXL address range
    uint16_t local_node_id;        // This node's ID
    uint16_t num_nodes;            // Total nodes in cluster
    int      trust_threshold;      // Stalker trust threshold (0 = recompile always, -1 = trust after first run)
    bool     hook_mov;             // Hook mov/movabs (default: true)
    bool     hook_movzx;           // Hook movzx/movsxd (default: true)
    bool     hook_movnti;          // Hook non-temporal stores (default: true)
    bool     hook_rep_movs;        // Hook rep movsb/movsq (default: true)
    bool     verbose;              // Print instrumented instructions
    const char *include_modules;   // Exact ELF basenames, comma-separated
    bool     strict_validation;    // Fail validation on incomplete coverage
} pgas_stalker_config_t;

// Statistics
typedef struct {
    uint64_t blocks_transformed;   // Basic blocks JIT-recompiled
    uint64_t insns_scanned;        // Total instructions scanned
    uint64_t mov_loads_hooked;     // Memory load movs instrumented
    uint64_t mov_stores_hooked;    // Memory store movs instrumented
    uint64_t callouts_fired;       // Runtime callouts entered
    uint64_t remote_loads;         // Actual remote loads executed
    uint64_t remote_stores;        // Actual remote stores executed
    uint64_t local_passthrough;    // Local accesses (no-op callout)
} pgas_stalker_stats_t;

typedef struct {
    uint64_t runtime_id;
    uint64_t os_tid;
    uint64_t remote_loads;
    uint64_t remote_stores;
    uint64_t bytes_read;
    uint64_t bytes_written;
    uint64_t cross_line_splits;
    uint64_t unsupported;
    uint64_t failures;
    uint64_t follow_events;
    uint64_t unfollow_events;
} pgas_stalker_thread_stats_t;

// Initialize stalker context (call after gum_init_embedded())
pgas_stalker_ctx_t *pgas_stalker_init(const pgas_stalker_config_t *config);

// Start stalking the current thread
// All basic blocks will be JIT-recompiled with mov interception
int pgas_stalker_follow_me(pgas_stalker_ctx_t *ctx);

// Start stalking a specific thread
int pgas_stalker_follow(pgas_stalker_ctx_t *ctx, GumThreadId thread_id);

// Stop stalking current thread
void pgas_stalker_unfollow_me(pgas_stalker_ctx_t *ctx);

// Stop stalking a specific thread
void pgas_stalker_unfollow(pgas_stalker_ctx_t *ctx, GumThreadId thread_id);

// Activate/deactivate gate: only stalk between activate/deactivate calls
// target = address of the "gate" function; stalker starts when execution
// hits this address and stops when deactivate is called
void pgas_stalker_activate(pgas_stalker_ctx_t *ctx, const void *target);
void pgas_stalker_deactivate(pgas_stalker_ctx_t *ctx);

// Exclude a memory range from stalking (e.g., libc, Frida itself)
void pgas_stalker_exclude(pgas_stalker_ctx_t *ctx, uint64_t base, uint64_t size);

// Get statistics
void pgas_stalker_get_stats(pgas_stalker_ctx_t *ctx, pgas_stalker_stats_t *stats);

// Return the total record count and copy up to capacity records when output is
// non-null. Runtime IDs are stable for the context lifetime.
size_t pgas_stalker_snapshot_threads(pgas_stalker_ctx_t *ctx,
                                     pgas_stalker_thread_stats_t *output,
                                     size_t capacity);

// Apply the same exact-basename policy used by translated code to a creator.
int pgas_stalker_should_follow_creator(pgas_stalker_ctx_t *ctx,
                                       const char *module_path);

// Return nonzero when strict coverage and per-thread invariants are valid.
int pgas_stalker_strict_valid(pgas_stalker_ctx_t *ctx);

// Print statistics
void pgas_stalker_print_stats(pgas_stalker_ctx_t *ctx);

// Cleanup
void pgas_stalker_finalize(pgas_stalker_ctx_t *ctx);

#ifdef __cplusplus
}

namespace bpftime::attach {

bool pgas_x86_emit_range_gate(GumX86Writer *writer,
                              GumX86Reg address_register,
                              GumX86Reg scratch_start,
                              GumX86Reg scratch_end,
                              GumX86Reg scratch_bound, int64_t displacement,
                              uint8_t width,
                              uint64_t pgas_base, uint64_t pgas_size,
                              gconstpointer inside_label,
                              gconstpointer outside_label,
                              gconstpointer partial_label,
                              gconstpointer overflow_label);

} // namespace bpftime::attach
#endif

#endif // _PGAS_STALKER_MOV_HPP
