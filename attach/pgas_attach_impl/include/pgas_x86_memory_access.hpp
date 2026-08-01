// SPDX-License-Identifier: MIT
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace bpftime::attach {

enum class pgas_x86_range_result { outside, inside, partial, overflow };

enum class pgas_x86_access_class {
    read,
    write,
    read_modify_write,
    prefetch,
    unsupported
};

enum class pgas_x86_register_class { none, gpr, xmm, ymm, zmm };

struct pgas_x86_memory_descriptor {
    uint64_t instruction_address{};
    unsigned instruction_id{};
    char mnemonic[32]{};
    pgas_x86_access_class access_class{ pgas_x86_access_class::unsupported };
    uint8_t memory_operand_index{};
    uint8_t width{};
    int base_register{};
    int index_register{};
    int scale{};
    int64_t displacement{};
    int data_register{};
    int vector_index_register{};
    int mask_register{};
    pgas_x86_register_class register_class{ pgas_x86_register_class::none };
    uint8_t lane_width{};
    uint8_t index_width{};
    uint8_t lane_count{};
    bool atomic{};
    bool replayable{};
    bool gather{};
    bool scatter{};
};

struct pgas_x86_segment {
    uint64_t address{};
    uint8_t offset{};
    uint8_t size{};
};

struct pgas_x86_segments {
    std::array<pgas_x86_segment, 2> value{};
    uint8_t count{};
};

struct pgas_x86_transport {
    int (*read)(void *, uint16_t, uint64_t, void *, size_t){};
    int (*write)(void *, uint16_t, uint64_t, const void *, size_t){};
    void *opaque{};
};

struct pgas_x86_failure;
using pgas_x86_fail_fn = void (*)(void *, const pgas_x86_failure &);

struct pgas_x86_failure {
    uint64_t thread_id{};
    uint64_t instruction_address{};
    unsigned instruction_id{};
    char mnemonic[32]{};
    pgas_x86_access_class access_class{ pgas_x86_access_class::unsupported };
    uint64_t effective_address{};
    size_t width{};
    uint8_t segment_index{};
    uint16_t target_node{};
    int transport_error{};
};

struct pgas_x86_runtime_config {
    uint64_t pgas_base{};
    uint64_t pgas_size{};
    uint16_t local_node_id{};
    uint16_t num_nodes{};
    pgas_x86_transport transport{};
    pgas_x86_fail_fn fail{};
    void *fail_opaque{};
};

struct pgas_x86_runtime;

struct pgas_x86_access_event {
    const pgas_x86_memory_descriptor *descriptor{};
    uint64_t effective_address{};
    uint16_t target_node{};
    pgas_x86_segments segments{};
    std::array<uint16_t, 2> lock_stripes{};
    uint8_t lock_count{};
    bool locks_held{};
    pgas_x86_runtime *runtime{};
};

pgas_x86_range_result pgas_x86_classify_range(uint64_t address,
                                               size_t width,
                                               uint64_t base,
                                               uint64_t region_size);

pgas_x86_segments pgas_x86_split_cachelines(uint64_t address, size_t width);

pgas_x86_runtime *
pgas_x86_runtime_create(const pgas_x86_runtime_config &config);
void pgas_x86_runtime_destroy(pgas_x86_runtime *runtime);

int pgas_x86_begin_load(pgas_x86_runtime *runtime,
                        pgas_x86_access_event *event);
int pgas_x86_begin_store(pgas_x86_runtime *runtime,
                         pgas_x86_access_event *event, const void *source,
                         size_t source_size);
void pgas_x86_finish_access(pgas_x86_access_event *event);

// Internal bridge used by the bounded replay transaction implementation.
int pgas_x86_runtime_lock_lines(pgas_x86_runtime *runtime,
                                const uint64_t *lines, size_t line_count,
                                uint16_t *stripes, size_t stripe_capacity,
                                uint16_t &acquired);
void pgas_x86_runtime_unlock_lines(pgas_x86_runtime *runtime,
                                   const uint16_t *stripes,
                                   uint16_t acquired);
int pgas_x86_runtime_read(pgas_x86_runtime *runtime, uint16_t node,
                          uint64_t address, void *destination, size_t size);
int pgas_x86_runtime_write(pgas_x86_runtime *runtime, uint16_t node,
                           uint64_t address, const void *source, size_t size);

} // namespace bpftime::attach
