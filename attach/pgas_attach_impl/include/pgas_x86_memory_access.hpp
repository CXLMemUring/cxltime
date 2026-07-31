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
    pgas_x86_register_class register_class{ pgas_x86_register_class::none };
    bool atomic{};
    bool executable_scalar_mov{};
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

pgas_x86_range_result pgas_x86_classify_range(uint64_t address,
                                               size_t width,
                                               uint64_t base,
                                               uint64_t region_size);

pgas_x86_segments pgas_x86_split_cachelines(uint64_t address, size_t width);

} // namespace bpftime::attach
