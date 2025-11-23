// SPDX-License-Identifier: MIT
// PGAS Attach Private Data for CXL memory operations
#ifndef _PGAS_ATTACH_PRIVATE_DATA_HPP
#define _PGAS_ATTACH_PRIVATE_DATA_HPP

#include "attach_private_data.hpp"
#include <string>
#include <cstdint>
#include <vector>
#include <sstream>

namespace bpftime {
namespace attach {

// PGAS memory operation types
enum class pgas_op_type {
    LOAD,           // Memory read operation
    STORE,          // Memory write operation
    ATOMIC_ADD,     // Atomic addition
    ATOMIC_CAS,     // Compare and swap
    FENCE,          // Memory fence
    MEMCPY,         // Block memory copy
    MEMMOVE,        // Block memory move
    MEMSET          // Block memory set
};

// PGAS node information
struct pgas_node_info {
    uint16_t node_id;
    uint64_t base_addr;
    uint64_t size;
    std::string hostname;
    uint16_t port;
};

// PGAS attach configuration
struct pgas_attach_private_data final : public attach_private_data {
    // Target function/address to hook
    void *target_address = nullptr;
    std::string module_name;
    uint64_t module_offset = 0;
    std::string symbol_name;

    // PGAS configuration
    uint16_t local_node_id = 0;
    uint16_t num_nodes = 1;
    std::vector<pgas_node_info> nodes;

    // Memory region configuration
    uint64_t pgas_base_addr = 0;
    uint64_t pgas_size = 0;

    // Hook type
    pgas_op_type op_type = pgas_op_type::LOAD;

    // Consistency model
    bool enable_coherence = true;
    bool enable_caching = false;

    int initialize_from_string(const std::string_view &sv) override {
        // Parse format: "module:symbol:op_type:node_id:num_nodes"
        // or "address:op_type:node_id:num_nodes"
        std::string str(sv);
        std::istringstream iss(str);
        std::string token;
        std::vector<std::string> tokens;

        while (std::getline(iss, token, ':')) {
            tokens.push_back(token);
        }

        if (tokens.size() < 3) {
            return -EINVAL;
        }

        // Check if first token is a hex address
        if (tokens[0].find("0x") == 0 || tokens[0].find("0X") == 0) {
            target_address = (void *)std::stoull(tokens[0], nullptr, 16);
        } else {
            module_name = tokens[0];
            if (tokens.size() > 1) {
                symbol_name = tokens[1];
            }
        }

        // Parse operation type
        size_t op_idx = (module_name.empty()) ? 1 : 2;
        if (tokens.size() > op_idx) {
            std::string op_str = tokens[op_idx];
            if (op_str == "load") op_type = pgas_op_type::LOAD;
            else if (op_str == "store") op_type = pgas_op_type::STORE;
            else if (op_str == "atomic_add") op_type = pgas_op_type::ATOMIC_ADD;
            else if (op_str == "atomic_cas") op_type = pgas_op_type::ATOMIC_CAS;
            else if (op_str == "fence") op_type = pgas_op_type::FENCE;
            else if (op_str == "memcpy") op_type = pgas_op_type::MEMCPY;
            else if (op_str == "memmove") op_type = pgas_op_type::MEMMOVE;
            else if (op_str == "memset") op_type = pgas_op_type::MEMSET;
        }

        // Parse node configuration
        if (tokens.size() > op_idx + 1) {
            local_node_id = std::stoi(tokens[op_idx + 1]);
        }
        if (tokens.size() > op_idx + 2) {
            num_nodes = std::stoi(tokens[op_idx + 2]);
        }

        return 0;
    }

    std::string to_string() const override {
        std::ostringstream oss;
        if (!module_name.empty()) {
            oss << module_name << ":" << symbol_name;
        } else {
            oss << "0x" << std::hex << (uint64_t)target_address;
        }

        oss << ":";
        switch (op_type) {
            case pgas_op_type::LOAD: oss << "load"; break;
            case pgas_op_type::STORE: oss << "store"; break;
            case pgas_op_type::ATOMIC_ADD: oss << "atomic_add"; break;
            case pgas_op_type::ATOMIC_CAS: oss << "atomic_cas"; break;
            case pgas_op_type::FENCE: oss << "fence"; break;
            case pgas_op_type::MEMCPY: oss << "memcpy"; break;
            case pgas_op_type::MEMMOVE: oss << "memmove"; break;
            case pgas_op_type::MEMSET: oss << "memset"; break;
        }

        oss << ":" << local_node_id << ":" << num_nodes;
        return oss.str();
    }
};

} // namespace attach
} // namespace bpftime

#endif // _PGAS_ATTACH_PRIVATE_DATA_HPP
