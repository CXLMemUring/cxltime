// SPDX-License-Identifier: MIT
// Implementation of PGAS CXLMemSim integration

#include "pgas_cxlmemsim_integration.hpp"
#include <spdlog/spdlog.h>
#include <fstream>
#include <sstream>
#include <cstring>
#include <dlfcn.h>
#include <cstdlib>
#include <cctype>
#include <limits>
#include <thread>

namespace bpftime {
namespace attach {

// ============================================================================
// cxlmemsim_connection_manager implementation
// ============================================================================

int cxlmemsim_connection_manager::connect_node_locked(uint16_t node_id) {
    if (node_id == local_node_id_) return 0;
    if (connections_.find(node_id) != connections_.end()) return 0;

    auto node_it = node_configs_.find(node_id);
    if (node_it == node_configs_.end()) {
        SPDLOG_ERROR("No CXLMemSim config for node {}", node_id);
        return -1;
    }

    const auto& node = node_it->second;
    if (node.port == 0) {
        SPDLOG_ERROR("CXLMemSim node {} has no TCP port configured", node_id);
        return -1;
    }

    auto ctx = std::make_unique<cxlmemsim_ctx_t>();
    if (cxlmemsim_init(ctx.get(), node.hostname.c_str(), node.port) != 0) {
        SPDLOG_ERROR("Failed to init CXLMemSim client for node {}", node_id);
        return -1;
    }

    if (cxlmemsim_connect(ctx.get()) != 0) {
        SPDLOG_ERROR("Failed to connect to CXLMemSim server at {}:{} for node {}",
                     node.hostname, node.port, node_id);
        cxlmemsim_finalize(ctx.get());
        return -1;
    }

    SPDLOG_INFO("Connected to CXLMemSim server for node {} at {}:{}",
                node_id, node.hostname, node.port);
    connections_[node_id] = std::move(ctx);
    return 0;
}

int cxlmemsim_connection_manager::init(
    const std::vector<pgas_node_info>& nodes,
    uint16_t local_node_id,
    bool eager_connect) {

    std::lock_guard<std::mutex> lock(mutex_);

    for (auto& [id, ctx] : connections_) {
        cxlmemsim_finalize(ctx.get());
    }
    connections_.clear();
    node_configs_.clear();
    local_node_id_ = local_node_id;

    for (const auto& node : nodes) {
        node_configs_[node.node_id] = node;
        if (node.node_id == local_node_id_) {
            SPDLOG_INFO("Node {} is local, skipping CXLMemSim connection",
                        node.node_id);
        }
    }

    if (node_configs_.empty()) {
        SPDLOG_WARN("No CXLMemSim nodes configured");
        return -1;
    }

    if (eager_connect) {
        for (const auto& [node_id, node] : node_configs_) {
            (void)node;
            if (node_id != local_node_id_) {
                (void)connect_node_locked(node_id);
            }
        }
    } else {
        SPDLOG_INFO("CXLMemSim lazy connection mode: {} configured node(s)",
                    node_configs_.size());
    }

    return 0;
}

cxlmemsim_ctx_t* cxlmemsim_connection_manager::get_connection(uint16_t node_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = connections_.find(node_id);
    if (it != connections_.end()) return it->second.get();

    if (connect_node_locked(node_id) != 0) return nullptr;

    it = connections_.find(node_id);
    return (it != connections_.end()) ? it->second.get() : nullptr;
}

void cxlmemsim_connection_manager::shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [id, ctx] : connections_) {
        cxlmemsim_finalize(ctx.get());
    }
    connections_.clear();
    node_configs_.clear();
}

cxlmemsim_connection_manager::stats
cxlmemsim_connection_manager::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void cxlmemsim_connection_manager::reset_stats() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_ = {};
}

// ============================================================================
// pgas_cxlmemsim_hooker implementation
// ============================================================================

int pgas_cxlmemsim_hooker::init(const config& cfg) {
    config_ = cfg;

    // Initialize CXLMemSim connections
    auto& conn_mgr = cxlmemsim_connection_manager::instance();
    if (conn_mgr.init(cfg.nodes, cfg.local_node_id, cfg.eager_connect) != 0) {
        SPDLOG_WARN("No CXLMemSim connections established, "
                    "remote access will fail");
    }

    // Create attach implementation
    attach_impl_ = std::make_unique<pgas_attach_impl>();

    // Set PGAS region
    attach_impl_->set_pgas_region(cfg.pgas_base_addr, cfg.pgas_region_size);

    release_x86_runtime();
    const pgas_x86_runtime_config runtime_config{
        cfg.pgas_base_addr,
        cfg.pgas_region_size,
        cfg.local_node_id,
        cfg.num_nodes,
        pgas_cxlmemsim_x86_transport(),
        nullptr,
        nullptr,
    };
    x86_runtime_ = pgas_x86_runtime_create(runtime_config);
    if (x86_runtime_ == nullptr) {
        SPDLOG_ERROR("Invalid shared x86 PGAS runtime configuration");
        attach_impl_.reset();
        return -EINVAL;
    }
    x86_runtime_accepting_.store(true, std::memory_order_release);

    initialized_ = true;
    SPDLOG_INFO("PGAS CXLMemSim hooker initialized: "
                "local_node={} num_nodes={} pgas_base=0x{:x} pgas_size={}",
                cfg.local_node_id, cfg.num_nodes,
                cfg.pgas_base_addr, cfg.pgas_region_size);

    return 0;
}

bool pgas_cxlmemsim_hooker::touches_pgas(uint64_t address, size_t size) const
{
    uint64_t region_end{};
    if (__builtin_add_overflow(config_.pgas_base_addr,
                               config_.pgas_region_size, &region_end))
        return false;
    if (size == 0)
        return address >= config_.pgas_base_addr && address < region_end;
    uint64_t access_end{};
    if (__builtin_add_overflow(address, static_cast<uint64_t>(size),
                               &access_end))
        return true;
    return address < region_end && access_end > config_.pgas_base_addr;
}

void pgas_cxlmemsim_hooker::release_x86_runtime()
{
    x86_runtime_accepting_.store(false, std::memory_order_release);
    while (x86_runtime_users_.load(std::memory_order_acquire) != 0)
        std::this_thread::yield();
    if (x86_runtime_ != nullptr) {
        pgas_x86_runtime_destroy(x86_runtime_);
        x86_runtime_ = nullptr;
    }
}

pgas_x86_runtime *pgas_cxlmemsim_hooker::acquire_x86_runtime()
{
    if (!x86_runtime_accepting_.load(std::memory_order_acquire))
        return nullptr;
    x86_runtime_users_.fetch_add(1, std::memory_order_acq_rel);
    if (!x86_runtime_accepting_.load(std::memory_order_acquire)) {
        x86_runtime_users_.fetch_sub(1, std::memory_order_acq_rel);
        return nullptr;
    }
    return x86_runtime_;
}

void pgas_cxlmemsim_hooker::release_x86_runtime_user(
    pgas_x86_runtime *runtime)
{
    if (runtime != nullptr)
        x86_runtime_users_.fetch_sub(1, std::memory_order_acq_rel);
}

int pgas_cxlmemsim_hooker::install_hooks() {
    if (!initialized_) {
        SPDLOG_ERROR("Hooker not initialized");
        return -1;
    }

    if (hooks_installed_) {
        SPDLOG_WARN("Hooks already installed");
        return 0;
    }

    // Hook memcpy
    if (config_.hook_memcpy) {
        void* memcpy_addr = dlsym(RTLD_DEFAULT, "memcpy");
        if (memcpy_addr) {
            attach_impl_->create_memcpy_hook(memcpy_addr,
                                              config_.local_node_id,
                                              config_.num_nodes);
            SPDLOG_INFO("Hooked memcpy at {}", memcpy_addr);
        }
    }

    // Hook memmove
    if (config_.hook_memmove) {
        void* memmove_addr = dlsym(RTLD_DEFAULT, "memmove");
        if (memmove_addr) {
            pgas_attach_private_data priv;
            priv.target_address = memmove_addr;
            priv.op_type = pgas_op_type::MEMMOVE;
            priv.local_node_id = config_.local_node_id;
            priv.num_nodes = config_.num_nodes;
            attach_impl_->create_pgas_hook(priv, nullptr);
            SPDLOG_INFO("Hooked memmove at {}", memmove_addr);
        }
    }

    // Hook memset
    if (config_.hook_memset) {
        void* memset_addr = dlsym(RTLD_DEFAULT, "memset");
        if (memset_addr) {
            pgas_attach_private_data priv;
            priv.target_address = memset_addr;
            priv.op_type = pgas_op_type::MEMSET;
            priv.local_node_id = config_.local_node_id;
            priv.num_nodes = config_.num_nodes;
            attach_impl_->create_pgas_hook(priv, nullptr);
            SPDLOG_INFO("Hooked memset at {}", memset_addr);
        }
    }

    hooks_installed_ = true;
    return 0;
}

void pgas_cxlmemsim_hooker::remove_hooks() {
    const bool had_interceptor_hooks = hooks_installed_;
    attach_impl_.reset();
    hooks_installed_ = false;
    if (had_interceptor_hooks) {
        SPDLOG_INFO("PGAS hooks removed");
    }
}

int pgas_cxlmemsim_hooker::remote_read(uint16_t node_id, uint64_t addr,
                                        void* dest, size_t size) {
    auto& conn_mgr = cxlmemsim_connection_manager::instance();

    if (conn_mgr.is_local(node_id)) {
        // Local read - direct memory access
        memcpy(dest, (void*)addr, size);
        {
            std::lock_guard<std::mutex> lock(conn_mgr.stats_mutex_);
            conn_mgr.stats_.local_reads++;
        }
        return 0;
    }

    // Remote read via CXLMemSim
    auto* ctx = conn_mgr.get_connection(node_id);
    if (!ctx) {
        SPDLOG_ERROR("No connection for node {}", node_id);
        return -1;
    }

    uint64_t remote_addr = translate_addr(addr, node_id);
    int ret = cxlmemsim_remote_load(ctx, remote_addr, dest, size);
    if (ret == 0) {
        std::lock_guard<std::mutex> lock(conn_mgr.stats_mutex_);
        conn_mgr.stats_.remote_reads++;
        conn_mgr.stats_.remote_bytes_read += size;
        conn_mgr.stats_.total_remote_latency_ns += ctx->total_latency_ns;
    }
    return ret;
}

int pgas_cxlmemsim_hooker::remote_write(uint16_t node_id, uint64_t addr,
                                         const void* src, size_t size) {
    auto& conn_mgr = cxlmemsim_connection_manager::instance();

    if (conn_mgr.is_local(node_id)) {
        // Local write - direct memory access
        memcpy((void*)addr, src, size);
        {
            std::lock_guard<std::mutex> lock(conn_mgr.stats_mutex_);
            conn_mgr.stats_.local_writes++;
        }
        return 0;
    }

    // Remote write via CXLMemSim
    auto* ctx = conn_mgr.get_connection(node_id);
    if (!ctx) {
        SPDLOG_ERROR("No connection for node {}", node_id);
        return -1;
    }

    uint64_t remote_addr = translate_addr(addr, node_id);
    int ret = cxlmemsim_remote_store(ctx, remote_addr, src, size);
    if (ret == 0) {
        std::lock_guard<std::mutex> lock(conn_mgr.stats_mutex_);
        conn_mgr.stats_.remote_writes++;
        conn_mgr.stats_.remote_bytes_written += size;
        conn_mgr.stats_.total_remote_latency_ns += ctx->total_latency_ns;
    }
    return ret;
}

uint16_t pgas_cxlmemsim_hooker::addr_to_node(uint64_t addr) const {
    if (!is_pgas_addr(addr)) {
        return config_.local_node_id;  // Non-PGAS address is local
    }
    if (config_.num_nodes == 0 || config_.pgas_region_size == 0) {
        return config_.local_node_id;
    }

    uint64_t region_size = config_.pgas_region_size / config_.num_nodes;
    if (region_size == 0) return config_.local_node_id;

    // Simple partitioning: each node owns a contiguous region.
    uint64_t offset = addr - config_.pgas_base_addr;
    uint64_t node = offset / region_size;
    if (node >= config_.num_nodes) node = config_.num_nodes - 1;
    return static_cast<uint16_t>(node);
}

uint64_t pgas_cxlmemsim_hooker::translate_addr(uint64_t local_addr,
                                                uint16_t target_node) const {
    if (!config_.use_node_local_offsets || !is_pgas_addr(local_addr) ||
        config_.num_nodes == 0 || config_.pgas_region_size == 0 ||
        target_node >= config_.num_nodes) {
        return local_addr;
    }

    uint64_t region_size = config_.pgas_region_size / config_.num_nodes;
    if (region_size == 0) return local_addr;

    uint64_t offset = local_addr - config_.pgas_base_addr;
    uint64_t node_base = static_cast<uint64_t>(target_node) * region_size;
    if (offset < node_base) return offset;
    return offset - node_base;
}

void pgas_cxlmemsim_hooker::print_stats() const {
    auto stats = cxlmemsim_connection_manager::instance().get_stats();

    fprintf(stderr, "\n=== PGAS CXLMemSim Hook Statistics ===\n");
    fprintf(stderr, "Local reads:  %lu\n", stats.local_reads);
    fprintf(stderr, "Local writes: %lu\n", stats.local_writes);
    fprintf(stderr, "Remote reads:  %lu\n", stats.remote_reads);
    fprintf(stderr, "Remote writes: %lu\n", stats.remote_writes);
    fprintf(stderr, "Total remote latency: %lu ns\n", stats.total_remote_latency_ns);

    uint64_t total_remote = stats.remote_reads + stats.remote_writes;
    if (total_remote > 0) {
        fprintf(stderr, "Avg remote latency: %lu ns\n",
               stats.total_remote_latency_ns / total_remote);
    }
    fprintf(stderr, "======================================\n\n");
}

// ============================================================================
// Remote operation handlers (called from Frida hooks)
// ============================================================================

int pgas_remote_memcpy_handler(void* dest, const void* src, size_t n,
                                uint16_t target_node, bool dest_is_remote) {
    auto& hooker = pgas_cxlmemsim_hooker::instance();

    if (dest_is_remote) {
        // Writing to remote node
        return hooker.remote_write(target_node, (uint64_t)dest, src, n);
    } else {
        // Reading from remote node
        return hooker.remote_read(target_node, (uint64_t)src, dest, n);
    }
}

int pgas_remote_memset_handler(void* s, int c, size_t n, uint16_t target_node) {
    // For remote memset, we need to create a local buffer and send it
    auto& hooker = pgas_cxlmemsim_hooker::instance();

    // For small sizes, use stack buffer
    if (n <= 4096) {
        char buf[4096];
        memset(buf, c, n);
        return hooker.remote_write(target_node, (uint64_t)s, buf, n);
    }

    // For larger sizes, allocate
    void* buf = malloc(n);
    if (!buf) return -1;

    memset(buf, c, n);
    int ret = hooker.remote_write(target_node, (uint64_t)s, buf, n);
    free(buf);

    return ret;
}

// ============================================================================
// hooks namespace - simplified interface
// ============================================================================

static std::string trim_copy(const std::string& input) {
    size_t begin = 0;
    while (begin < input.size() && std::isspace(static_cast<unsigned char>(input[begin]))) begin++;
    size_t end = input.size();
    while (end > begin && std::isspace(static_cast<unsigned char>(input[end - 1]))) end--;
    return input.substr(begin, end - begin);
}

static bool parse_bool_value(const std::string& value) {
    std::string v = trim_copy(value);
    for (auto& ch : v) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    return v == "1" || v == "true" || v == "yes" || v == "on";
}

static uint16_t parse_node_id_value(const std::string& value, uint16_t fallback) {
    std::string v = trim_copy(value);
    if (v == "none") return std::numeric_limits<uint16_t>::max();
    long parsed = std::stol(v, nullptr, 0);
    if (parsed < 0) return std::numeric_limits<uint16_t>::max();
    if (parsed > std::numeric_limits<uint16_t>::max()) return fallback;
    return static_cast<uint16_t>(parsed);
}

namespace hooks {

static bool g_active = false;

int init_from_config(const std::string& config_file) {
    pgas_cxlmemsim_hooker::config cfg;

    std::ifstream file(config_file);
    if (!file.is_open()) {
        SPDLOG_ERROR("Failed to open config file: {}", config_file);
        return -1;
    }

    uint16_t max_node_id = 0;
    bool saw_node = false;
    std::string line;
    while (std::getline(file, line)) {
        auto comment = line.find('#');
        if (comment != std::string::npos) line.erase(comment);
        line = trim_copy(line);
        if (line.empty()) continue;

        auto sep = line.find('=');
        if (sep == std::string::npos) continue;

        std::string key = trim_copy(line.substr(0, sep));
        std::string value = trim_copy(line.substr(sep + 1));
        try {
            if (key == "local_node_id" || key == "node_id") {
                cfg.local_node_id = parse_node_id_value(value, cfg.local_node_id);
            } else if (key == "num_nodes") {
                unsigned long parsed = std::stoul(value, nullptr, 0);
                if (parsed > 0 && parsed <= std::numeric_limits<uint16_t>::max()) {
                    cfg.num_nodes = static_cast<uint16_t>(parsed);
                }
            } else if (key == "pgas_base" || key == "base_addr") {
                cfg.pgas_base_addr = std::stoull(value, nullptr, 0);
            } else if (key == "pgas_size" || key == "size") {
                cfg.pgas_region_size = std::stoull(value, nullptr, 0);
            } else if (key == "eager_connect") {
                cfg.eager_connect = parse_bool_value(value);
            } else if (key == "use_node_local_offsets") {
                cfg.use_node_local_offsets = parse_bool_value(value);
            } else if (key == "remote_addr_mode") {
                cfg.use_node_local_offsets = (value != "global");
            } else if (key.rfind("cxlmemsim", 0) == 0) {
                // Parse cxlmemsimN=host:port:node_id
                pgas_node_info node;
                std::istringstream vss(value);
                std::string host, port_str, node_id_str;
                if (std::getline(vss, host, ':') &&
                    std::getline(vss, port_str, ':') &&
                    std::getline(vss, node_id_str)) {
                    unsigned long port = std::stoul(trim_copy(port_str), nullptr, 0);
                    unsigned long node_id = std::stoul(trim_copy(node_id_str), nullptr, 0);
                    if (port <= std::numeric_limits<uint16_t>::max() &&
                        node_id <= std::numeric_limits<uint16_t>::max()) {
                        node.hostname = trim_copy(host);
                        node.port = static_cast<uint16_t>(port);
                        node.node_id = static_cast<uint16_t>(node_id);
                        cfg.nodes.push_back(node);
                        if (!saw_node || node.node_id > max_node_id) max_node_id = node.node_id;
                        saw_node = true;
                    }
                }
            }
        } catch (const std::exception& e) {
            SPDLOG_WARN("Ignoring invalid config line '{}': {}", line, e.what());
        }
    }

    if (saw_node && max_node_id < std::numeric_limits<uint16_t>::max() &&
        max_node_id >= cfg.num_nodes) {
        cfg.num_nodes = max_node_id + 1;
    }

    return pgas_cxlmemsim_hooker::instance().init(cfg);
}

int init(uint16_t local_node_id, uint16_t num_nodes,
         const std::vector<std::pair<std::string, int>>& server_addresses,
         uint64_t pgas_base_addr, uint64_t pgas_size) {

    pgas_cxlmemsim_hooker::config cfg;
    cfg.local_node_id = local_node_id;
    cfg.num_nodes = num_nodes;
    cfg.pgas_base_addr = pgas_base_addr;
    cfg.pgas_region_size = pgas_size;

    for (size_t i = 0; i < server_addresses.size(); i++) {
        pgas_node_info node;
        node.node_id = static_cast<uint16_t>(i);
        node.hostname = server_addresses[i].first;
        node.port = server_addresses[i].second;
        cfg.nodes.push_back(node);
    }

    return pgas_cxlmemsim_hooker::instance().init(cfg);
}

int start() {
    int ret = pgas_cxlmemsim_hooker::instance().install_hooks();
    if (ret == 0) {
        g_active = true;
    }
    return ret;
}

void stop() {
    pgas_cxlmemsim_hooker::instance().remove_hooks();
    g_active = false;
}

bool is_active() {
    return g_active;
}

cxlmemsim_connection_manager::stats get_stats() {
    return cxlmemsim_connection_manager::instance().get_stats();
}

void finalize() {
    stop();
    pgas_cxlmemsim_hooker::instance().release_x86_runtime();
    cxlmemsim_connection_manager::instance().shutdown();
}

} // namespace hooks

namespace {

int x86_transport_read(void *, uint16_t node, uint64_t address, void *dest,
                       size_t size)
{
    return pgas_cxlmemsim_hooker::instance().remote_read(node, address, dest,
                                                         size);
}

int x86_transport_write(void *, uint16_t node, uint64_t address,
                        const void *source, size_t size)
{
    return pgas_cxlmemsim_hooker::instance().remote_write(
        node, address, source, size);
}

} // namespace

pgas_x86_transport pgas_cxlmemsim_x86_transport()
{
    return { x86_transport_read, x86_transport_write, nullptr };
}

pgas_x86_runtime *pgas_cxlmemsim_acquire_x86_runtime()
{
    return pgas_cxlmemsim_hooker::instance().acquire_x86_runtime();
}

void pgas_cxlmemsim_release_x86_runtime_user(pgas_x86_runtime *runtime)
{
    pgas_cxlmemsim_hooker::instance().release_x86_runtime_user(runtime);
}

} // namespace attach
} // namespace bpftime

// ============================================================================
// C interface implementation
// ============================================================================

extern "C" {

int pgas_hook_init(const char* config_file) {
    return bpftime::attach::hooks::init_from_config(config_file);
}

int pgas_hook_start(void) {
    return bpftime::attach::hooks::start();
}

void pgas_hook_stop(void) {
    bpftime::attach::hooks::stop();
}

int pgas_hook_remote_read(uint16_t node_id, uint64_t addr,
                           void* dest, size_t size) {
    return bpftime::attach::pgas_cxlmemsim_hooker::instance().remote_read(
        node_id, addr, dest, size);
}

int pgas_hook_remote_write(uint16_t node_id, uint64_t addr,
                            const void* src, size_t size) {
    return bpftime::attach::pgas_cxlmemsim_hooker::instance().remote_write(
        node_id, addr, src, size);
}

void pgas_hook_finalize(void) {
    bpftime::attach::hooks::finalize();
}

void pgas_hook_print_stats(void) {
    bpftime::attach::pgas_cxlmemsim_hooker::instance().print_stats();
}

} // extern "C"
