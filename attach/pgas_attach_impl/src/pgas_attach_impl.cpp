// SPDX-License-Identifier: MIT
// PGAS Attach Implementation using Frida
#include "pgas_attach_impl.hpp"
#include "frida_register_def.hpp"
#include <spdlog/spdlog.h>
#include <cstring>
#include <dlfcn.h>

namespace bpftime {
namespace attach {

// Thread-local storage for current context
static thread_local GumCpuContext *current_gum_context = nullptr;
static thread_local pgas_internal_attach_entry *current_pgas_entry = nullptr;

// Forward declarations for Frida callbacks
static void pgas_listener_on_enter(GumInvocationListener *listener,
                                    GumInvocationContext *ic);
static void pgas_listener_on_leave(GumInvocationListener *listener,
                                    GumInvocationContext *ic);

// Override handlers for different operations
extern "C" void *pgas_memcpy_override_handler();
extern "C" void *pgas_memmove_override_handler();
extern "C" void *pgas_memset_override_handler();

// Frida listener interface - use simple struct approach like frida_uprobe_attach_impl
struct _PgasListener {
    GObject parent;
    pgas_internal_attach_entry *hook_entry;
};

static void pgas_listener_iface_init(gpointer g_iface, gpointer iface_data);

#define PGAS_TYPE_LISTENER (pgas_listener_get_type())
G_DECLARE_FINAL_TYPE(PgasListener, pgas_listener, PGAS, LISTENER, GObject)
G_DEFINE_TYPE_EXTENDED(PgasListener, pgas_listener, G_TYPE_OBJECT, 0,
                       G_IMPLEMENT_INTERFACE(GUM_TYPE_INVOCATION_LISTENER,
                                            pgas_listener_iface_init))

static void pgas_listener_class_init(PgasListenerClass *klass) {
    (void)klass;
}

static void pgas_listener_init(PgasListener *self) {
    (void)self;
}

static void pgas_listener_iface_init(gpointer g_iface, gpointer iface_data) {
    (void)iface_data;
    auto *iface = (GumInvocationListenerInterface *)g_iface;
    iface->on_enter = pgas_listener_on_enter;
    iface->on_leave = pgas_listener_on_leave;
}

// Helper to convert GumCpuContext to pt_regs
static void convert_to_pt_regs(GumCpuContext *cpu_ctx, pt_regs &regs) {
#if defined(__x86_64__)
    regs.r15 = cpu_ctx->r15;
    regs.r14 = cpu_ctx->r14;
    regs.r13 = cpu_ctx->r13;
    regs.r12 = cpu_ctx->r12;
    regs.bp = cpu_ctx->rbp;
    regs.bx = cpu_ctx->rbx;
    regs.r11 = cpu_ctx->r11;
    regs.r10 = cpu_ctx->r10;
    regs.r9 = cpu_ctx->r9;
    regs.r8 = cpu_ctx->r8;
    regs.ax = cpu_ctx->rax;
    regs.cx = cpu_ctx->rcx;
    regs.dx = cpu_ctx->rdx;
    regs.si = cpu_ctx->rsi;
    regs.di = cpu_ctx->rdi;
    regs.ip = cpu_ctx->rip;
    regs.sp = cpu_ctx->rsp;
#elif defined(__aarch64__)
    for (int i = 0; i < 29; i++) {
        regs.regs[i] = cpu_ctx->x[i];
    }
    regs.regs[29] = cpu_ctx->fp;
    regs.regs[30] = cpu_ctx->lr;
    regs.sp = cpu_ctx->sp;
    regs.pc = cpu_ctx->pc;
#endif
}

// pgas_internal_attach_entry implementation
pgas_internal_attach_entry::pgas_internal_attach_entry(
    void *func, uint16_t local_node, uint16_t num_nodes,
    uint64_t base_addr, uint64_t size)
    : function(func), listener(nullptr),
      local_node_id(local_node), num_nodes(num_nodes),
      pgas_base_addr(base_addr), pgas_size(size),
      is_overrided(false), user_ret(0) {}

pgas_internal_attach_entry::~pgas_internal_attach_entry() {
    if (listener) {
        g_object_unref(listener);
    }
}

void pgas_internal_attach_entry::add_attach(pgas_attach_entry *entry) {
    user_attaches.push_back(entry);
}

void pgas_internal_attach_entry::remove_attach(pgas_attach_entry *entry) {
    user_attaches.erase(
        std::remove(user_attaches.begin(), user_attaches.end(), entry),
        user_attaches.end());
}

uint16_t pgas_internal_attach_entry::route_to_node(uint64_t addr) const {
    if (num_nodes <= 1) return local_node_id;
    if (pgas_size == 0) return local_node_id;

    // Simple hash-based routing
    uint64_t offset = addr - pgas_base_addr;
    uint64_t region_size = pgas_size / num_nodes;
    return (uint16_t)(offset / region_size) % num_nodes;
}

void pgas_internal_attach_entry::execute_load_callbacks(
    void *addr, size_t size, void *dest) {

    pgas_memory_context ctx;
    ctx.address = addr;
    ctx.size = size;
    ctx.op_type = pgas_op_type::LOAD;
    ctx.target_node = route_to_node((uint64_t)addr);
    ctx.local_node = local_node_id;
    ctx.data = dest;
    ctx.is_remote = (ctx.target_node != local_node_id);

    for (auto *attach : user_attaches) {
        if (attach->op_type == pgas_op_type::LOAD) {
            if (attach->pgas_callback) {
                attach->pgas_callback(ctx);
            }
            if (attach->ebpf_callback) {
                uint64_t ret = 0;
                attach->ebpf_callback(&ctx, sizeof(ctx), &ret);
            }
        }
    }
}

void pgas_internal_attach_entry::execute_store_callbacks(
    void *addr, size_t size, const void *src) {

    pgas_memory_context ctx;
    ctx.address = addr;
    ctx.size = size;
    ctx.op_type = pgas_op_type::STORE;
    ctx.target_node = route_to_node((uint64_t)addr);
    ctx.local_node = local_node_id;
    ctx.data = const_cast<void*>(src);
    ctx.is_remote = (ctx.target_node != local_node_id);

    for (auto *attach : user_attaches) {
        if (attach->op_type == pgas_op_type::STORE) {
            if (attach->pgas_callback) {
                attach->pgas_callback(ctx);
            }
            if (attach->ebpf_callback) {
                uint64_t ret = 0;
                attach->ebpf_callback(&ctx, sizeof(ctx), &ret);
            }
        }
    }
}

void pgas_internal_attach_entry::execute_memcpy_callbacks(
    void *dest, const void *src, size_t size) {

    pgas_memory_context ctx;
    ctx.address = dest;
    ctx.size = size;
    ctx.op_type = pgas_op_type::MEMCPY;
    ctx.target_node = route_to_node((uint64_t)dest);
    ctx.local_node = local_node_id;
    ctx.data = const_cast<void*>(src);
    ctx.is_remote = (ctx.target_node != local_node_id);

    for (auto *attach : user_attaches) {
        if (attach->op_type == pgas_op_type::MEMCPY) {
            if (attach->pgas_callback) {
                attach->pgas_callback(ctx);
            }
            if (attach->ebpf_callback) {
                uint64_t ret = 0;
                attach->ebpf_callback(&ctx, sizeof(ctx), &ret);
            }
        }
    }
}

// Frida callback implementations
static void pgas_listener_on_enter(GumInvocationListener *listener,
                                    GumInvocationContext *ic) {
    auto *self = (PgasListener *)listener;
    auto *entry = self->hook_entry;

    current_gum_context = ic->cpu_context;
    current_pgas_entry = entry;

    // Get function arguments
#if defined(__x86_64__)
    void *arg1 = (void *)ic->cpu_context->rdi;
    void *arg2 = (void *)ic->cpu_context->rsi;
    size_t arg3 = (size_t)ic->cpu_context->rdx;
#elif defined(__aarch64__)
    void *arg1 = (void *)ic->cpu_context->x[0];
    void *arg2 = (void *)ic->cpu_context->x[1];
    size_t arg3 = (size_t)ic->cpu_context->x[2];
#else
    void *arg1 = nullptr;
    void *arg2 = nullptr;
    size_t arg3 = 0;
#endif

    // Determine operation type based on hooked function
    // For memcpy-like: arg1=dest, arg2=src, arg3=size
    entry->execute_memcpy_callbacks(arg1, arg2, arg3);

    current_gum_context = nullptr;
    current_pgas_entry = nullptr;
}

static void pgas_listener_on_leave(GumInvocationListener *listener,
                                    GumInvocationContext *ic) {
    // Can capture return value here if needed
    (void)listener;
    (void)ic;
}

// Override handler for memcpy - intercepts and routes to appropriate node
extern "C" void *pgas_memcpy_override_handler() {
    GumInvocationContext *ctx = gum_interceptor_get_current_invocation();
    auto *entry = (pgas_internal_attach_entry *)
        gum_invocation_context_get_replacement_data(ctx);

#if defined(__x86_64__)
    void *dest = (void *)ctx->cpu_context->rdi;
    const void *src = (const void *)ctx->cpu_context->rsi;
    size_t n = (size_t)ctx->cpu_context->rdx;
#elif defined(__aarch64__)
    void *dest = (void *)ctx->cpu_context->x[0];
    const void *src = (const void *)ctx->cpu_context->x[1];
    size_t n = (size_t)ctx->cpu_context->x[2];
#else
    void *dest = gum_invocation_context_get_nth_argument(ctx, 0);
    const void *src = gum_invocation_context_get_nth_argument(ctx, 1);
    size_t n = (size_t)gum_invocation_context_get_nth_argument(ctx, 2);
#endif

    // Execute callbacks
    entry->execute_memcpy_callbacks(dest, src, n);

    // Check if this is a remote access
    uint16_t target_node = entry->route_to_node((uint64_t)dest);

    if (target_node != entry->local_node_id) {
        // Remote access - would need to route through network
        // For now, log and perform local copy
        SPDLOG_DEBUG("PGAS remote memcpy: dest={} src={} size={} target_node={}",
                     dest, src, n, target_node);

        // TODO: Implement actual remote memory copy via CXL/network
        // For demonstration, fall through to local copy
    }

    // Perform the actual memcpy
    return memcpy(dest, src, n);
}

extern "C" void *pgas_memmove_override_handler() {
    GumInvocationContext *ctx = gum_interceptor_get_current_invocation();
    auto *entry = (pgas_internal_attach_entry *)
        gum_invocation_context_get_replacement_data(ctx);

#if defined(__x86_64__)
    void *dest = (void *)ctx->cpu_context->rdi;
    const void *src = (const void *)ctx->cpu_context->rsi;
    size_t n = (size_t)ctx->cpu_context->rdx;
#elif defined(__aarch64__)
    void *dest = (void *)ctx->cpu_context->x[0];
    const void *src = (const void *)ctx->cpu_context->x[1];
    size_t n = (size_t)ctx->cpu_context->x[2];
#else
    void *dest = gum_invocation_context_get_nth_argument(ctx, 0);
    const void *src = gum_invocation_context_get_nth_argument(ctx, 1);
    size_t n = (size_t)gum_invocation_context_get_nth_argument(ctx, 2);
#endif

    // Execute callbacks
    pgas_memory_context mem_ctx;
    mem_ctx.address = dest;
    mem_ctx.size = n;
    mem_ctx.op_type = pgas_op_type::MEMMOVE;
    mem_ctx.target_node = entry->route_to_node((uint64_t)dest);
    mem_ctx.local_node = entry->local_node_id;
    mem_ctx.data = const_cast<void*>(src);
    mem_ctx.is_remote = (mem_ctx.target_node != entry->local_node_id);

    for (auto *attach : entry->user_attaches) {
        if (attach->op_type == pgas_op_type::MEMMOVE && attach->pgas_callback) {
            attach->pgas_callback(mem_ctx);
        }
    }

    return memmove(dest, src, n);
}

extern "C" void *pgas_memset_override_handler() {
    GumInvocationContext *ctx = gum_interceptor_get_current_invocation();
    auto *entry = (pgas_internal_attach_entry *)
        gum_invocation_context_get_replacement_data(ctx);

#if defined(__x86_64__)
    void *s = (void *)ctx->cpu_context->rdi;
    int c = (int)ctx->cpu_context->rsi;
    size_t n = (size_t)ctx->cpu_context->rdx;
#elif defined(__aarch64__)
    void *s = (void *)ctx->cpu_context->x[0];
    int c = (int)ctx->cpu_context->x[1];
    size_t n = (size_t)ctx->cpu_context->x[2];
#else
    void *s = gum_invocation_context_get_nth_argument(ctx, 0);
    int c = (int)(uintptr_t)gum_invocation_context_get_nth_argument(ctx, 1);
    size_t n = (size_t)gum_invocation_context_get_nth_argument(ctx, 2);
#endif

    // Execute callbacks
    pgas_memory_context mem_ctx;
    mem_ctx.address = s;
    mem_ctx.size = n;
    mem_ctx.op_type = pgas_op_type::MEMSET;
    mem_ctx.target_node = entry->route_to_node((uint64_t)s);
    mem_ctx.local_node = entry->local_node_id;
    mem_ctx.new_value = c;
    mem_ctx.is_remote = (mem_ctx.target_node != entry->local_node_id);

    for (auto *attach : entry->user_attaches) {
        if (attach->op_type == pgas_op_type::MEMSET && attach->pgas_callback) {
            attach->pgas_callback(mem_ctx);
        }
    }

    return memset(s, c, n);
}

// pgas_attach_impl implementation
pgas_attach_impl::pgas_attach_impl()
    : pgas_base_addr(0), pgas_size(0), local_node_id(0), num_nodes(1) {

    gum_init_embedded();
    interceptor = gum_interceptor_obtain();
    SPDLOG_INFO("PGAS attach implementation initialized");
}

pgas_attach_impl::~pgas_attach_impl() {
    std::lock_guard<std::mutex> lock(mutex);

    // Detach all hooks
    for (auto &[addr, entry] : internal_attaches) {
        gum_interceptor_revert(interceptor, entry->function);
    }

    g_object_unref(interceptor);
    SPDLOG_INFO("PGAS attach implementation destroyed");
}

int pgas_attach_impl::detach_by_id(int id) {
    std::lock_guard<std::mutex> lock(mutex);

    auto it = attaches.find(id);
    if (it == attaches.end()) {
        return -ENOENT;
    }

    // Find and remove from internal entry
    for (auto &[addr, internal] : internal_attaches) {
        internal->remove_attach(it->second.get());
        if (!internal->has_attaches()) {
            gum_interceptor_revert(interceptor, addr);
        }
    }

    attaches.erase(it);
    return 0;
}

int pgas_attach_impl::create_attach_with_ebpf_callback(
    ebpf_run_callback &&cb,
    const attach_private_data &private_data,
    int attach_type) {

    auto &priv = dynamic_cast<const pgas_attach_private_data&>(private_data);
    return create_pgas_hook(priv, std::move(cb));
}

void pgas_attach_impl::register_custom_helpers(
    ebpf_helper_register_callback register_callback) {

    // Register PGAS-specific helpers
    // TODO: Add helpers for remote memory operations
}

int pgas_attach_impl::create_pgas_hook(
    const pgas_attach_private_data &priv,
    ebpf_run_callback &&cb) {

    std::lock_guard<std::mutex> lock(mutex);

    // Resolve target address
    void *target = priv.target_address;
    if (!target && !priv.module_name.empty()) {
        target = resolve_symbol(priv.module_name, priv.symbol_name);
        if (!target) {
            SPDLOG_ERROR("Failed to resolve symbol: {}:{}",
                         priv.module_name, priv.symbol_name);
            return -ENOENT;
        }
    }

    // Get or create internal entry
    auto *internal = get_or_create_internal_entry(
        target, priv.local_node_id, priv.num_nodes);

    // Create user attach entry
    int id = allocate_id();
    auto entry = std::make_unique<pgas_attach_entry>(id, priv.op_type);
    entry->ebpf_callback = std::move(cb);

    internal->add_attach(entry.get());
    attaches[id] = std::move(entry);

    SPDLOG_INFO("Created PGAS hook id={} addr={} op_type={}",
                id, target, (int)priv.op_type);
    return id;
}

int pgas_attach_impl::create_load_hook(void *func_addr, uint16_t local_node,
                                        uint16_t num_nodes) {
    pgas_attach_private_data priv;
    priv.target_address = func_addr;
    priv.op_type = pgas_op_type::LOAD;
    priv.local_node_id = local_node;
    priv.num_nodes = num_nodes;
    return create_pgas_hook(priv, nullptr);
}

int pgas_attach_impl::create_store_hook(void *func_addr, uint16_t local_node,
                                         uint16_t num_nodes) {
    pgas_attach_private_data priv;
    priv.target_address = func_addr;
    priv.op_type = pgas_op_type::STORE;
    priv.local_node_id = local_node;
    priv.num_nodes = num_nodes;
    return create_pgas_hook(priv, nullptr);
}

int pgas_attach_impl::create_memcpy_hook(void *func_addr, uint16_t local_node,
                                          uint16_t num_nodes) {
    pgas_attach_private_data priv;
    priv.target_address = func_addr;
    priv.op_type = pgas_op_type::MEMCPY;
    priv.local_node_id = local_node;
    priv.num_nodes = num_nodes;
    return create_pgas_hook(priv, nullptr);
}

void pgas_attach_impl::set_pgas_region(uint64_t base_addr, uint64_t size) {
    std::lock_guard<std::mutex> lock(mutex);
    pgas_base_addr = base_addr;
    pgas_size = size;

    // Update all internal entries
    for (auto &[addr, entry] : internal_attaches) {
        entry->pgas_base_addr = base_addr;
        entry->pgas_size = size;
    }
}

void *pgas_attach_impl::resolve_symbol(const std::string &module,
                                        const std::string &symbol) {
    // Try to find the symbol using dlsym
    void *handle = dlopen(module.empty() ? nullptr : module.c_str(), RTLD_NOW);
    if (!handle) {
        return nullptr;
    }

    void *addr = dlsym(handle, symbol.c_str());
    if (!module.empty()) {
        dlclose(handle);
    }
    return addr;
}

pgas_internal_attach_entry* pgas_attach_impl::get_or_create_internal_entry(
    void *addr, uint16_t local_node, uint16_t num_nodes) {

    auto it = internal_attaches.find(addr);
    if (it != internal_attaches.end()) {
        return it->second.get();
    }

    // Create new internal entry
    auto entry = std::make_unique<pgas_internal_attach_entry>(
        addr, local_node, num_nodes, pgas_base_addr, pgas_size);

    // Create Frida listener
    auto *listener = (PgasListener *)
        g_object_new(pgas_listener_get_type(), nullptr);
    listener->hook_entry = entry.get();
    entry->listener = GUM_INVOCATION_LISTENER(listener);

    // Attach using Frida interceptor with override
    gum_interceptor_replace(interceptor, addr,
                            (void *)pgas_memcpy_override_handler,
                            entry.get(), nullptr);

    auto *result = entry.get();
    internal_attaches[addr] = std::move(entry);
    return result;
}

} // namespace attach
} // namespace bpftime
