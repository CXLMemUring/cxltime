// SPDX-License-Identifier: MIT
// Frida Stalker-based mov instruction interception for CXL PGAS
//
// PERFORMANCE OPTIMIZATIONS:
//   1. Skip stack-relative movs (RSP/RBP-based) at JIT time — these
//      are never CXL addresses and account for ~60% of all memory movs.
//   2. Inline range check via GumX86Writer BEFORE the callout — the
//      common case (non-CXL address) is ~8 cycles of inline asm with
//      no function call, vs ~80 cycles for a full callout.
//   3. Trust threshold defaults to -1 (cache JIT'd blocks forever).
//   4. Lock-free bump allocator for callout metadata.
//   5. Flatten the hot-path: cache pgas_base/size directly in callout
//      data, avoid singleton lookups and virtual calls.

#include "pgas_stalker_mov.hpp"
#include "pgas_cxlmemsim_integration.hpp"
#include "pgas_stalker_module_policy.hpp"
#include "pgas_x86_bulk.hpp"
#include "pgas_x86_memory_access.hpp"
#include "pgas_x86_replay.hpp"
#include "pgas_x86_xstate.hpp"
#include <spdlog/spdlog.h>
#include <array>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <mutex>
#include <atomic>
#include <cerrno>
#include <algorithm>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>

#include <dlfcn.h>
#include <asm/prctl.h>
#include <signal.h>
#include <sys/syscall.h>
#include <unistd.h>

using namespace bpftime::attach;

#if defined(__x86_64__)

bool bpftime::attach::pgas_x86_emit_range_gate(
    GumX86Writer *writer, GumX86Reg address_register,
    GumX86Reg scratch_start, GumX86Reg scratch_end,
    GumX86Reg scratch_bound, int64_t displacement, uint8_t width,
    uint64_t pgas_base,
    uint64_t pgas_size, gconstpointer inside_label,
    gconstpointer outside_label, gconstpointer partial_label,
    gconstpointer overflow_label)
{
    if (writer == nullptr || inside_label == nullptr ||
        outside_label == nullptr || partial_label == nullptr ||
        overflow_label == nullptr || width == 0 || width > 64 ||
        pgas_size == 0 || pgas_base > UINT64_MAX - pgas_size ||
        address_register == scratch_start ||
        address_register == scratch_end ||
        address_register == scratch_bound || scratch_start == scratch_end ||
        scratch_start == scratch_bound || scratch_end == scratch_bound) {
        return false;
    }

    static std::atomic<uintptr_t> next_label{ 0x1000 };
    const auto label_base = next_label.fetch_add(4, std::memory_order_relaxed);
    const auto inside_restore = GSIZE_TO_POINTER(label_base);
    const auto outside_restore = GSIZE_TO_POINTER(label_base + 1);
    const auto partial_restore = GSIZE_TO_POINTER(label_base + 2);
    const auto overflow_restore = GSIZE_TO_POINTER(label_base + 3);
    const uint64_t pgas_end = pgas_base + pgas_size;

    // Leaf functions may keep live locals in the SysV 128-byte red zone.
    // Move below it before saving state; LEA preserves the caller's flags.
    if (!gum_x86_writer_put_lea_reg_reg_offset(writer, GUM_X86_RSP,
                                               GUM_X86_RSP, -128)) {
        return false;
    }
    gum_x86_writer_put_pushfx(writer);
    if (!gum_x86_writer_put_push_reg(writer, scratch_start) ||
        !gum_x86_writer_put_push_reg(writer, scratch_end) ||
        !gum_x86_writer_put_push_reg(writer, scratch_bound) ||
        !gum_x86_writer_put_mov_reg_reg(writer, scratch_start,
                                        address_register) ||
        (displacement != 0 &&
         !gum_x86_writer_put_add_reg_imm(writer, scratch_start,
                                         displacement)) ||
        !gum_x86_writer_put_mov_reg_reg(writer, scratch_end, scratch_start) ||
        !gum_x86_writer_put_add_reg_imm(writer, scratch_end, width)) {
        return false;
    }
    gum_x86_writer_put_jcc_near_label(writer, X86_INS_JB, overflow_restore,
                                      GUM_NO_HINT);

    if (!gum_x86_writer_put_mov_reg_u64(writer, scratch_bound, pgas_base) ||
        !gum_x86_writer_put_cmp_reg_reg(writer, scratch_end, scratch_bound)) {
        return false;
    }
    gum_x86_writer_put_jcc_near_label(writer, X86_INS_JBE, outside_restore,
                                      GUM_NO_HINT);
    if (!gum_x86_writer_put_cmp_reg_reg(writer, scratch_start,
                                        scratch_bound)) {
        return false;
    }
    gum_x86_writer_put_jcc_near_label(writer, X86_INS_JB, partial_restore,
                                      GUM_NO_HINT);

    if (!gum_x86_writer_put_mov_reg_u64(writer, scratch_bound, pgas_end) ||
        !gum_x86_writer_put_cmp_reg_reg(writer, scratch_start,
                                        scratch_bound)) {
        return false;
    }
    gum_x86_writer_put_jcc_near_label(writer, X86_INS_JAE, outside_restore,
                                      GUM_NO_HINT);
    if (!gum_x86_writer_put_cmp_reg_reg(writer, scratch_end, scratch_bound)) {
        return false;
    }
    gum_x86_writer_put_jcc_near_label(writer, X86_INS_JA, partial_restore,
                                      GUM_NO_HINT);
    gum_x86_writer_put_jmp_near_label(writer, inside_restore);

    const auto emit_restore = [&](gconstpointer restore_label,
                                  gconstpointer target_label) {
        if (!gum_x86_writer_put_label(writer, restore_label) ||
            !gum_x86_writer_put_pop_reg(writer, scratch_bound) ||
            !gum_x86_writer_put_pop_reg(writer, scratch_end) ||
            !gum_x86_writer_put_pop_reg(writer, scratch_start)) {
            return false;
        }
        gum_x86_writer_put_popfx(writer);
        if (!gum_x86_writer_put_lea_reg_reg_offset(writer, GUM_X86_RSP,
                                                   GUM_X86_RSP, 128)) {
            return false;
        }
        gum_x86_writer_put_jmp_near_label(writer, target_label);
        return true;
    };

    return emit_restore(inside_restore, inside_label) &&
           emit_restore(outside_restore, outside_label) &&
           emit_restore(partial_restore, partial_label) &&
           emit_restore(overflow_restore, overflow_label);
}

// ---------------------------------------------------------------------------
// Internal context
// ---------------------------------------------------------------------------

struct stalker_thread_record {
    pgas_stalker_thread_stats_t stats{};
};

struct application_signal_state {
    std::array<struct sigaction, 2> actions{};
    std::array<std::atomic<unsigned>, 2> readers{};
    std::atomic<uint64_t> published{};
    std::atomic<uint64_t> reset_claimed{ UINT64_MAX };
};

struct pgas_stalker_ctx {
    GumStalker *stalker;
    GumStalkerTransformer *transformer;

    pgas_stalker_config_t config;
    pgas_stalker_stats_t stats;
    pgas_x86_runtime *runtime;
    bool owns_runtime{};
    pgas_x86_xstate_layout xstate;
    std::unique_ptr<pgas_stalker_module_policy> module_policy;
    std::string main_basename;
    std::mutex module_cache_mutex;
    std::unordered_map<uintptr_t, bool> module_cache;
    std::mutex thread_mutex;
    std::mutex lifecycle_mutex;
    std::vector<std::unique_ptr<stalker_thread_record>> threads;
    uint64_t next_runtime_id;
    uint64_t followed_threads{};
    std::array<application_signal_state, 4> application_signals{};
    std::atomic_flag signal_action_writer = ATOMIC_FLAG_INIT;
    std::atomic<bool> signal_handlers_installed{};

    std::atomic<bool> active;
};

static thread_local stalker_thread_record *current_thread_record;
static thread_local pgas_stalker_ctx *current_thread_context;

static std::string basename_from_path(const char *path)
{
    if (path == nullptr || *path == '\0')
        return {};
    const char *slash = strrchr(path, '/');
    return slash == nullptr ? std::string(path) : std::string(slash + 1);
}

static std::string current_executable_basename()
{
    std::array<char, 4096> path{};
    const ssize_t size = readlink("/proc/self/exe", path.data(),
                                  path.size() - 1);
    if (size <= 0)
        return {};
    path[static_cast<size_t>(size)] = '\0';
    return basename_from_path(path.data());
}

static bool is_main_module(const pgas_stalker_ctx *ctx,
                           const std::string &basename)
{
    return basename.empty() || basename == ctx->main_basename;
}

static bool should_instrument_address(pgas_stalker_ctx *ctx,
                                      uint64_t address)
{
    Dl_info info{};
    const bool resolved = dladdr(reinterpret_cast<void *>(address), &info) != 0;
    const uintptr_t cache_key =
        resolved && info.dli_fbase != nullptr
            ? reinterpret_cast<uintptr_t>(info.dli_fbase)
            : static_cast<uintptr_t>(address >> 12);
    {
        std::lock_guard lock(ctx->module_cache_mutex);
        const auto cached = ctx->module_cache.find(cache_key);
        if (cached != ctx->module_cache.end())
            return cached->second;
    }

    const std::string basename =
        resolved ? basename_from_path(info.dli_fname) : std::string{};
    const bool instrument = resolved && ctx->module_policy->should_instrument(
                                              basename,
                                              is_main_module(ctx, basename));
    {
        std::lock_guard lock(ctx->module_cache_mutex);
        ctx->module_cache.emplace(cache_key, instrument);
    }
    return instrument;
}

static stalker_thread_record *create_thread_record(pgas_stalker_ctx *ctx,
                                                    uint64_t os_tid)
{
    auto record = std::make_unique<stalker_thread_record>();
    record->stats.os_tid = os_tid;
    record->stats.follow_events = 1;
    auto *result = record.get();
    std::lock_guard lock(ctx->thread_mutex);
    record->stats.runtime_id = ctx->next_runtime_id++;
    ctx->threads.push_back(std::move(record));
    return result;
}

static stalker_thread_record *register_current_thread(pgas_stalker_ctx *ctx)
{
    if (current_thread_context == ctx && current_thread_record != nullptr) {
        ++current_thread_record->stats.follow_events;
        return current_thread_record;
    }

    auto *result = create_thread_record(
        ctx, static_cast<uint64_t>(syscall(SYS_gettid)));
    current_thread_context = ctx;
    current_thread_record = result;
    return result;
}

static stalker_thread_record *bind_current_thread(pgas_stalker_ctx *ctx)
{
    if (current_thread_context == ctx && current_thread_record != nullptr)
        return current_thread_record;
    const uint64_t os_tid = static_cast<uint64_t>(syscall(SYS_gettid));
    std::lock_guard lock(ctx->thread_mutex);
    for (auto iterator = ctx->threads.rbegin(); iterator != ctx->threads.rend();
         ++iterator) {
        auto &stats = (*iterator)->stats;
        if (stats.os_tid == os_tid &&
            stats.follow_events > stats.unfollow_events) {
            current_thread_context = ctx;
            current_thread_record = iterator->get();
            return current_thread_record;
        }
    }
    return nullptr;
}

static void unregister_thread_id(pgas_stalker_ctx *ctx, uint64_t os_tid)
{
    std::lock_guard lock(ctx->thread_mutex);
    for (auto iterator = ctx->threads.rbegin(); iterator != ctx->threads.rend();
         ++iterator) {
        auto &stats = (*iterator)->stats;
        if (stats.os_tid == os_tid &&
            stats.follow_events > stats.unfollow_events) {
            ++stats.unfollow_events;
            return;
        }
    }
}

static void unregister_current_thread(pgas_stalker_ctx *ctx)
{
    if (current_thread_context != ctx || current_thread_record == nullptr)
        return;
    ++current_thread_record->stats.unfollow_events;
    current_thread_record = nullptr;
    current_thread_context = nullptr;
}

// ---------------------------------------------------------------------------
// Helpers: detect if a Capstone instruction has a memory operand
// ---------------------------------------------------------------------------

static bool is_mov_insn(unsigned int insn_id) {
    switch (insn_id) {
    case X86_INS_MOV:  case X86_INS_MOVABS:
    case X86_INS_MOVZX: case X86_INS_MOVSXD: case X86_INS_MOVSX:
    case X86_INS_MOVNTI: case X86_INS_MOVNTDQ: case X86_INS_MOVNTPS:
    case X86_INS_MOVNTPD:
    case X86_INS_MOVAPS: case X86_INS_MOVUPS: case X86_INS_MOVAPD:
    case X86_INS_MOVUPD: case X86_INS_MOVDQA: case X86_INS_MOVDQU:
    case X86_INS_MOVSD:  case X86_INS_MOVSS:
    case X86_INS_MOVQ:   case X86_INS_MOVD:
    case X86_INS_VMOVQ: case X86_INS_VMOVAPD: case X86_INS_VMOVAPS:
    case X86_INS_VMOVD: case X86_INS_VMOVDQA: case X86_INS_VMOVDQA32:
    case X86_INS_VMOVDQA64: case X86_INS_VMOVDQU: case X86_INS_VMOVDQU8:
    case X86_INS_VMOVDQU16: case X86_INS_VMOVDQU32:
    case X86_INS_VMOVDQU64: case X86_INS_VMOVSD: case X86_INS_VMOVSS:
    case X86_INS_VMOVUPD: case X86_INS_VMOVUPS:
        return true;
    default:
        return false;
    }
}

static bool mov_is_enabled(unsigned int insn_id,
                           const pgas_stalker_config_t *cfg)
{
    if ((insn_id == X86_INS_MOV || insn_id == X86_INS_MOVABS) &&
        !cfg->hook_mov)
        return false;
    if ((insn_id == X86_INS_MOVZX || insn_id == X86_INS_MOVSXD ||
         insn_id == X86_INS_MOVSX) &&
        !cfg->hook_movzx)
        return false;
    if ((insn_id == X86_INS_MOVNTI || insn_id == X86_INS_MOVNTDQ ||
         insn_id == X86_INS_MOVNTPS || insn_id == X86_INS_MOVNTPD) &&
        !cfg->hook_movnti)
        return false;
    return true;
}

static bool is_gpr(x86_reg reg)
{
    switch (reg) {
    case X86_REG_RAX: case X86_REG_EAX: case X86_REG_AX: case X86_REG_AL:
    case X86_REG_AH:
    case X86_REG_RBX: case X86_REG_EBX: case X86_REG_BX: case X86_REG_BL:
    case X86_REG_BH:
    case X86_REG_RCX: case X86_REG_ECX: case X86_REG_CX: case X86_REG_CL:
    case X86_REG_CH:
    case X86_REG_RDX: case X86_REG_EDX: case X86_REG_DX: case X86_REG_DL:
    case X86_REG_DH:
    case X86_REG_RSI: case X86_REG_ESI: case X86_REG_SI: case X86_REG_SIL:
    case X86_REG_RDI: case X86_REG_EDI: case X86_REG_DI: case X86_REG_DIL:
    case X86_REG_RBP: case X86_REG_EBP: case X86_REG_BP: case X86_REG_BPL:
    case X86_REG_RSP: case X86_REG_ESP: case X86_REG_SP: case X86_REG_SPL:
    case X86_REG_R8: case X86_REG_R8D: case X86_REG_R8W: case X86_REG_R8B:
    case X86_REG_R9: case X86_REG_R9D: case X86_REG_R9W: case X86_REG_R9B:
    case X86_REG_R10: case X86_REG_R10D: case X86_REG_R10W: case X86_REG_R10B:
    case X86_REG_R11: case X86_REG_R11D: case X86_REG_R11W: case X86_REG_R11B:
    case X86_REG_R12: case X86_REG_R12D: case X86_REG_R12W: case X86_REG_R12B:
    case X86_REG_R13: case X86_REG_R13D: case X86_REG_R13W: case X86_REG_R13B:
    case X86_REG_R14: case X86_REG_R14D: case X86_REG_R14W: case X86_REG_R14B:
    case X86_REG_R15: case X86_REG_R15D: case X86_REG_R15W: case X86_REG_R15B:
        return true;
    default:
        return false;
    }
}

static pgas_x86_register_class register_class(x86_reg reg)
{
    if (is_gpr(reg))
        return pgas_x86_register_class::gpr;
    if (reg >= X86_REG_XMM0 && reg <= X86_REG_XMM31)
        return pgas_x86_register_class::xmm;
    if (reg >= X86_REG_YMM0 && reg <= X86_REG_YMM31)
        return pgas_x86_register_class::ymm;
    if (reg >= X86_REG_ZMM0 && reg <= X86_REG_ZMM31)
        return pgas_x86_register_class::zmm;
    return pgas_x86_register_class::none;
}

static bool has_lock_prefix(const cs_insn *insn)
{
    const auto &x86 = insn->detail->x86;
    return x86.prefix[0] == X86_PREFIX_LOCK ||
           x86.prefix[1] == X86_PREFIX_LOCK ||
           x86.prefix[2] == X86_PREFIX_LOCK ||
           x86.prefix[3] == X86_PREFIX_LOCK;
}

static bool is_explicit_rmw_instruction(const cs_insn *insn)
{
    switch (insn->id) {
    case X86_INS_CMPXCHG:
    case X86_INS_CMPXCHG8B:
    case X86_INS_CMPXCHG16B:
    case X86_INS_XADD:
    case X86_INS_XCHG:
        return true;
    default:
        return false;
    }
}

static bool is_atomic_instruction(const cs_insn *insn)
{
    return has_lock_prefix(insn) || insn->id == X86_INS_XCHG;
}

static bool is_prefetch_instruction(const cs_insn *insn)
{
    return strncmp(insn->mnemonic, "prefetch", 8) == 0;
}

static bool is_gather_instruction(const cs_insn *insn)
{
    return insn->id == X86_INS_VPGATHERDD;
}

static bool is_scatter_instruction(const cs_insn *insn)
{
    return insn->id == X86_INS_VPSCATTERDD;
}

static bool is_opmask(x86_reg reg)
{
    return reg >= X86_REG_K0 && reg <= X86_REG_K7;
}

static uint8_t vector_register_bytes(x86_reg reg)
{
    if (reg >= X86_REG_XMM0 && reg <= X86_REG_XMM31)
        return 16;
    if (reg >= X86_REG_YMM0 && reg <= X86_REG_YMM31)
        return 32;
    if (reg >= X86_REG_ZMM0 && reg <= X86_REG_ZMM31)
        return 64;
    return 0;
}

enum class rep_string_kind : uint8_t {
    none,
    move,
    store,
    compare,
    scan,
    load,
};

static bool decode_rep_string(const cs_insn *insn, rep_string_kind &kind,
                              uint8_t &element_width)
{
    kind = rep_string_kind::none;
    element_width = 0;
    if (insn == nullptr || insn->detail == nullptr)
        return false;
    const auto &x86 = insn->detail->x86;
    if (x86.prefix[0] != X86_PREFIX_REP &&
        x86.prefix[0] != X86_PREFIX_REPNE)
        return false;
    switch (insn->id) {
    case X86_INS_MOVSB: kind = rep_string_kind::move; element_width = 1; break;
    case X86_INS_MOVSW: kind = rep_string_kind::move; element_width = 2; break;
    case X86_INS_MOVSD: kind = rep_string_kind::move; element_width = 4; break;
    case X86_INS_MOVSQ: kind = rep_string_kind::move; element_width = 8; break;
    case X86_INS_STOSB: kind = rep_string_kind::store; element_width = 1; break;
    case X86_INS_STOSW: kind = rep_string_kind::store; element_width = 2; break;
    case X86_INS_STOSD: kind = rep_string_kind::store; element_width = 4; break;
    case X86_INS_STOSQ: kind = rep_string_kind::store; element_width = 8; break;
    case X86_INS_CMPSB: kind = rep_string_kind::compare; element_width = 1; break;
    case X86_INS_CMPSW: kind = rep_string_kind::compare; element_width = 2; break;
    case X86_INS_CMPSD: kind = rep_string_kind::compare; element_width = 4; break;
    case X86_INS_CMPSQ: kind = rep_string_kind::compare; element_width = 8; break;
    case X86_INS_SCASB: kind = rep_string_kind::scan; element_width = 1; break;
    case X86_INS_SCASW: kind = rep_string_kind::scan; element_width = 2; break;
    case X86_INS_SCASD: kind = rep_string_kind::scan; element_width = 4; break;
    case X86_INS_SCASQ: kind = rep_string_kind::scan; element_width = 8; break;
    case X86_INS_LODSB: kind = rep_string_kind::load; element_width = 1; break;
    case X86_INS_LODSW: kind = rep_string_kind::load; element_width = 2; break;
    case X86_INS_LODSD: kind = rep_string_kind::load; element_width = 4; break;
    case X86_INS_LODSQ: kind = rep_string_kind::load; element_width = 8; break;
    default: return false;
    }
    return true;
}

// OPT 1: Skip stack-relative memory accesses at JIT time.
// RSP/RBP-based movs are local stack variables — never CXL addresses.
static bool is_stack_relative(x86_reg reg) {
    switch (reg) {
    case X86_REG_RSP: case X86_REG_ESP: case X86_REG_SP: case X86_REG_SPL:
    case X86_REG_RBP: case X86_REG_EBP: case X86_REG_BP: case X86_REG_BPL:
        return true;
    default:
        return false;
    }
}

static bool analyze_memory_instruction(
    const cs_insn *insn, const pgas_stalker_config_t *cfg,
    pgas_x86_memory_descriptor *out)
{
    *out = {};
    if (insn == nullptr || insn->detail == nullptr)
        return false;

    out->instruction_address = insn->address;
    out->instruction_id = insn->id;
    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", insn->mnemonic);
    out->instruction_size = static_cast<uint8_t>(
        std::min<size_t>(insn->size, out->instruction_bytes.size()));
    std::memcpy(out->instruction_bytes.data(), insn->bytes,
                out->instruction_size);
    Dl_info module_info{};
    if (dladdr(reinterpret_cast<const void *>(insn->address),
               &module_info) != 0) {
        const auto module = basename_from_path(module_info.dli_fname);
        snprintf(out->module_basename, sizeof(out->module_basename), "%s",
                 module.c_str());
    }
    out->atomic = is_atomic_instruction(insn);
    out->gather = is_gather_instruction(insn);
    out->scatter = is_scatter_instruction(insn);
    const cs_x86 *x86 = &insn->detail->x86;
    uint8_t memory_count = 0;
    for (uint8_t i = 0; i < x86->op_count; i++) {
        if (x86->operands[i].type == X86_OP_MEM) {
            ++memory_count;
            if (memory_count != 1)
                continue;
            out->memory_operand_index = i;
            out->base_register = x86->operands[i].mem.base;
            out->index_register = x86->operands[i].mem.index;
            out->vector_index_register = x86->operands[i].mem.index;
            out->scale = x86->operands[i].mem.scale;
            out->displacement = x86->operands[i].mem.disp;
            out->width = x86->operands[i].size;

            const auto access = x86->operands[i].access;
            if (out->gather) {
                out->access_class = pgas_x86_access_class::read;
            } else if (out->scatter) {
                out->access_class = pgas_x86_access_class::write;
            } else if (is_prefetch_instruction(insn)) {
                out->access_class = pgas_x86_access_class::prefetch;
            } else if (is_mov_insn(insn->id)) {
                out->access_class =
                    i == 0 ? pgas_x86_access_class::write
                           : pgas_x86_access_class::read;
            } else if ((access & CS_AC_READ) && (access & CS_AC_WRITE)) {
                out->access_class = pgas_x86_access_class::read_modify_write;
            } else if (access & CS_AC_READ) {
                out->access_class = pgas_x86_access_class::read;
            } else if (access & CS_AC_WRITE) {
                out->access_class = pgas_x86_access_class::write;
            } else {
                out->access_class = pgas_x86_access_class::read_modify_write;
            }
        }
    }
    if (memory_count == 0)
        return false;
    if (memory_count != 1)
        out->access_class = pgas_x86_access_class::unsupported;
    else if (out->atomic || is_explicit_rmw_instruction(insn))
        out->access_class = pgas_x86_access_class::read_modify_write;

    for (uint8_t i = 0; i < x86->op_count; ++i) {
        if (i == out->memory_operand_index)
            continue;
        if (x86->operands[i].type == X86_OP_REG) {
            const auto operand_reg =
                static_cast<x86_reg>(x86->operands[i].reg);
            if (is_opmask(operand_reg)) {
                out->mask_register = operand_reg;
                continue;
            }
            out->data_register = x86->operands[i].reg;
            out->register_class =
                register_class(static_cast<x86_reg>(out->data_register));
            break;
        }
    }

    if (out->gather || out->scatter) {
        out->lane_width = 4;
        out->index_width = 4;
        const uint8_t index_bytes = vector_register_bytes(
            static_cast<x86_reg>(out->vector_index_register));
        out->lane_count = index_bytes / out->index_width;
        if (out->mask_register == X86_REG_INVALID) {
            for (uint8_t i = 0; i < x86->op_count; ++i) {
                if (x86->operands[i].type != X86_OP_REG ||
                    x86->operands[i].reg == out->data_register ||
                    x86->operands[i].reg == out->vector_index_register)
                    continue;
                out->mask_register = x86->operands[i].reg;
            }
        }
    }

    const auto base = static_cast<x86_reg>(out->base_register);
    const auto index = static_cast<x86_reg>(out->index_register);
    const bool scalar_address =
        (base == X86_REG_INVALID || base == X86_REG_RIP || is_gpr(base)) &&
        (index == X86_REG_INVALID || is_gpr(index));
    const bool configured_mov = !is_mov_insn(insn->id) ||
                                mov_is_enabled(insn->id, cfg);
    const bool lane_access = (out->gather || out->scatter) &&
                             out->lane_count != 0 &&
                             out->mask_register != X86_REG_INVALID;
    out->replayable = memory_count == 1 && out->width >= 1 &&
                      out->width <= 64 &&
                      (scalar_address || lane_access) && configured_mov &&
                      out->access_class != pgas_x86_access_class::unsupported;
    return true;
}

// ---------------------------------------------------------------------------
// Register <-> GumCpuContext mapping
// ---------------------------------------------------------------------------

#if defined(__x86_64__)
static uint64_t read_reg(const GumCpuContext *cpu, x86_reg reg) {
    switch (reg) {
    case X86_REG_RAX: case X86_REG_EAX: case X86_REG_AX: case X86_REG_AL: return cpu->rax;
    case X86_REG_RBX: case X86_REG_EBX: case X86_REG_BX: case X86_REG_BL: return cpu->rbx;
    case X86_REG_RCX: case X86_REG_ECX: case X86_REG_CX: case X86_REG_CL: return cpu->rcx;
    case X86_REG_RDX: case X86_REG_EDX: case X86_REG_DX: case X86_REG_DL: return cpu->rdx;
    case X86_REG_RSI: case X86_REG_ESI: case X86_REG_SI: case X86_REG_SIL: return cpu->rsi;
    case X86_REG_RDI: case X86_REG_EDI: case X86_REG_DI: case X86_REG_DIL: return cpu->rdi;
    case X86_REG_RBP: case X86_REG_EBP: case X86_REG_BP: case X86_REG_BPL: return cpu->rbp;
    case X86_REG_RSP: case X86_REG_ESP: case X86_REG_SP: case X86_REG_SPL: return cpu->rsp;
    case X86_REG_R8:  case X86_REG_R8D:  case X86_REG_R8W:  case X86_REG_R8B:  return cpu->r8;
    case X86_REG_R9:  case X86_REG_R9D:  case X86_REG_R9W:  case X86_REG_R9B:  return cpu->r9;
    case X86_REG_R10: case X86_REG_R10D: case X86_REG_R10W: case X86_REG_R10B: return cpu->r10;
    case X86_REG_R11: case X86_REG_R11D: case X86_REG_R11W: case X86_REG_R11B: return cpu->r11;
    case X86_REG_R12: case X86_REG_R12D: case X86_REG_R12W: case X86_REG_R12B: return cpu->r12;
    case X86_REG_R13: case X86_REG_R13D: case X86_REG_R13W: case X86_REG_R13B: return cpu->r13;
    case X86_REG_R14: case X86_REG_R14D: case X86_REG_R14W: case X86_REG_R14B: return cpu->r14;
    case X86_REG_R15: case X86_REG_R15D: case X86_REG_R15W: case X86_REG_R15B: return cpu->r15;
    case X86_REG_RIP: return cpu->rip;
    default: return 0;
    }
}

// Map Capstone register to Frida GumX86Reg for inline codegen
static GumX86Reg cs_to_gum_reg(x86_reg reg) {
    switch (reg) {
    case X86_REG_RAX: case X86_REG_EAX: case X86_REG_AX:
    case X86_REG_AL: case X86_REG_AH: return GUM_X86_RAX;
    case X86_REG_RBX: case X86_REG_EBX: case X86_REG_BX:
    case X86_REG_BL: case X86_REG_BH: return GUM_X86_RBX;
    case X86_REG_RCX: case X86_REG_ECX: case X86_REG_CX:
    case X86_REG_CL: case X86_REG_CH: return GUM_X86_RCX;
    case X86_REG_RDX: case X86_REG_EDX: case X86_REG_DX:
    case X86_REG_DL: case X86_REG_DH: return GUM_X86_RDX;
    case X86_REG_RSI: case X86_REG_ESI: case X86_REG_SI:
    case X86_REG_SIL: return GUM_X86_RSI;
    case X86_REG_RDI: case X86_REG_EDI: case X86_REG_DI:
    case X86_REG_DIL: return GUM_X86_RDI;
    case X86_REG_RBP: case X86_REG_EBP: case X86_REG_BP:
    case X86_REG_BPL: return GUM_X86_RBP;
    case X86_REG_RSP: case X86_REG_ESP: case X86_REG_SP:
    case X86_REG_SPL: return GUM_X86_RSP;
    case X86_REG_R8: case X86_REG_R8D: case X86_REG_R8W:
    case X86_REG_R8B: return GUM_X86_R8;
    case X86_REG_R9: case X86_REG_R9D: case X86_REG_R9W:
    case X86_REG_R9B: return GUM_X86_R9;
    case X86_REG_R10: case X86_REG_R10D: case X86_REG_R10W:
    case X86_REG_R10B: return GUM_X86_R10;
    case X86_REG_R11: case X86_REG_R11D: case X86_REG_R11W:
    case X86_REG_R11B: return GUM_X86_R11;
    case X86_REG_R12: case X86_REG_R12D: case X86_REG_R12W:
    case X86_REG_R12B: return GUM_X86_R12;
    case X86_REG_R13: case X86_REG_R13D: case X86_REG_R13W:
    case X86_REG_R13B: return GUM_X86_R13;
    case X86_REG_R14: case X86_REG_R14D: case X86_REG_R14W:
    case X86_REG_R14B: return GUM_X86_R14;
    case X86_REG_R15: case X86_REG_R15D: case X86_REG_R15W:
    case X86_REG_R15B: return GUM_X86_R15;
    default: return GUM_X86_NONE;
    }
}
#endif // __x86_64__

static uint64_t compute_ea(const GumCpuContext *cpu,
                           const pgas_x86_memory_descriptor *descriptor) {
    uint64_t ea = static_cast<uint64_t>(descriptor->displacement);
    if (descriptor->base_register != X86_REG_INVALID)
        ea += read_reg(cpu, static_cast<x86_reg>(descriptor->base_register));
    if (descriptor->index_register != X86_REG_INVALID)
        ea += read_reg(cpu, static_cast<x86_reg>(descriptor->index_register)) *
              descriptor->scale;
    return ea;
}

static uint64_t read_gum_register(const GumCpuContext *cpu, GumX86Reg reg)
{
    switch (reg) {
    case GUM_X86_RAX: return cpu->rax;
    case GUM_X86_RBX: return cpu->rbx;
    case GUM_X86_RCX: return cpu->rcx;
    case GUM_X86_RDX: return cpu->rdx;
    case GUM_X86_RSI: return cpu->rsi;
    case GUM_X86_RDI: return cpu->rdi;
    case GUM_X86_R8: return cpu->r8;
    case GUM_X86_R9: return cpu->r9;
    case GUM_X86_R10: return cpu->r10;
    case GUM_X86_R11: return cpu->r11;
    case GUM_X86_R12: return cpu->r12;
    case GUM_X86_R14: return cpu->r14;
    case GUM_X86_R15: return cpu->r15;
    default: return 0;
    }
}

static int vector_register_index(x86_reg reg)
{
    if (reg >= X86_REG_XMM0 && reg <= X86_REG_XMM31)
        return reg - X86_REG_XMM0;
    if (reg >= X86_REG_YMM0 && reg <= X86_REG_YMM31)
        return reg - X86_REG_YMM0;
    if (reg >= X86_REG_ZMM0 && reg <= X86_REG_ZMM31)
        return reg - X86_REG_ZMM0;
    return -1;
}

static bool add_signed_offset(uint64_t base, int64_t offset, uint64_t &result)
{
    if (offset >= 0)
        return !__builtin_add_overflow(base, static_cast<uint64_t>(offset),
                                       &result);
    const uint64_t magnitude = static_cast<uint64_t>(-(offset + 1)) + 1;
    if (base < magnitude)
        return false;
    result = base - magnitude;
    return true;
}

// ---------------------------------------------------------------------------
// OPT 4: Lock-free bump allocator for callout metadata
// ---------------------------------------------------------------------------

struct memory_callout_data {
    uint64_t pgas_base;
    uint64_t pgas_size;
    uint16_t local_node_id;
    uint16_t num_nodes;
    pgas_stalker_stats_t *stats;
    pgas_x86_runtime *runtime;
    pgas_stalker_ctx *context;
    pgas_x86_memory_descriptor descriptor;
    rep_string_kind rep_kind{};
    uint8_t rep_element_width{};
    uint8_t rep_address_size{};
    uint8_t rep_segment_prefix{};
    uint32_t saved_flags_offset{};
    GumX86Reg xstate_pointer;
    char labels[5];
};

static int plan_vector_lanes(const GumCpuContext *cpu,
                             const memory_callout_data *cd,
                             pgas_x86_replay_plan &plan)
{
    const auto &descriptor = cd->descriptor;
    const int index_register = vector_register_index(
        static_cast<x86_reg>(descriptor.vector_index_register));
    if (index_register < 0 || descriptor.index_width != 4 ||
        descriptor.lane_width != 4 || descriptor.lane_count == 0 ||
        descriptor.lane_count > 16)
        return -ENOTSUP;

    const auto *xstate = reinterpret_cast<const std::byte *>(
        read_gum_register(cpu, cd->xstate_pointer));
    if (xstate == nullptr)
        return -EINVAL;
    const size_t vector_size = descriptor.lane_count * descriptor.index_width;
    std::array<std::byte, 64> index_bytes{};
    int result = pgas_x86_read_vector(
        cd->context->xstate, xstate, cd->context->xstate.area_size,
        static_cast<unsigned>(index_register), index_bytes.data(),
        vector_size);
    if (result != 0)
        return result;

    uint64_t active_mask{};
    const auto mask_reg = static_cast<x86_reg>(descriptor.mask_register);
    if (is_opmask(mask_reg)) {
        result = pgas_x86_read_opmask(
            cd->context->xstate, xstate, cd->context->xstate.area_size,
            static_cast<unsigned>(mask_reg - X86_REG_K0), active_mask);
        if (result != 0)
            return result;
    } else {
        const int mask_register = vector_register_index(mask_reg);
        if (mask_register < 0)
            return -ENOTSUP;
        std::array<std::byte, 64> mask_bytes{};
        result = pgas_x86_read_vector(
            cd->context->xstate, xstate, cd->context->xstate.area_size,
            static_cast<unsigned>(mask_register), mask_bytes.data(),
            vector_size);
        if (result != 0)
            return result;
        for (size_t lane = 0; lane < descriptor.lane_count; ++lane) {
            int32_t mask_value{};
            std::memcpy(&mask_value,
                        mask_bytes.data() + lane * descriptor.index_width,
                        sizeof(mask_value));
            if (mask_value < 0)
                active_mask |= UINT64_C(1) << lane;
        }
    }

    uint64_t base_address{};
    if (descriptor.base_register != X86_REG_INVALID)
        base_address = read_reg(
            cpu, static_cast<x86_reg>(descriptor.base_register));
    if (!add_signed_offset(base_address, descriptor.displacement,
                           base_address))
        return -EOVERFLOW;

    std::array<uint64_t, 16> addresses{};
    for (size_t lane = 0; lane < descriptor.lane_count; ++lane) {
        if ((active_mask & (UINT64_C(1) << lane)) == 0)
            continue;
        int32_t index{};
        std::memcpy(&index,
                    index_bytes.data() + lane * descriptor.index_width,
                    sizeof(index));
        const int64_t scaled = static_cast<int64_t>(index) * descriptor.scale;
        if (!add_signed_offset(base_address, scaled, addresses[lane]))
            return -EOVERFLOW;
    }

    const pgas_x86_runtime_config config{
        cd->pgas_base, cd->pgas_size, cd->local_node_id, cd->num_nodes, {},
        nullptr, nullptr
    };
    plan = pgas_x86_plan_lanes(config, addresses.data(),
                               descriptor.lane_count,
                               descriptor.lane_width, active_mask);
    return plan.status;
}

// Bump allocator: single contiguous block, no locks, no free
#define CALLOUT_POOL_CAPACITY (1024 * 1024)
static memory_callout_data g_callout_pool_storage[CALLOUT_POOL_CAPACITY];
static uint64_t g_callout_pool_next = 0;

static memory_callout_data *alloc_callout_data() {
    uint64_t idx = __atomic_fetch_add(&g_callout_pool_next, 1, __ATOMIC_RELAXED);
    if (idx >= CALLOUT_POOL_CAPACITY) {
        SPDLOG_ERROR("Callout pool exhausted ({} entries)", CALLOUT_POOL_CAPACITY);
        return nullptr;
    }
    return &g_callout_pool_storage[idx];
}

struct pending_access {
    pgas_x86_replay_transaction transaction{};
    const memory_callout_data *callout{};
    uint64_t effective_address{};
};

static thread_local pending_access current_access;
static thread_local std::atomic<bool> current_access_signal_active{};

struct pending_rep_string {
    const memory_callout_data *callout{};
    uint64_t initial_count{};
    uint64_t initial_source{};
    uint64_t initial_destination{};
    uint64_t source_low{};
    uint64_t destination_low{};
    uint64_t total_bytes{};
    bool backward{};
    bool active{};
    pgas_x86_bulk_lock lock{};
};

static thread_local pending_rep_string current_rep_string;
static thread_local std::atomic<bool> current_rep_signal_active{};

static void reset_current_rep_string()
{
    current_rep_string.callout = nullptr;
    current_rep_string.initial_count = 0;
    current_rep_string.initial_source = 0;
    current_rep_string.initial_destination = 0;
    current_rep_string.source_low = 0;
    current_rep_string.destination_low = 0;
    current_rep_string.total_bytes = 0;
    current_rep_string.backward = false;
    current_rep_string.active = false;
    current_rep_string.lock.runtime = nullptr;
    current_rep_string.lock.acquired = 0;
    current_rep_string.lock.active = false;
}

static_assert(std::atomic<bool>::is_always_lock_free);
static_assert(std::atomic<unsigned>::is_always_lock_free);
static_assert(std::atomic<pgas_stalker_ctx *>::is_always_lock_free);
static_assert(__atomic_always_lock_free(sizeof(uint64_t), nullptr));

namespace {

constexpr std::array<int, 4> replay_fault_signals{
    SIGSEGV, SIGBUS, SIGILL, SIGFPE,
};

std::atomic<pgas_stalker_ctx *> replay_signal_context{};

using real_sigaction_fn = int (*)(int, const struct sigaction *,
                                  struct sigaction *);

real_sigaction_fn resolve_real_sigaction()
{
    static const auto implementation = reinterpret_cast<real_sigaction_fn>(
        dlsym(RTLD_NEXT, "sigaction"));
    return implementation;
}

int call_real_sigaction(int signal_number, const struct sigaction *action,
                        struct sigaction *old_action)
{
    const auto implementation = resolve_real_sigaction();
    if (implementation == nullptr) {
        errno = ENOSYS;
        return -1;
    }
    return implementation(signal_number, action, old_action);
}

size_t replay_signal_index(int signal_number)
{
    for (size_t index = 0; index < replay_fault_signals.size(); ++index) {
        if (replay_fault_signals[index] == signal_number)
            return index;
    }
    return replay_fault_signals.size();
}

struct application_action_snapshot {
    struct sigaction action{};
    uint64_t publication{};
};

application_action_snapshot load_application_action(
    application_signal_state &state)
{
    for (;;) {
        const uint64_t publication = state.published.load(
            std::memory_order_acquire);
        const unsigned slot = static_cast<unsigned>(publication & 1U);
        state.readers[slot].fetch_add(1, std::memory_order_acquire);
        if (state.published.load(std::memory_order_acquire) == publication) {
            application_action_snapshot snapshot{
                state.actions[slot], publication
            };
            state.readers[slot].fetch_sub(1, std::memory_order_release);
            return snapshot;
        }
        state.readers[slot].fetch_sub(1, std::memory_order_release);
    }
}

void block_all_signals(sigset_t &old_mask)
{
    sigset_t all_signals;
    sigfillset(&all_signals);
    sigprocmask(SIG_SETMASK, &all_signals, &old_mask);
}

void restore_signal_mask(const sigset_t &old_mask)
{
    sigprocmask(SIG_SETMASK, &old_mask, nullptr);
}

void lock_signal_action_writer(pgas_stalker_ctx *ctx)
{
    while (ctx->signal_action_writer.test_and_set(std::memory_order_acquire)) {
    }
}

void unlock_signal_action_writer(pgas_stalker_ctx *ctx)
{
    ctx->signal_action_writer.clear(std::memory_order_release);
}

void publish_application_action(application_signal_state &state,
                                const struct sigaction &action,
                                uint64_t current_publication)
{
    const uint64_t next_publication = current_publication + 1;
    const unsigned next_slot =
        static_cast<unsigned>(next_publication & 1U);
    while (state.readers[next_slot].load(std::memory_order_acquire) != 0) {
    }
    state.actions[next_slot] = action;
    state.published.store(next_publication, std::memory_order_release);
}

[[noreturn]] void restore_default_and_raise(int signal_number)
{
    struct sigaction action{};
    action.sa_handler = SIG_DFL;
    sigemptyset(&action.sa_mask);
    call_real_sigaction(signal_number, &action, nullptr);
    sigset_t signal_set;
    sigemptyset(&signal_set);
    sigaddset(&signal_set, signal_number);
    sigprocmask(SIG_UNBLOCK, &signal_set, nullptr);
    raise(signal_number);
    _exit(128 + signal_number);
}

void chain_replay_signal(const struct sigaction &saved, int signal_number,
                         siginfo_t *info, void *ucontext)
{
    if (saved.sa_handler == SIG_IGN)
        return;
    if (saved.sa_handler == SIG_DFL)
        restore_default_and_raise(signal_number);

    if ((saved.sa_flags & SA_SIGINFO) != 0)
        saved.sa_sigaction(signal_number, info, ucontext);
    else
        saved.sa_handler(signal_number);
}

void replay_signal_handler(int signal_number, siginfo_t *info, void *ucontext)
{
    auto *ctx = replay_signal_context.load(std::memory_order_acquire);
    const size_t signal_index = replay_signal_index(signal_number);
    if (ctx == nullptr || signal_index == replay_fault_signals.size())
        restore_default_and_raise(signal_number);

    if (current_thread_context == ctx && current_thread_record != nullptr &&
        current_access_signal_active.exchange(false,
                                              std::memory_order_acq_rel)) {
        pgas_x86_replay_abort(current_access.transaction);
        current_access.callout = nullptr;
        __atomic_fetch_add(
            &current_thread_record->stats.transaction_aborts, UINT64_C(1),
            __ATOMIC_RELAXED);
        __atomic_fetch_add(
            &current_thread_record->stats.signal_cleanups, UINT64_C(1),
            __ATOMIC_RELAXED);
        const uint64_t active = __atomic_load_n(
            &current_thread_record->stats.active_transactions,
            __ATOMIC_RELAXED);
        if (active != 0) {
            __atomic_fetch_sub(
                &current_thread_record->stats.active_transactions,
                UINT64_C(1), __ATOMIC_RELAXED);
        }
    }

    if (current_thread_context == ctx && current_thread_record != nullptr &&
        current_rep_signal_active.exchange(false,
                                           std::memory_order_acq_rel)) {
        pgas_x86_bulk_unlock_ranges(current_rep_string.lock);
        reset_current_rep_string();
        __atomic_fetch_add(
            &current_thread_record->stats.transaction_aborts, UINT64_C(1),
            __ATOMIC_RELAXED);
        __atomic_fetch_add(
            &current_thread_record->stats.signal_cleanups, UINT64_C(1),
            __ATOMIC_RELAXED);
        __atomic_fetch_add(&current_thread_record->stats.failures,
                           UINT64_C(1), __ATOMIC_RELAXED);
        // Network commits are not async-signal-safe.  A fault after a native
        // REP may have changed only the shadow, so continuing into an
        // application longjmp would expose stale remote state.  Fail closed.
        restore_default_and_raise(signal_number);
    }

    auto &state = ctx->application_signals[signal_index];
    const auto snapshot = load_application_action(state);
    const struct sigaction &saved = snapshot.action;
    if ((saved.sa_flags & SA_RESETHAND) != 0 &&
        state.reset_claimed.exchange(snapshot.publication,
                                     std::memory_order_acq_rel) ==
            snapshot.publication) {
        struct sigaction default_action{};
        default_action.sa_handler = SIG_DFL;
        sigemptyset(&default_action.sa_mask);
        chain_replay_signal(default_action, signal_number, info, ucontext);
    }
    chain_replay_signal(saved, signal_number, info, ucontext);
}

struct sigaction replay_wrapper_action(const struct sigaction &application)
{
    struct sigaction wrapper{};
    wrapper.sa_sigaction = replay_signal_handler;
    wrapper.sa_mask = application.sa_mask;
    wrapper.sa_flags = SA_SIGINFO |
        (application.sa_flags & (SA_ONSTACK | SA_NODEFER | SA_RESTART));
    return wrapper;
}

bool install_replay_signal_handlers(pgas_stalker_ctx *ctx)
{
    if (ctx->signal_handlers_installed.load(std::memory_order_acquire))
        return true;

    pgas_stalker_ctx *expected = nullptr;
    if (!replay_signal_context.compare_exchange_strong(
            expected, ctx, std::memory_order_acq_rel) && expected != ctx)
        return false;

    sigset_t old_mask;
    block_all_signals(old_mask);
    lock_signal_action_writer(ctx);
    size_t installed{};
    for (; installed < replay_fault_signals.size(); ++installed) {
        const int signal_number = replay_fault_signals[installed];
        struct sigaction application{};
        if (call_real_sigaction(signal_number, nullptr, &application) != 0)
            break;
        auto &state = ctx->application_signals[installed];
        state.actions[0] = application;
        state.published.store(0, std::memory_order_relaxed);
        state.reset_claimed.store(UINT64_MAX, std::memory_order_relaxed);
        const struct sigaction wrapper = replay_wrapper_action(application);
        if (call_real_sigaction(signal_number, &wrapper, nullptr) != 0)
            break;
    }
    if (installed == replay_fault_signals.size()) {
        ctx->signal_handlers_installed.store(true, std::memory_order_release);
        unlock_signal_action_writer(ctx);
        restore_signal_mask(old_mask);
        return true;
    }

    while (installed != 0) {
        --installed;
        const auto snapshot = load_application_action(
            ctx->application_signals[installed]);
        call_real_sigaction(
            replay_fault_signals[installed],
            &snapshot.action, nullptr);
    }
    unlock_signal_action_writer(ctx);
    restore_signal_mask(old_mask);
    replay_signal_context.store(nullptr, std::memory_order_release);
    return false;
}

void restore_replay_signal_handlers(pgas_stalker_ctx *ctx)
{
    if (!ctx->signal_handlers_installed.load(std::memory_order_acquire))
        return;
    sigset_t old_mask;
    block_all_signals(old_mask);
    lock_signal_action_writer(ctx);
    ctx->signal_handlers_installed.store(false, std::memory_order_release);
    for (size_t index = 0; index < replay_fault_signals.size(); ++index) {
        auto &state = ctx->application_signals[index];
        const auto snapshot = load_application_action(state);
        struct sigaction application = snapshot.action;
        if ((application.sa_flags & SA_RESETHAND) != 0 &&
            state.reset_claimed.load(std::memory_order_acquire) ==
                snapshot.publication) {
            application = {};
            application.sa_handler = SIG_DFL;
            sigemptyset(&application.sa_mask);
        }
        call_real_sigaction(replay_fault_signals[index], &application,
                            nullptr);
    }
    pgas_stalker_ctx *expected = ctx;
    replay_signal_context.compare_exchange_strong(
        expected, nullptr, std::memory_order_acq_rel);
    unlock_signal_action_writer(ctx);
    restore_signal_mask(old_mask);
}

} // namespace

static const char *access_class_name(pgas_x86_access_class access_class)
{
    switch (access_class) {
    case pgas_x86_access_class::read:
        return "read";
    case pgas_x86_access_class::write:
        return "write";
    case pgas_x86_access_class::read_modify_write:
        return "read_modify_write";
    case pgas_x86_access_class::prefetch:
        return "prefetch";
    case pgas_x86_access_class::unsupported:
        return "unsupported";
    }
    return "unsupported";
}

static const char *transaction_phase_name(pgas_x86_transaction_phase phase)
{
    switch (phase) {
    case pgas_x86_transaction_phase::plan: return "plan";
    case pgas_x86_transaction_phase::prepare: return "prepare";
    case pgas_x86_transaction_phase::execute: return "execute";
    case pgas_x86_transaction_phase::commit: return "commit";
    case pgas_x86_transaction_phase::cleanup: return "cleanup";
    }
    return "plan";
}

static uint16_t target_node_for(const memory_callout_data *cd,
                                uint64_t effective_address)
{
    if (cd->num_nodes == 0 || cd->pgas_size == 0)
        return UINT16_MAX;
    const uint64_t node_size = cd->pgas_size / cd->num_nodes;
    if (node_size == 0 || effective_address < cd->pgas_base)
        return UINT16_MAX;
    uint64_t node = (effective_address - cd->pgas_base) / node_size;
    if (node >= cd->num_nodes)
        node = cd->num_nodes - 1;
    return static_cast<uint16_t>(node);
}

[[noreturn]] static void emit_fatal_failure(
    const pgas_x86_failure &failure, const char *unsupported)
{
    char instruction_bytes[31]{};
    constexpr char hex[] = "0123456789abcdef";
    const size_t instruction_size = std::min<size_t>(
        failure.instruction_size, failure.instruction_bytes.size());
    for (size_t i = 0; i < instruction_size; ++i) {
        instruction_bytes[2 * i] = hex[failure.instruction_bytes[i] >> 4];
        instruction_bytes[2 * i + 1] =
            hex[failure.instruction_bytes[i] & 0xf];
    }
    dprintf(STDERR_FILENO,
            "PGAS_X86_FAILURE thread_id=%lu pc=0x%lx mnemonic=%s(%u) "
            "instruction_bytes=%s module=%s phase=%s operand=%u lane=%u "
            "ea=0x%lx width=%zu access_class=%s segment=%u node=%u "
            "transport_error=%d transport_status=%d unsupported=%s\n",
            failure.thread_id, failure.instruction_address,
            failure.mnemonic, failure.instruction_id,
            instruction_bytes, failure.module_basename,
            transaction_phase_name(failure.phase), failure.operand_index,
            failure.lane_index,
            failure.effective_address, failure.width,
            access_class_name(failure.access_class), failure.segment_index,
            failure.target_node, failure.transport_error,
            failure.transport_error, unsupported);
    dprintf(STDOUT_FILENO,
            "{\"kind\":\"pgas_x86_failure\",\"thread_id\":%lu,"
            "\"pc\":%lu,\"mnemonic\":\"%s\",\"instruction_id\":%u,"
            "\"instruction_bytes\":\"%s\",\"module\":\"%s\","
            "\"phase\":\"%s\",\"operand\":%u,\"lane\":%u,"
            "\"segment\":%u,\"effective_address\":%lu,\"width\":%zu,"
            "\"node\":%u,"
            "\"transport_status\":%d}\n",
            failure.thread_id, failure.instruction_address,
            failure.mnemonic, failure.instruction_id, instruction_bytes,
            failure.module_basename, transaction_phase_name(failure.phase),
            failure.operand_index, failure.lane_index,
            failure.segment_index,
            failure.effective_address, failure.width, failure.target_node,
            failure.transport_error);
    _exit(128 + SIGBUS);
}

[[noreturn]] static void strict_access_failure(
    const memory_callout_data *cd, uint64_t effective_address, int error,
    pgas_x86_transaction_phase phase = pgas_x86_transaction_phase::plan,
    uint8_t lane_index = UINT8_MAX,
    uint16_t segment_index = UINT16_MAX)
{
    const auto &descriptor = cd->descriptor;
    if (current_thread_record != nullptr &&
        current_thread_context == cd->context) {
        if (error == -ENOTSUP)
            ++current_thread_record->stats.unsupported;
        else
            ++current_thread_record->stats.failures;
    }
    pgas_x86_failure failure{};
    failure.thread_id = static_cast<uint64_t>(syscall(SYS_gettid));
    failure.instruction_address = descriptor.instruction_address;
    failure.instruction_id = descriptor.instruction_id;
    std::memcpy(failure.mnemonic, descriptor.mnemonic,
                sizeof(failure.mnemonic));
    failure.instruction_size = descriptor.instruction_size;
    failure.instruction_bytes = descriptor.instruction_bytes;
    std::memcpy(failure.module_basename, descriptor.module_basename,
                sizeof(failure.module_basename));
    failure.access_class = descriptor.access_class;
    failure.phase = phase;
    failure.effective_address = effective_address;
    failure.width = lane_index != UINT8_MAX && descriptor.lane_width != 0
                        ? descriptor.lane_width
                        : descriptor.width;
    failure.operand_index = descriptor.memory_operand_index;
    failure.lane_index = lane_index;
    failure.segment_index = static_cast<uint8_t>(
        std::min<uint16_t>(segment_index, UINT8_MAX));
    failure.target_node = target_node_for(cd, effective_address);
    failure.transport_error = error;
    emit_fatal_failure(failure,
                       error == -ENOTSUP ? descriptor.mnemonic : "none");
}

static void runtime_failure(void *, const pgas_x86_failure &failure)
{
    if (current_thread_record != nullptr)
        ++current_thread_record->stats.failures;
    emit_fatal_failure(failure, "none");
}

static bool rep_range_low(uint64_t pointer, uint64_t count, uint8_t width,
                          bool backward, uint64_t &low, uint64_t &bytes)
{
    if (__builtin_mul_overflow(count, static_cast<uint64_t>(width), &bytes))
        return false;
    low = pointer;
    if (backward && count != 0) {
        uint64_t delta{};
        if (__builtin_mul_overflow(count - 1,
                                   static_cast<uint64_t>(width), &delta) ||
            pointer < delta)
            return false;
        low = pointer - delta;
    }
    uint64_t end{};
    return !__builtin_add_overflow(low, bytes, &end);
}

static bool rep_range_intersects(const memory_callout_data *cd,
                                 uint64_t address, uint64_t size)
{
    if (size == 0)
        return false;
    uint64_t end{};
    uint64_t pgas_end{};
    if (__builtin_add_overflow(address, size, &end) ||
        __builtin_add_overflow(cd->pgas_base, cd->pgas_size, &pgas_end))
        return false;
    return address < pgas_end && end > cd->pgas_base;
}

static bool rep_range32_intersects(const memory_callout_data *cd,
                                   uint32_t pointer, uint64_t count,
                                   uint8_t width, bool backward,
                                   uint64_t segment_base, bool &overflow)
{
    overflow = false;
    uint64_t bytes{};
    if (__builtin_mul_overflow(count, static_cast<uint64_t>(width), &bytes)) {
        overflow = true;
        return false;
    }
    if (bytes == 0)
        return false;
    constexpr uint64_t address_space = UINT64_C(1) << 32;
    bool crossing_intersects = false;
    const uint64_t crossing_tail = pointer % width;
    if (crossing_tail != 0) {
        const uint64_t crossing_start =
            address_space - width + crossing_tail;
        const uint64_t distance = backward
            ? ((static_cast<uint64_t>(pointer) + address_space -
                crossing_start) % address_space) / width
            : ((crossing_start + address_space -
                static_cast<uint64_t>(pointer)) % address_space) / width;
        if (distance < count) {
            uint64_t boundary{};
            if (__builtin_add_overflow(segment_base, address_space,
                                       &boundary) ||
                crossing_tail > UINT64_MAX - boundary) {
                overflow = true;
                return false;
            }
            crossing_intersects = rep_range_intersects(
                cd, boundary, crossing_tail);
        }
    }
    if (bytes >= address_space) {
        uint64_t end{};
        if (__builtin_add_overflow(segment_base, address_space, &end)) {
            overflow = true;
            return false;
        }
        return crossing_intersects ||
               rep_range_intersects(cd, segment_base, address_space);
    }

    uint32_t start = pointer;
    if (backward) {
        const uint64_t delta = ((count - 1) * width) % address_space;
        start = static_cast<uint32_t>(pointer - static_cast<uint32_t>(delta));
    }
    const uint64_t first_size = std::min<uint64_t>(
        bytes, address_space - static_cast<uint64_t>(start));
    uint64_t first_address{};
    if (__builtin_add_overflow(segment_base, static_cast<uint64_t>(start),
                               &first_address)) {
        overflow = true;
        return false;
    }
    if (first_size > UINT64_MAX - first_address) {
        overflow = true;
        return false;
    }
    if (crossing_intersects ||
        rep_range_intersects(cd, first_address, first_size))
        return true;
    const uint64_t second_size = bytes - first_size;
    if (second_size != 0 && second_size > UINT64_MAX - segment_base) {
        overflow = true;
        return false;
    }
    return second_size != 0 &&
           rep_range_intersects(cd, segment_base, second_size);
}

static void rep_sync_or_fail(const memory_callout_data *cd, uint64_t address,
                             uint64_t bytes, bool refresh)
{
    if (bytes == 0 || !rep_range_intersects(cd, address, bytes))
        return;
    if (bytes > SIZE_MAX)
        strict_access_failure(cd, address, -EOVERFLOW);
    const int result = refresh
        ? pgas_x86_bulk_refresh_locked(
              cd->runtime, reinterpret_cast<void *>(address),
              static_cast<size_t>(bytes))
        : pgas_x86_bulk_flush_locked(
              cd->runtime, reinterpret_cast<const void *>(address),
              static_cast<size_t>(bytes));
    if (result != 0)
        strict_access_failure(
            cd, address, result,
            refresh ? pgas_x86_transaction_phase::prepare
                    : pgas_x86_transaction_phase::commit);
}

static void rep_pre_callout(GumCpuContext *cpu_context, gpointer user_data)
{
    auto *cd = static_cast<memory_callout_data *>(user_data);
    if (current_rep_string.active)
        strict_access_failure(cd, cpu_context->rip, -EBUSY);

    uint64_t saved_flags{};
    std::memcpy(&saved_flags,
                reinterpret_cast<const void *>(
                    cpu_context->rsp + cd->saved_flags_offset),
                sizeof(saved_flags));
    const bool backward = (saved_flags & (UINT64_C(1) << 10)) != 0;
    const uint64_t count = cd->rep_address_size == 4
        ? static_cast<uint32_t>(cpu_context->rcx) : cpu_context->rcx;
    if (count == 0) {
        reset_current_rep_string();
        return;
    }
    uint64_t source_pointer = cd->rep_address_size == 4
        ? static_cast<uint32_t>(cpu_context->rsi) : cpu_context->rsi;
    const uint64_t destination_pointer = cd->rep_address_size == 4
        ? static_cast<uint32_t>(cpu_context->rdi) : cpu_context->rdi;
    uint64_t segment_base{};
    if (cd->rep_segment_prefix == X86_PREFIX_FS ||
        cd->rep_segment_prefix == X86_PREFIX_GS) {
        unsigned long queried_base{};
        const int request = cd->rep_segment_prefix == X86_PREFIX_FS
            ? ARCH_GET_FS : ARCH_GET_GS;
        if (syscall(SYS_arch_prctl, request, &queried_base) != 0)
            strict_access_failure(cd, source_pointer, -errno);
        segment_base = queried_base;
    }

    const bool has_source = cd->rep_kind == rep_string_kind::move ||
                            cd->rep_kind == rep_string_kind::compare ||
                            cd->rep_kind == rep_string_kind::load;
    const bool has_destination = cd->rep_kind == rep_string_kind::move ||
                                 cd->rep_kind == rep_string_kind::store ||
                                 cd->rep_kind == rep_string_kind::compare ||
                                 cd->rep_kind == rep_string_kind::scan;
    if (cd->rep_address_size == 4) {
        bool source_overflow{};
        bool destination_overflow{};
        const bool source_remote = has_source && rep_range32_intersects(
            cd, static_cast<uint32_t>(cpu_context->rsi), count,
            cd->rep_element_width, backward, segment_base, source_overflow);
        const bool destination_remote = has_destination &&
            rep_range32_intersects(
                cd, static_cast<uint32_t>(cpu_context->rdi), count,
                cd->rep_element_width, backward, 0, destination_overflow);
        if (source_overflow || destination_overflow)
            strict_access_failure(cd, source_pointer, -EOVERFLOW);
        if (source_remote || destination_remote)
            strict_access_failure(
                cd, source_remote ? source_pointer : destination_pointer,
                -ENOTSUP);
        reset_current_rep_string();
        return;
    }
    if (cd->rep_address_size != 8)
        strict_access_failure(cd, source_pointer, -ENOTSUP);
    if (segment_base != 0 &&
            __builtin_add_overflow(source_pointer,
                                   segment_base,
                                   &source_pointer))
        strict_access_failure(cd, source_pointer, -EOVERFLOW);
    uint64_t source_low{};
    uint64_t destination_low{};
    uint64_t source_bytes{};
    uint64_t destination_bytes{};

    if (has_source &&
        !rep_range_low(source_pointer, count, cd->rep_element_width,
                       backward, source_low, source_bytes))
        strict_access_failure(cd, source_pointer, -EOVERFLOW);
    if (has_destination &&
        !rep_range_low(destination_pointer, count, cd->rep_element_width,
                       backward, destination_low, destination_bytes))
        strict_access_failure(cd, destination_pointer, -EOVERFLOW);

    const bool source_remote = has_source &&
        rep_range_intersects(cd, source_low, source_bytes);
    const bool destination_remote = has_destination &&
        rep_range_intersects(cd, destination_low, destination_bytes);
    if (!source_remote && !destination_remote) {
        reset_current_rep_string();
        return;
    }
    if (bind_current_thread(cd->context) == nullptr)
        strict_access_failure(cd, source_remote ? source_low : destination_low,
                              -ESRCH);

    reset_current_rep_string();
    current_rep_string.callout = cd;
    current_rep_string.initial_count = count;
    current_rep_string.initial_source = source_pointer;
    current_rep_string.initial_destination = destination_pointer;
    current_rep_string.source_low = source_low;
    current_rep_string.destination_low = destination_low;
    current_rep_string.total_bytes = source_bytes != 0
        ? source_bytes : destination_bytes;
    current_rep_string.backward = backward;
    current_rep_string.active = true;

    std::array<pgas_x86_bulk_range, 2> ranges{};
    size_t range_count{};
    if (has_source)
        ranges[range_count++] = { source_low, source_bytes };
    if (has_destination)
        ranges[range_count++] = { destination_low, destination_bytes };
    current_rep_signal_active.store(true, std::memory_order_release);
    const int lock_result = pgas_x86_bulk_lock_ranges(
        cd->runtime, ranges.data(), range_count, current_rep_string.lock);
    if (lock_result != 0)
        strict_access_failure(cd,
                              source_remote ? source_low : destination_low,
                              lock_result,
                              pgas_x86_transaction_phase::prepare);

    if (cd->rep_kind == rep_string_kind::move ||
        cd->rep_kind == rep_string_kind::compare ||
        cd->rep_kind == rep_string_kind::load)
        rep_sync_or_fail(cd, source_low, source_bytes, true);
    if (cd->rep_kind == rep_string_kind::compare ||
        cd->rep_kind == rep_string_kind::scan)
        rep_sync_or_fail(cd, destination_low, destination_bytes, true);
    __atomic_fetch_add(&cd->stats->callouts_fired, 1, __ATOMIC_RELAXED);
}

static void rep_post_callout(GumCpuContext *cpu_context, gpointer user_data)
{
    auto *cd = static_cast<memory_callout_data *>(user_data);
    if (!current_rep_string.active)
        return;
    if (current_rep_string.callout != cd ||
        cpu_context->rcx > current_rep_string.initial_count)
        strict_access_failure(cd, cpu_context->rip, -EINVAL,
                              pgas_x86_transaction_phase::commit);
    const uint64_t consumed =
        current_rep_string.initial_count - cpu_context->rcx;
    uint64_t consumed_bytes{};
    uint64_t destination_low{};
    if (__builtin_mul_overflow(consumed,
                               static_cast<uint64_t>(cd->rep_element_width),
                               &consumed_bytes))
        strict_access_failure(cd, current_rep_string.initial_destination,
                              -EOVERFLOW,
                              pgas_x86_transaction_phase::commit);
    if ((cd->rep_kind == rep_string_kind::move ||
         cd->rep_kind == rep_string_kind::store) &&
        !rep_range_low(current_rep_string.initial_destination, consumed,
                       cd->rep_element_width, current_rep_string.backward,
                       destination_low, consumed_bytes))
        strict_access_failure(cd, current_rep_string.initial_destination,
                              -EOVERFLOW,
                              pgas_x86_transaction_phase::commit);
    if (cd->rep_kind == rep_string_kind::move ||
        cd->rep_kind == rep_string_kind::store)
        rep_sync_or_fail(cd, destination_low, consumed_bytes, false);
    if (consumed != 0)
        pgas_stalker_record_bulk(PGAS_BULK_REP_STRING,
                                 static_cast<size_t>(consumed_bytes));
    current_rep_signal_active.store(false, std::memory_order_release);
    pgas_x86_bulk_unlock_ranges(current_rep_string.lock);
    reset_current_rep_string();
}

static void memory_pre_callout(GumCpuContext *cpu_context, gpointer user_data)
{
    auto *cd = static_cast<memory_callout_data *>(user_data);
    const auto effective_address = compute_ea(cpu_context, &cd->descriptor);
    const auto range = pgas_x86_classify_range(
        effective_address, cd->descriptor.width, cd->pgas_base,
        cd->pgas_size);
    if (range == pgas_x86_range_result::outside)
        return;
    if (range == pgas_x86_range_result::partial)
        strict_access_failure(cd, effective_address, -ERANGE);
    if (range == pgas_x86_range_result::overflow)
        strict_access_failure(cd, effective_address, -EOVERFLOW);
    if (bind_current_thread(cd->context) == nullptr)
        strict_access_failure(cd, effective_address, -ESRCH);
    if (!cd->descriptor.replayable)
        strict_access_failure(cd, effective_address, -ENOTSUP);
    if (current_access.transaction.active)
        strict_access_failure(cd, effective_address, -EBUSY);
    if (cd->descriptor.instruction_id == X86_INS_CMPXCHG16B &&
        (effective_address & 0xf) != 0)
        strict_access_failure(cd, effective_address, -EINVAL);

    const pgas_x86_runtime_config plan_config{
        cd->pgas_base, cd->pgas_size, cd->local_node_id, cd->num_nodes, {},
        nullptr, nullptr
    };
    pgas_x86_replay_plan plan{};
    if (cd->descriptor.gather || cd->descriptor.scatter) {
        const int lane_result = plan_vector_lanes(cpu_context, cd, plan);
        if (lane_result != 0) {
            if (plan.status == 0)
                ++current_thread_record->stats.xstate_failures;
            strict_access_failure(
                cd,
                plan.failure_lane == UINT8_MAX ? effective_address
                                                : plan.failure_address,
                lane_result, pgas_x86_transaction_phase::plan,
                plan.failure_lane, plan.failure_fragment);
        }
    } else {
        plan = pgas_x86_plan_contiguous(
            plan_config, effective_address, cd->descriptor.width);
    }
    if (plan.status != 0)
        strict_access_failure(
            cd,
            plan.failure_lane == UINT8_MAX ? effective_address
                                            : plan.failure_address,
            plan.status, pgas_x86_transaction_phase::plan,
            plan.failure_lane, plan.failure_fragment);
    current_access = {};
    current_access.callout = cd;
    current_access.effective_address = effective_address;
    const int result = pgas_x86_replay_prepare(
        cd->runtime, current_access.transaction, plan,
        cd->descriptor.access_class);
    if (result != 0) {
        const auto &transaction = current_access.transaction;
        strict_access_failure(
            cd,
            transaction.failure_lane == UINT8_MAX
                ? effective_address
                : transaction.failure_address,
            result, pgas_x86_transaction_phase::prepare,
            transaction.failure_lane, transaction.failure_fragment);
    }
    current_access_signal_active.store(true, std::memory_order_release);
    __atomic_fetch_add(&current_thread_record->stats.active_transactions,
                       UINT64_C(1), __ATOMIC_RELAXED);
    current_thread_record->stats.lock_contentions +=
        current_access.transaction.lock_contentions;

    if (cd->descriptor.register_class == pgas_x86_register_class::xmm ||
        cd->descriptor.register_class == pgas_x86_register_class::ymm ||
        cd->descriptor.register_class == pgas_x86_register_class::zmm ||
        cd->descriptor.gather || cd->descriptor.scatter)
        ++current_thread_record->stats.vector;
    if (cd->descriptor.gather)
        ++current_thread_record->stats.gather;
    if (cd->descriptor.scatter)
        ++current_thread_record->stats.scatter;
    if (cd->descriptor.access_class ==
        pgas_x86_access_class::read_modify_write)
        ++current_thread_record->stats.rmw;
    if (cd->descriptor.atomic)
        ++current_thread_record->stats.atomic;
    if (cd->descriptor.access_class == pgas_x86_access_class::prefetch)
        ++current_thread_record->stats.prefetches;
    if (cd->descriptor.gather || cd->descriptor.scatter) {
        current_thread_record->stats.active_lanes += plan.active_lanes;
        current_thread_record->stats.inactive_lanes +=
            plan.lane_count - plan.active_lanes;
    }

    __atomic_fetch_add(&cd->stats->callouts_fired, 1, __ATOMIC_RELAXED);
    size_t remote_bytes{};
    bool remote{};
    for (size_t i = 0; i < plan.fragment_count; ++i) {
        if (plan.fragments[i].remote) {
            remote = true;
            remote_bytes += plan.fragments[i].size;
        }
    }
    if (!remote) {
        __atomic_fetch_add(&cd->stats->local_passthrough, 1,
                           __ATOMIC_RELAXED);
    } else if (cd->descriptor.access_class == pgas_x86_access_class::read ||
               cd->descriptor.access_class ==
                   pgas_x86_access_class::read_modify_write) {
        __atomic_fetch_add(&cd->stats->remote_loads, 1, __ATOMIC_RELAXED);
        ++current_thread_record->stats.remote_loads;
        current_thread_record->stats.bytes_read += remote_bytes;
    }
    const bool issues_read =
        cd->descriptor.access_class == pgas_x86_access_class::read ||
        cd->descriptor.access_class == pgas_x86_access_class::read_modify_write ||
        cd->descriptor.access_class == pgas_x86_access_class::prefetch;
    if (issues_read) {
        for (size_t i = 0; i < plan.fragment_count; ++i) {
            const auto &fragment = plan.fragments[i];
            if (!fragment.remote || fragment.node >= 64)
                continue;
            ++current_thread_record->stats
                  .remote_requests_by_node[fragment.node];
            current_thread_record->stats.remote_bytes_by_node[fragment.node] +=
                fragment.size;
        }
    }
    if (plan.lock_count > 1)
        ++current_thread_record->stats.cross_line_splits;
}

static void memory_post_callout(GumCpuContext *, gpointer user_data)
{
    if (!current_access.transaction.active)
        return;
    auto *cd = static_cast<memory_callout_data *>(user_data);
    const auto access = current_access.transaction.access;
    const auto plan = current_access.transaction.plan;
    const uint64_t effective_address = current_access.effective_address;
    const int result = pgas_x86_replay_commit(current_access.transaction);
    current_access_signal_active.store(false, std::memory_order_release);
    current_access.callout = nullptr;
    if (result != 0) {
        const auto &transaction = current_access.transaction;
        strict_access_failure(
            cd,
            transaction.failure_lane == UINT8_MAX
                ? effective_address
                : transaction.failure_address,
            result, pgas_x86_transaction_phase::commit,
            transaction.failure_lane, transaction.failure_fragment);
    }
    if (access == pgas_x86_access_class::write ||
        access == pgas_x86_access_class::read_modify_write) {
        size_t remote_bytes{};
        for (size_t i = 0; i < plan.fragment_count; ++i) {
            const auto &fragment = plan.fragments[i];
            if (!fragment.remote)
                continue;
            remote_bytes += fragment.size;
            if (fragment.node < 64) {
                ++current_thread_record->stats
                      .remote_requests_by_node[fragment.node];
                current_thread_record->stats
                    .remote_bytes_by_node[fragment.node] += fragment.size;
            }
        }
        if (remote_bytes != 0) {
            __atomic_fetch_add(&cd->stats->remote_stores, 1,
                               __ATOMIC_RELAXED);
            ++current_thread_record->stats.remote_stores;
            current_thread_record->stats.bytes_written += remote_bytes;
        }
    }
    const uint64_t active = __atomic_load_n(
        &current_thread_record->stats.active_transactions, __ATOMIC_RELAXED);
    if (active == 0) {
        __atomic_fetch_add(&current_thread_record->stats.lock_leaks,
                           UINT64_C(1), __ATOMIC_RELAXED);
    } else {
        __atomic_fetch_sub(&current_thread_record->stats.active_transactions,
                           UINT64_C(1), __ATOMIC_RELAXED);
    }
}

static bool choose_scratch_registers(
    const pgas_x86_memory_descriptor &descriptor,
    std::array<GumX86Reg, 3> &scratch)
{
    constexpr std::array candidates{
        GUM_X86_RAX, GUM_X86_RCX, GUM_X86_RDX, GUM_X86_RSI,
        GUM_X86_RDI, GUM_X86_R8,  GUM_X86_R9,  GUM_X86_R10,
        GUM_X86_R11, GUM_X86_R12, GUM_X86_R13, GUM_X86_R14,
        GUM_X86_R15,
    };
    const GumX86Reg base =
        cs_to_gum_reg(static_cast<x86_reg>(descriptor.base_register));
    const GumX86Reg index =
        cs_to_gum_reg(static_cast<x86_reg>(descriptor.index_register));
    const GumX86Reg data =
        cs_to_gum_reg(static_cast<x86_reg>(descriptor.data_register));
    size_t count{};
    for (const auto candidate : candidates) {
        if (candidate == base || candidate == index || candidate == data)
            continue;
        scratch[count++] = candidate;
        if (count == scratch.size())
            return true;
    }
    return false;
}

static bool choose_xstate_pointer(
    const pgas_x86_memory_descriptor &descriptor, GumX86Reg &pointer)
{
    constexpr std::array candidates{
        GUM_X86_R11, GUM_X86_R10, GUM_X86_R9,  GUM_X86_R8,
        GUM_X86_RBX, GUM_X86_RCX, GUM_X86_RSI, GUM_X86_RDI,
        GUM_X86_R14, GUM_X86_R15, GUM_X86_R12,
    };
    const GumX86Reg base =
        cs_to_gum_reg(static_cast<x86_reg>(descriptor.base_register));
    const GumX86Reg index =
        cs_to_gum_reg(static_cast<x86_reg>(descriptor.index_register));
    const GumX86Reg data =
        cs_to_gum_reg(static_cast<x86_reg>(descriptor.data_register));
    for (const auto candidate : candidates) {
        if (candidate != base && candidate != index && candidate != data) {
            pointer = candidate;
            return true;
        }
    }
    return false;
}

static void emit_enveloped_callout(GumStalkerIterator *iterator,
                                   GumX86Writer *writer,
                                   memory_callout_data *cd,
                                   GumStalkerCallout callout)
{
    pgas_x86_state_frame frame{};
    if (!pgas_x86_emit_state_save(writer, cd->context->xstate,
                                  cd->xstate_pointer, frame))
        strict_access_failure(cd, cd->descriptor.instruction_address,
                              -ENOTSUP);
    cd->saved_flags_offset = frame.saved_flags_offset;
    gum_stalker_iterator_put_callout(iterator, callout, cd, nullptr);
    if (!pgas_x86_emit_state_restore(writer, cd->context->xstate, frame))
        strict_access_failure(cd, cd->descriptor.instruction_address,
                              -ENOTSUP);
}

static void emit_rep_string_access(GumStalkerIterator *iterator,
                                   GumStalkerOutput *output,
                                   memory_callout_data *cd)
{
    auto *writer = output->writer.x86;
    if (!choose_xstate_pointer(cd->descriptor, cd->xstate_pointer))
        strict_access_failure(cd, cd->descriptor.instruction_address,
                              -ENOTSUP);
    emit_enveloped_callout(iterator, writer, cd, rep_pre_callout);
    gum_stalker_iterator_keep(iterator);
    emit_enveloped_callout(iterator, writer, cd, rep_post_callout);
}

static void emit_memory_access(GumStalkerIterator *iterator,
                               GumStalkerOutput *output,
                               memory_callout_data *cd)
{
    auto *writer = output->writer.x86;
    const auto &descriptor = cd->descriptor;
    if (!choose_xstate_pointer(descriptor, cd->xstate_pointer))
        strict_access_failure(cd, descriptor.instruction_address, -ENOTSUP);
    const bool simple_address =
        descriptor.base_register != X86_REG_INVALID &&
        descriptor.base_register != X86_REG_RIP &&
        descriptor.index_register == X86_REG_INVALID;
    std::array<GumX86Reg, 3> scratch{};
    const bool can_inline = simple_address &&
                            choose_scratch_registers(descriptor, scratch);

    if (!can_inline) {
        emit_enveloped_callout(iterator, writer, cd, memory_pre_callout);
        gum_stalker_iterator_keep(iterator);
        emit_enveloped_callout(iterator, writer, cd, memory_post_callout);
        return;
    }

    const auto inside = static_cast<gconstpointer>(&cd->labels[0]);
    const auto outside = static_cast<gconstpointer>(&cd->labels[1]);
    const auto partial = static_cast<gconstpointer>(&cd->labels[2]);
    const auto overflow = static_cast<gconstpointer>(&cd->labels[3]);
    const auto original = static_cast<gconstpointer>(&cd->labels[4]);
    if (!pgas_x86_emit_range_gate(
            writer,
            cs_to_gum_reg(static_cast<x86_reg>(descriptor.base_register)),
            scratch[0], scratch[1], scratch[2], descriptor.displacement,
            descriptor.width, cd->pgas_base, cd->pgas_size, inside, outside,
            partial, overflow)) {
        strict_access_failure(cd, descriptor.instruction_address, -EINVAL);
    }

    gum_x86_writer_put_label(writer, inside);
    emit_enveloped_callout(iterator, writer, cd, memory_pre_callout);
    gum_x86_writer_put_jmp_near_label(writer, original);

    gum_x86_writer_put_label(writer, outside);
    gum_x86_writer_put_jmp_near_label(writer, original);

    gum_x86_writer_put_label(writer, partial);
    emit_enveloped_callout(iterator, writer, cd, memory_pre_callout);
    gum_x86_writer_put_breakpoint(writer);

    gum_x86_writer_put_label(writer, overflow);
    emit_enveloped_callout(iterator, writer, cd, memory_pre_callout);
    gum_x86_writer_put_breakpoint(writer);

    gum_x86_writer_put_label(writer, original);
    gum_stalker_iterator_keep(iterator);
    emit_enveloped_callout(iterator, writer, cd, memory_post_callout);
}

// ---------------------------------------------------------------------------
// Stalker transformer callback
// ---------------------------------------------------------------------------

static void transform_block(GumStalkerIterator *iterator,
                            GumStalkerOutput *output, gpointer user_data) {
    auto *ctx = (pgas_stalker_ctx *)user_data;
    const cs_insn *insn;
    bool first_instruction = true;
    bool instrument_block = false;

    __atomic_fetch_add(&ctx->stats.blocks_transformed, 1, __ATOMIC_RELAXED);

    while (gum_stalker_iterator_next(iterator, &insn)) {
        __atomic_fetch_add(&ctx->stats.insns_scanned, 1, __ATOMIC_RELAXED);

        if (first_instruction) {
            instrument_block = should_instrument_address(ctx, insn->address);
            first_instruction = false;
        }
        if (!instrument_block) {
            gum_stalker_iterator_keep(iterator);
            continue;
        }

        rep_string_kind rep_kind{};
        uint8_t rep_width{};
        if (decode_rep_string(insn, rep_kind, rep_width)) {
            if (!ctx->config.hook_rep_movs) {
                gum_stalker_iterator_keep(iterator);
                continue;
            }
            auto *cd = alloc_callout_data();
            if (cd == nullptr) {
                gum_stalker_iterator_keep(iterator);
                continue;
            }
            *cd = {};
            cd->pgas_base = ctx->config.pgas_base_addr;
            cd->pgas_size = ctx->config.pgas_region_size;
            cd->local_node_id = ctx->config.local_node_id;
            cd->num_nodes = ctx->config.num_nodes;
            cd->stats = &ctx->stats;
            cd->runtime = ctx->runtime;
            cd->context = ctx;
            cd->rep_kind = rep_kind;
            cd->rep_element_width = rep_width;
            cd->rep_address_size = insn->detail->x86.addr_size;
            cd->rep_segment_prefix = insn->detail->x86.prefix[1];
            auto &descriptor = cd->descriptor;
            descriptor.instruction_address = insn->address;
            descriptor.instruction_id = insn->id;
            descriptor.width = rep_width;
            descriptor.replayable = true;
            descriptor.access_class =
                rep_kind == rep_string_kind::store
                    ? pgas_x86_access_class::write
                    : (rep_kind == rep_string_kind::move
                           ? pgas_x86_access_class::read_modify_write
                           : pgas_x86_access_class::read);
            std::snprintf(descriptor.mnemonic, sizeof(descriptor.mnemonic),
                          "%s", insn->mnemonic);
            descriptor.instruction_size = static_cast<uint8_t>(
                std::min<size_t>(insn->size,
                                 descriptor.instruction_bytes.size()));
            std::memcpy(descriptor.instruction_bytes.data(), insn->bytes,
                        descriptor.instruction_size);
            Dl_info module_info{};
            if (dladdr(reinterpret_cast<const void *>(insn->address),
                       &module_info) != 0) {
                const auto module = basename_from_path(module_info.dli_fname);
                std::snprintf(descriptor.module_basename,
                              sizeof(descriptor.module_basename), "%s",
                              module.c_str());
            }
            emit_rep_string_access(iterator, output, cd);
            if (descriptor.access_class == pgas_x86_access_class::read)
                __atomic_fetch_add(&ctx->stats.translated_reads, 1,
                                   __ATOMIC_RELAXED);
            else if (descriptor.access_class == pgas_x86_access_class::write)
                __atomic_fetch_add(&ctx->stats.translated_writes, 1,
                                   __ATOMIC_RELAXED);
            else
                __atomic_fetch_add(
                    &ctx->stats.translated_read_modify_writes, 1,
                    __ATOMIC_RELAXED);
            continue;
        }

        pgas_x86_memory_descriptor descriptor;
        if (!analyze_memory_instruction(insn, &ctx->config, &descriptor)) {
            gum_stalker_iterator_keep(iterator);
            continue;
        }

        // OPT 1: Skip stack-relative accesses (RSP/RBP-based).
        // These are local variables, function args, spills — never CXL.
        if (is_stack_relative(
                static_cast<x86_reg>(descriptor.base_register))) {
            gum_stalker_iterator_keep(iterator);
            continue;
        }

        // Static displacement-only: check at JIT time
        const bool needs_runtime =
            descriptor.base_register != X86_REG_INVALID ||
            descriptor.index_register != X86_REG_INVALID;
        if (!needs_runtime) {
            const auto range = pgas_x86_classify_range(
                static_cast<uint64_t>(descriptor.displacement),
                descriptor.width, ctx->config.pgas_base_addr,
                ctx->config.pgas_region_size);
            if (range == pgas_x86_range_result::outside) {
                gum_stalker_iterator_keep(iterator);
                continue;
            }
        }

        // RIP-relative addressing: typically code/data segment, not CXL
        if (descriptor.base_register == X86_REG_RIP) {
            gum_stalker_iterator_keep(iterator);
            continue;
        }

        // Allocate callout metadata
        auto *cd = alloc_callout_data();
        if (!cd) {
            gum_stalker_iterator_keep(iterator);
            continue;
        }

        // OPT 5: Flatten — copy config into callout data directly
        cd->pgas_base = ctx->config.pgas_base_addr;
        cd->pgas_size = ctx->config.pgas_region_size;
        cd->local_node_id = ctx->config.local_node_id;
        cd->num_nodes = ctx->config.num_nodes;
        cd->stats = &ctx->stats;
        cd->runtime = ctx->runtime;
        cd->context = ctx;
        cd->descriptor = descriptor;

        emit_memory_access(iterator, output, cd);
        switch (descriptor.access_class) {
        case pgas_x86_access_class::read:
            __atomic_fetch_add(&ctx->stats.translated_reads, 1,
                               __ATOMIC_RELAXED);
            break;
        case pgas_x86_access_class::write:
            __atomic_fetch_add(&ctx->stats.translated_writes, 1,
                               __ATOMIC_RELAXED);
            break;
        case pgas_x86_access_class::read_modify_write:
            __atomic_fetch_add(&ctx->stats.translated_read_modify_writes, 1,
                               __ATOMIC_RELAXED);
            break;
        case pgas_x86_access_class::prefetch:
            __atomic_fetch_add(&ctx->stats.translated_prefetches, 1,
                               __ATOMIC_RELAXED);
            break;
        case pgas_x86_access_class::unsupported:
            __atomic_fetch_add(&ctx->stats.translated_unsupported, 1,
                               __ATOMIC_RELAXED);
            break;
        }
        if (descriptor.access_class == pgas_x86_access_class::read) {
            __atomic_fetch_add(&ctx->stats.mov_loads_hooked, 1, __ATOMIC_RELAXED);
        } else if (descriptor.access_class == pgas_x86_access_class::write) {
            __atomic_fetch_add(&ctx->stats.mov_stores_hooked, 1, __ATOMIC_RELAXED);
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

extern "C" {

void pgas_stalker_record_bulk(pgas_bulk_operation_t operation, size_t size)
{
    const auto index = static_cast<unsigned>(operation);
    if (current_thread_record == nullptr || index >= 4)
        return;
    ++current_thread_record->stats.bulk_calls[index];
    current_thread_record->stats.bulk_bytes[index] += size;
}

void pgas_stalker_fatal_bulk(const char *operation, uint64_t address,
                             size_t size, uint16_t node, int error)
{
    if (current_thread_record != nullptr)
        ++current_thread_record->stats.failures;
    pgas_x86_failure failure{};
    failure.thread_id = static_cast<uint64_t>(syscall(SYS_gettid));
    std::snprintf(failure.mnemonic, sizeof(failure.mnemonic), "%s",
                  operation == nullptr ? "bulk" : operation);
    std::snprintf(failure.module_basename,
                  sizeof(failure.module_basename), "libc");
    failure.access_class = pgas_x86_access_class::read_modify_write;
    failure.phase = pgas_x86_transaction_phase::commit;
    failure.effective_address = address;
    failure.width = size;
    failure.lane_index = UINT8_MAX;
    failure.target_node = node;
    failure.transport_error = error;
    emit_fatal_failure(failure, "none");
}

pgas_stalker_ctx_t *pgas_stalker_init(const pgas_stalker_config_t *config) {
    if (config == nullptr || config->num_nodes > 64)
        return nullptr;
    auto *ctx = new pgas_stalker_ctx();
    memset(&ctx->stats, 0, sizeof(ctx->stats));
    ctx->config = *config;
    ctx->runtime = nullptr;
    ctx->next_runtime_id = 1;
    ctx->followed_threads = 0;
    ctx->active = false;

    if (pgas_x86_detect_xstate(ctx->xstate) != 0 ||
        !ctx->xstate.osxsave || !ctx->xstate.avx || !ctx->xstate.avx512) {
        SPDLOG_ERROR("Required x86 XSAVE/AVX/AVX-512 state is unavailable");
        delete ctx;
        return nullptr;
    }

    try {
        ctx->module_policy = std::make_unique<pgas_stalker_module_policy>(
            config->include_modules == nullptr ? "" : config->include_modules);
    } catch (const std::invalid_argument &error) {
        SPDLOG_ERROR("Invalid PGAS Stalker module allowlist: {}", error.what());
        delete ctx;
        return nullptr;
    }
    ctx->main_basename = current_executable_basename();

    if (!config->hook_mov && !config->hook_movzx &&
        !config->hook_movnti && !config->hook_rep_movs) {
        ctx->config.hook_mov = true;
        ctx->config.hook_movzx = true;
        ctx->config.hook_movnti = true;
    }

    ctx->runtime = pgas_cxlmemsim_acquire_x86_runtime();
    if (ctx->runtime == nullptr) {
        const pgas_x86_runtime_config runtime_config{
            config->pgas_base_addr,
            config->pgas_region_size,
            config->local_node_id,
            config->num_nodes,
            pgas_cxlmemsim_x86_transport(),
            runtime_failure,
            nullptr,
        };
        ctx->runtime = pgas_x86_runtime_create(runtime_config);
        ctx->owns_runtime = ctx->runtime != nullptr;
    }
    if (ctx->runtime == nullptr) {
        SPDLOG_ERROR("Invalid x86 PGAS runtime configuration");
        delete ctx;
        return nullptr;
    }

    ctx->stalker = gum_stalker_new();
    if (!ctx->stalker) {
        SPDLOG_ERROR("gum_stalker_new() failed");
        if (ctx->owns_runtime)
            pgas_x86_runtime_destroy(ctx->runtime);
        else
            pgas_cxlmemsim_release_x86_runtime_user(ctx->runtime);
        delete ctx;
        return nullptr;
    }

    // OPT 3: Default trust = -1 (cache JIT'd blocks forever)
    int trust = config->trust_threshold;
    if (trust == 0) trust = -1;  // upgrade default
    gum_stalker_set_trust_threshold(ctx->stalker, trust);

    ctx->transformer = gum_stalker_transformer_make_from_callback(
        transform_block, ctx, NULL);

    SPDLOG_INFO("PGAS Stalker initialized: base=0x{:x} size={} nodes={} trust={}",
                config->pgas_base_addr, config->pgas_region_size,
                config->num_nodes, trust);

    return ctx;
}

int pgas_stalker_follow_me(pgas_stalker_ctx_t *ctx) {
    if (!ctx || !ctx->stalker) return -1;
    std::lock_guard lifecycle_lock(ctx->lifecycle_mutex);
    register_current_thread(ctx);
    gum_stalker_follow_me(ctx->stalker, ctx->transformer, NULL);
    if (!install_replay_signal_handlers(ctx)) {
        gum_stalker_unfollow_me(ctx->stalker);
        unregister_current_thread(ctx);
        return -1;
    }
    ++ctx->followed_threads;
    ctx->active = true;
    SPDLOG_INFO("Stalker following current thread");
    return 0;
}

int pgas_stalker_follow(pgas_stalker_ctx_t *ctx, GumThreadId thread_id) {
    if (!ctx || !ctx->stalker) return -1;
    std::lock_guard lifecycle_lock(ctx->lifecycle_mutex);
    create_thread_record(ctx, static_cast<uint64_t>(thread_id));
    gum_stalker_follow(ctx->stalker, thread_id, ctx->transformer, NULL);
    if (!install_replay_signal_handlers(ctx)) {
        gum_stalker_unfollow(ctx->stalker, thread_id);
        unregister_thread_id(ctx, static_cast<uint64_t>(thread_id));
        return -1;
    }
    ++ctx->followed_threads;
    ctx->active = true;
    SPDLOG_INFO("Stalker following thread {}", thread_id);
    return 0;
}

void pgas_stalker_unfollow_me(pgas_stalker_ctx_t *ctx) {
    if (!ctx || !ctx->stalker) return;
    std::lock_guard lifecycle_lock(ctx->lifecycle_mutex);
    gum_stalker_unfollow_me(ctx->stalker);
    unregister_current_thread(ctx);
    if (ctx->followed_threads != 0)
        --ctx->followed_threads;
    if (ctx->followed_threads == 0) {
        restore_replay_signal_handlers(ctx);
        ctx->active = false;
    }
    SPDLOG_INFO("Stalker unfollowed current thread");
}

void pgas_stalker_unfollow(pgas_stalker_ctx_t *ctx, GumThreadId thread_id) {
    if (!ctx || !ctx->stalker) return;
    std::lock_guard lifecycle_lock(ctx->lifecycle_mutex);
    gum_stalker_unfollow(ctx->stalker, thread_id);
    unregister_thread_id(ctx, static_cast<uint64_t>(thread_id));
    if (ctx->followed_threads != 0)
        --ctx->followed_threads;
    if (ctx->followed_threads == 0) {
        restore_replay_signal_handlers(ctx);
        ctx->active = false;
    }
}

void pgas_stalker_activate(pgas_stalker_ctx_t *ctx, const void *target) {
    if (!ctx || !ctx->stalker) return;
    gum_stalker_activate(ctx->stalker, target);
}

void pgas_stalker_deactivate(pgas_stalker_ctx_t *ctx) {
    if (!ctx || !ctx->stalker) return;
    gum_stalker_deactivate(ctx->stalker);
}

void pgas_stalker_exclude(pgas_stalker_ctx_t *ctx, uint64_t base, uint64_t size) {
    if (!ctx || !ctx->stalker) return;
    GumMemoryRange range;
    range.base_address = (GumAddress)base;
    range.size = (gsize)size;
    gum_stalker_exclude(ctx->stalker, &range);
}

void pgas_stalker_get_stats(pgas_stalker_ctx_t *ctx, pgas_stalker_stats_t *stats) {
    if (!ctx || !stats) return;
    *stats = ctx->stats;
}

size_t pgas_stalker_snapshot_threads(pgas_stalker_ctx_t *ctx,
                                     pgas_stalker_thread_stats_t *output,
                                     size_t capacity)
{
    if (ctx == nullptr)
        return 0;
    std::lock_guard lock(ctx->thread_mutex);
    const size_t count = ctx->threads.size();
    if (output != nullptr) {
        const size_t copy_count = std::min(count, capacity);
        for (size_t i = 0; i < copy_count; ++i)
            output[i] = ctx->threads[i]->stats;
    }
    return count;
}

int pgas_stalker_should_follow_creator(pgas_stalker_ctx_t *ctx,
                                       const char *module_path)
{
    if (ctx == nullptr || ctx->module_policy == nullptr)
        return 0;
    const std::string basename = basename_from_path(module_path);
    return ctx->module_policy->should_instrument(
               basename, is_main_module(ctx, basename))
               ? 1
               : 0;
}

int pgas_stalker_may_instrument_module(pgas_stalker_ctx_t *ctx,
                                       const char *module_path)
{
    if (ctx == nullptr || ctx->module_policy == nullptr)
        return 0;
    const std::string basename = basename_from_path(module_path);
    return ctx->module_policy->may_instrument(
               basename, is_main_module(ctx, basename))
               ? 1
               : 0;
}

int pgas_stalker_sigaction(pgas_stalker_ctx_t *ctx, int signal_number,
                           const struct sigaction *action,
                           struct sigaction *old_action)
{
    const size_t index = replay_signal_index(signal_number);
    if (ctx == nullptr || index == replay_fault_signals.size())
        return call_real_sigaction(signal_number, action, old_action);

    if (!ctx->signal_handlers_installed.load(std::memory_order_acquire) &&
        action == nullptr)
        return call_real_sigaction(signal_number, action, old_action);

    auto &state = ctx->application_signals[index];
    struct sigaction requested_action{};
    if (action != nullptr)
        requested_action = *action;
    auto snapshot = load_application_action(state);
    if (old_action != nullptr) {
        if ((snapshot.action.sa_flags & SA_RESETHAND) != 0 &&
            state.reset_claimed.load(std::memory_order_acquire) ==
                snapshot.publication) {
            *old_action = {};
            old_action->sa_handler = SIG_DFL;
            sigemptyset(&old_action->sa_mask);
        } else {
            *old_action = snapshot.action;
        }
    }
    if (action == nullptr)
        return 0;

    sigset_t old_mask;
    block_all_signals(old_mask);
    lock_signal_action_writer(ctx);
    if (!ctx->signal_handlers_installed.load(std::memory_order_acquire)) {
        const int result = call_real_sigaction(signal_number, action,
                                               old_action);
        unlock_signal_action_writer(ctx);
        restore_signal_mask(old_mask);
        return result;
    }

    snapshot = load_application_action(state);
    if (old_action != nullptr) {
        if ((snapshot.action.sa_flags & SA_RESETHAND) != 0 &&
            state.reset_claimed.load(std::memory_order_acquire) ==
                snapshot.publication) {
            *old_action = {};
            old_action->sa_handler = SIG_DFL;
            sigemptyset(&old_action->sa_mask);
        } else {
            *old_action = snapshot.action;
        }
    }
    const struct sigaction wrapper = replay_wrapper_action(requested_action);
    if (call_real_sigaction(signal_number, &wrapper, nullptr) != 0) {
        unlock_signal_action_writer(ctx);
        restore_signal_mask(old_mask);
        return -1;
    }
    publish_application_action(state, requested_action,
                               snapshot.publication);
    unlock_signal_action_writer(ctx);
    restore_signal_mask(old_mask);
    return 0;
}

int pgas_stalker_strict_valid(pgas_stalker_ctx_t *ctx)
{
    if (ctx == nullptr)
        return 0;
    if (!ctx->config.strict_validation)
        return 1;
    if (!ctx->module_policy->requested_but_unseen().empty())
        return 0;

    std::lock_guard lock(ctx->thread_mutex);
    for (const auto &record : ctx->threads) {
        const auto &stats = record->stats;
        if (stats.unsupported != 0 || stats.failures != 0 ||
            stats.active_transactions != 0 || stats.lock_leaks != 0 ||
            stats.follow_events != stats.unfollow_events)
            return 0;
    }
    return 1;
}

void pgas_stalker_print_stats(pgas_stalker_ctx_t *ctx) {
    if (!ctx) return;
    auto &s = ctx->stats;
    uint64_t total_hooked = s.mov_loads_hooked + s.mov_stores_hooked;
    uint64_t total_runtime = s.remote_loads + s.remote_stores + s.local_passthrough;

    fprintf(stderr, "\n=== PGAS Stalker MOV Statistics ===\n");
    fprintf(stderr, "JIT phase:\n");
    fprintf(stderr, "  Blocks transformed:   %lu\n", s.blocks_transformed);
    fprintf(stderr, "  Instructions scanned: %lu\n", s.insns_scanned);
    fprintf(stderr, "  MOV loads hooked:     %lu\n", s.mov_loads_hooked);
    fprintf(stderr, "  MOV stores hooked:    %lu\n", s.mov_stores_hooked);
    fprintf(stderr, "  Instrumentation rate: %.1f%%\n",
           s.insns_scanned ? 100.0 * total_hooked / s.insns_scanned : 0);
    fprintf(stderr, "Runtime:\n");
    fprintf(stderr, "  Callouts fired:       %lu\n", total_runtime);
    fprintf(stderr, "  Remote loads:         %lu\n", s.remote_loads);
    fprintf(stderr, "  Remote stores:        %lu\n", s.remote_stores);
    fprintf(stderr, "  Local passthrough:    %lu\n", s.local_passthrough);
    fprintf(stderr, "  Callout pool used:    %lu / %d\n",
           g_callout_pool_next, CALLOUT_POOL_CAPACITY);
    const auto unseen = ctx->module_policy->requested_but_unseen();
    for (const auto &module : unseen)
        fprintf(stderr, "requested_include_unseen=%s\n", module.c_str());
    fprintf(stderr, "strict_valid=%d\n", pgas_stalker_strict_valid(ctx));
    fprintf(stderr, "==================================\n\n");
}

namespace {

void append_json_string(std::string &output, std::string_view value)
{
    output.push_back('"');
    constexpr char hex[] = "0123456789abcdef";
    for (const unsigned char character : value) {
        switch (character) {
        case '"': output += "\\\""; break;
        case '\\': output += "\\\\"; break;
        case '\b': output += "\\b"; break;
        case '\f': output += "\\f"; break;
        case '\n': output += "\\n"; break;
        case '\r': output += "\\r"; break;
        case '\t': output += "\\t"; break;
        default:
            if (character < 0x20) {
                output += "\\u00";
                output.push_back(hex[character >> 4]);
                output.push_back(hex[character & 0xf]);
            } else {
                output.push_back(static_cast<char>(character));
            }
        }
    }
    output.push_back('"');
}

void append_json_string_array(std::string &output,
                              const std::vector<std::string> &values)
{
    output.push_back('[');
    for (size_t i = 0; i < values.size(); ++i) {
        if (i != 0)
            output.push_back(',');
        append_json_string(output, values[i]);
    }
    output.push_back(']');
}

void append_remote_by_node(std::string &output,
                           const pgas_stalker_thread_stats_t &stats)
{
    output.push_back('{');
    bool first = true;
    for (size_t node = 0; node < 64; ++node) {
        if (stats.remote_requests_by_node[node] == 0 &&
            stats.remote_bytes_by_node[node] == 0)
            continue;
        if (!first)
            output.push_back(',');
        first = false;
        output += "\"" + std::to_string(node) + "\":{\"requests\":" +
                  std::to_string(stats.remote_requests_by_node[node]) +
                  ",\"bytes\":" +
                  std::to_string(stats.remote_bytes_by_node[node]) + "}";
    }
    output.push_back('}');
}

void append_bulk_values(std::string &output, const uint64_t values[4])
{
    output += "{\"memcpy\":" + std::to_string(values[PGAS_BULK_MEMCPY]) +
              ",\"memmove\":" +
              std::to_string(values[PGAS_BULK_MEMMOVE]) +
              ",\"memset\":" +
              std::to_string(values[PGAS_BULK_MEMSET]) +
              ",\"rep_string\":" +
              std::to_string(values[PGAS_BULK_REP_STRING]) + "}";
}

void write_stdout(const std::string &output)
{
    size_t offset{};
    while (offset < output.size()) {
        const ssize_t written = write(STDOUT_FILENO, output.data() + offset,
                                      output.size() - offset);
        if (written <= 0)
            return;
        offset += static_cast<size_t>(written);
    }
}

} // namespace

void pgas_stalker_print_json(
    pgas_stalker_ctx_t *ctx,
    const pgas_stalker_lifecycle_stats_t *lifecycle)
{
    if (ctx == nullptr)
        return;
    std::vector<pgas_stalker_thread_stats_t> threads(
        pgas_stalker_snapshot_threads(ctx, nullptr, 0));
    pgas_stalker_snapshot_threads(ctx, threads.data(), threads.size());
    std::ranges::sort(threads, {},
                      &pgas_stalker_thread_stats_t::runtime_id);

    pgas_stalker_thread_stats_t totals{};
    std::string output;
    for (const auto &thread : threads) {
        output += "{\"kind\":\"pgas_stalker_thread\",\"runtime_id\":" +
                  std::to_string(thread.runtime_id) +
                  ",\"os_tid\":" + std::to_string(thread.os_tid) +
                  ",\"remote_loads\":" + std::to_string(thread.remote_loads) +
                  ",\"remote_stores\":" + std::to_string(thread.remote_stores) +
                  ",\"bytes_read\":" + std::to_string(thread.bytes_read) +
                  ",\"bytes_written\":" + std::to_string(thread.bytes_written) +
                  ",\"cross_line_splits\":" +
                  std::to_string(thread.cross_line_splits) +
                  ",\"vector\":" + std::to_string(thread.vector) +
                  ",\"gather\":" + std::to_string(thread.gather) +
                  ",\"scatter\":" + std::to_string(thread.scatter) +
                  ",\"rmw\":" + std::to_string(thread.rmw) +
                  ",\"atomic\":" + std::to_string(thread.atomic) +
                  ",\"prefetches\":" +
                  std::to_string(thread.prefetches) +
                  ",\"prefetch_dropped\":" +
                  std::to_string(thread.prefetch_dropped) +
                  ",\"active_lanes\":" +
                  std::to_string(thread.active_lanes) +
                  ",\"inactive_lanes\":" +
                  std::to_string(thread.inactive_lanes) +
                  ",\"transaction_aborts\":" +
                  std::to_string(thread.transaction_aborts) +
                  ",\"signal_cleanups\":" +
                  std::to_string(thread.signal_cleanups) +
                  ",\"active_transactions\":" +
                  std::to_string(thread.active_transactions) +
                  ",\"lock_contentions\":" +
                  std::to_string(thread.lock_contentions) +
                  ",\"lock_leaks\":" + std::to_string(thread.lock_leaks) +
                  ",\"xstate_failures\":" +
                  std::to_string(thread.xstate_failures) +
                  ",\"bulk_calls\":";
        append_bulk_values(output, thread.bulk_calls);
        output += ",\"bulk_bytes\":";
        append_bulk_values(output, thread.bulk_bytes);
        output +=
                  ",\"remote_by_node\":";
        append_remote_by_node(output, thread);
        output +=
                  ",\"unsupported\":" + std::to_string(thread.unsupported) +
                  ",\"failures\":" + std::to_string(thread.failures) +
                  ",\"follow_events\":" + std::to_string(thread.follow_events) +
                  ",\"unfollow_events\":" +
                  std::to_string(thread.unfollow_events) + "}\n";
        totals.remote_loads += thread.remote_loads;
        totals.remote_stores += thread.remote_stores;
        totals.bytes_read += thread.bytes_read;
        totals.bytes_written += thread.bytes_written;
        totals.cross_line_splits += thread.cross_line_splits;
        totals.vector += thread.vector;
        totals.gather += thread.gather;
        totals.scatter += thread.scatter;
        totals.rmw += thread.rmw;
        totals.atomic += thread.atomic;
        totals.prefetches += thread.prefetches;
        totals.prefetch_dropped += thread.prefetch_dropped;
        totals.active_lanes += thread.active_lanes;
        totals.inactive_lanes += thread.inactive_lanes;
        totals.transaction_aborts += thread.transaction_aborts;
        totals.signal_cleanups += thread.signal_cleanups;
        totals.active_transactions += thread.active_transactions;
        totals.lock_contentions += thread.lock_contentions;
        totals.lock_leaks += thread.lock_leaks;
        totals.xstate_failures += thread.xstate_failures;
        for (size_t operation = 0; operation < 4; ++operation) {
            totals.bulk_calls[operation] += thread.bulk_calls[operation];
            totals.bulk_bytes[operation] += thread.bulk_bytes[operation];
        }
        for (size_t node = 0; node < 64; ++node) {
            totals.remote_requests_by_node[node] +=
                thread.remote_requests_by_node[node];
            totals.remote_bytes_by_node[node] +=
                thread.remote_bytes_by_node[node];
        }
        totals.unsupported += thread.unsupported;
        totals.failures += thread.failures;
        totals.follow_events += thread.follow_events;
        totals.unfollow_events += thread.unfollow_events;
    }

    const pgas_stalker_lifecycle_stats_t empty_lifecycle{};
    const auto &life = lifecycle == nullptr ? empty_lifecycle : *lifecycle;
    const bool strict_valid =
        pgas_stalker_strict_valid(ctx) != 0 &&
        life.pre_ready_application_threads == 0 &&
        life.unfollowed_application_threads == 0;
    output += "{\"kind\":\"pgas_stalker_summary\",\"threads\":" +
              std::to_string(threads.size()) +
              ",\"remote_loads\":" + std::to_string(totals.remote_loads) +
              ",\"remote_stores\":" + std::to_string(totals.remote_stores) +
              ",\"bytes_read\":" + std::to_string(totals.bytes_read) +
              ",\"bytes_written\":" + std::to_string(totals.bytes_written) +
              ",\"cross_line_splits\":" +
              std::to_string(totals.cross_line_splits) +
              ",\"vector\":" + std::to_string(totals.vector) +
              ",\"gather\":" + std::to_string(totals.gather) +
              ",\"scatter\":" + std::to_string(totals.scatter) +
              ",\"rmw\":" + std::to_string(totals.rmw) +
              ",\"atomic\":" + std::to_string(totals.atomic) +
              ",\"prefetches\":" + std::to_string(totals.prefetches) +
              ",\"prefetch_dropped\":" +
              std::to_string(totals.prefetch_dropped) +
              ",\"active_lanes\":" +
              std::to_string(totals.active_lanes) +
              ",\"inactive_lanes\":" +
              std::to_string(totals.inactive_lanes) +
              ",\"transaction_aborts\":" +
              std::to_string(totals.transaction_aborts) +
              ",\"signal_cleanups\":" +
              std::to_string(totals.signal_cleanups) +
              ",\"active_transactions\":" +
              std::to_string(totals.active_transactions) +
              ",\"lock_contentions\":" +
              std::to_string(totals.lock_contentions) +
              ",\"lock_leaks\":" + std::to_string(totals.lock_leaks) +
              ",\"xstate_failures\":" +
              std::to_string(totals.xstate_failures) +
              ",\"bulk_calls\":";
    append_bulk_values(output, totals.bulk_calls);
    output += ",\"bulk_bytes\":";
    append_bulk_values(output, totals.bulk_bytes);
    output +=
              ",\"remote_by_node\":";
    append_remote_by_node(output, totals);
    output +=
              ",\"unsupported\":" + std::to_string(totals.unsupported) +
              ",\"failures\":" + std::to_string(totals.failures) +
              ",\"follow_events\":" + std::to_string(totals.follow_events) +
              ",\"unfollow_events\":" + std::to_string(totals.unfollow_events) +
              ",\"requested_modules\":";
    append_json_string_array(output, ctx->module_policy->requested());
    output += ",\"observed_modules\":";
    append_json_string_array(output, ctx->module_policy->observed());
    output += ",\"pre_ready_application_threads\":" +
              std::to_string(life.pre_ready_application_threads) +
              ",\"internal_creator_threads\":" +
              std::to_string(life.internal_creator_threads) +
              ",\"unfollowed_application_threads\":" +
              std::to_string(life.unfollowed_application_threads) +
              ",\"translated_access_classes\":{\"read\":" +
              std::to_string(ctx->stats.translated_reads) +
              ",\"write\":" + std::to_string(ctx->stats.translated_writes) +
              ",\"read_modify_write\":" +
              std::to_string(ctx->stats.translated_read_modify_writes) +
              ",\"prefetch\":" +
              std::to_string(ctx->stats.translated_prefetches) +
              ",\"unsupported\":" +
              std::to_string(ctx->stats.translated_unsupported) +
              "},\"strict_valid\":" + (strict_valid ? "true" : "false") +
              "}\n";
    write_stdout(output);
}

void pgas_stalker_finalize(pgas_stalker_ctx_t *ctx) {
    if (!ctx) return;
    restore_replay_signal_handlers(ctx);
    if (ctx->stalker) {
        gum_stalker_flush(ctx->stalker);
        gum_stalker_garbage_collect(ctx->stalker);
        g_object_unref(ctx->stalker);
    }
    if (ctx->transformer)
        g_object_unref(ctx->transformer);

    if (ctx->owns_runtime)
        pgas_x86_runtime_destroy(ctx->runtime);
    else
        pgas_cxlmemsim_release_x86_runtime_user(ctx->runtime);

    // Reset bump allocator (no individual frees needed)
    g_callout_pool_next = 0;

    delete ctx;
    SPDLOG_INFO("PGAS Stalker finalized");
}

} // extern "C"

#elif defined(__aarch64__)

// ---------------------------------------------------------------------------
// AArch64 Stalker implementation
// ---------------------------------------------------------------------------

struct pgas_stalker_ctx {
    GumStalker *stalker;
    GumStalkerTransformer *transformer;

    pgas_stalker_config_t config;
    pgas_stalker_stats_t stats;

    bool active;
};

struct arm64_mem_info {
    bool has_mem_op;
    bool is_load;
    bool is_store;
    uint8_t mem_op_idx;
    uint8_t reg_count;
    uint8_t access_size;
    uint8_t per_reg_size;
    arm64_reg regs[2];
    arm64_reg base_reg;
    arm64_reg index_reg;
    arm64_extender index_ext;
    uint8_t index_shift;
    int64_t disp;
};

static bool starts_with(const char *s, const char *prefix) {
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

static bool is_arm64_load(const char *mnemonic) {
    return starts_with(mnemonic, "ldr") ||
           starts_with(mnemonic, "ldur") ||
           starts_with(mnemonic, "ldp") ||
           starts_with(mnemonic, "ldnp") ||
           starts_with(mnemonic, "ldar") ||
           starts_with(mnemonic, "ldaxr") ||
           starts_with(mnemonic, "ldxr");
}

static bool is_arm64_store(const char *mnemonic) {
    return starts_with(mnemonic, "str") ||
           starts_with(mnemonic, "stur") ||
           starts_with(mnemonic, "stp") ||
           starts_with(mnemonic, "stnp") ||
           starts_with(mnemonic, "stlr") ||
           starts_with(mnemonic, "stlxr") ||
           starts_with(mnemonic, "stxr");
}

static bool is_supported_gpr(arm64_reg reg) {
    if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) return true;
    if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28) return true;
    return reg == ARM64_REG_X29 || reg == ARM64_REG_X30 ||
           reg == ARM64_REG_SP || reg == ARM64_REG_WSP ||
           reg == ARM64_REG_XZR || reg == ARM64_REG_WZR;
}

static bool is_stack_relative(arm64_reg reg) {
    return reg == ARM64_REG_SP || reg == ARM64_REG_WSP ||
           reg == ARM64_REG_X29 || reg == ARM64_REG_W29;
}

static uint8_t arm64_memory_width(const char *mnemonic, arm64_reg reg) {
    const size_t len = strlen(mnemonic);
    if (strstr(mnemonic, "rsb") != nullptr ||
        (len > 0 && mnemonic[len - 1] == 'b'))
        return 1;
    if (strstr(mnemonic, "rsh") != nullptr ||
        (len > 0 && mnemonic[len - 1] == 'h'))
        return 2;
    if (strstr(mnemonic, "rsw") != nullptr)
        return 4;
    if ((reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) ||
        reg == ARM64_REG_WSP || reg == ARM64_REG_WZR)
        return 4;
    return 8;
}

static bool analyze_arm64_mem(const cs_insn *insn,
                              const pgas_stalker_config_t *cfg,
                              arm64_mem_info *out) {
    memset(out, 0, sizeof(*out));
    out->base_reg = ARM64_REG_INVALID;
    out->index_reg = ARM64_REG_INVALID;

    const bool is_load = is_arm64_load(insn->mnemonic);
    const bool is_store = is_arm64_store(insn->mnemonic);
    if (!is_load && !is_store) return false;
    if (!cfg->hook_mov) return false;

    const cs_arm64 *arm64 = &insn->detail->arm64;
    int mem_idx = -1;
    for (uint8_t i = 0; i < arm64->op_count; i++) {
        if (arm64->operands[i].type == ARM64_OP_MEM) {
            mem_idx = i;
            break;
        }
    }
    if (mem_idx < 0) return false;

    out->has_mem_op = true;
    out->is_load = is_load;
    out->is_store = is_store;
    out->mem_op_idx = (uint8_t)mem_idx;
    out->base_reg = arm64->operands[mem_idx].mem.base;
    out->index_reg = arm64->operands[mem_idx].mem.index;
    out->index_ext = arm64->operands[mem_idx].ext;
    out->index_shift = (uint8_t)arm64->operands[mem_idx].shift.value;
    out->disp = arm64->operands[mem_idx].mem.disp;

    for (int i = 0; i < mem_idx && out->reg_count < 2; i++) {
        if (arm64->operands[i].type != ARM64_OP_REG) continue;
        arm64_reg reg = (arm64_reg)arm64->operands[i].reg;
        if (!is_supported_gpr(reg)) continue;
        out->regs[out->reg_count++] = reg;
        if (out->per_reg_size == 0) {
            out->per_reg_size = arm64_memory_width(insn->mnemonic, reg);
        }
    }

    if (out->reg_count == 0) return false;
    if (out->per_reg_size == 0) out->per_reg_size = 8;
    if (out->per_reg_size > 8) return false;

    out->access_size = out->per_reg_size * out->reg_count;
    if (out->access_size == 0 || out->access_size > 16) return false;
    return true;
}

static uint64_t read_reg(const GumCpuContext *cpu, arm64_reg reg) {
    if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28) {
        return cpu->x[reg - ARM64_REG_X0];
    }
    if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W28) {
        return (uint32_t)cpu->x[reg - ARM64_REG_W0];
    }
    if (reg == ARM64_REG_X29) return cpu->fp;
    if (reg == ARM64_REG_W29) return (uint32_t)cpu->fp;
    if (reg == ARM64_REG_X30) return cpu->lr;
    if (reg == ARM64_REG_W30) return (uint32_t)cpu->lr;
    if (reg == ARM64_REG_SP || reg == ARM64_REG_WSP) return cpu->sp;
    return 0;
}

static uint64_t compute_ea(const GumCpuContext *cpu, const arm64_mem_info *info) {
    uint64_t ea = (uint64_t)info->disp;
    if (info->base_reg != ARM64_REG_INVALID)
        ea += read_reg(cpu, info->base_reg);
    if (info->index_reg != ARM64_REG_INVALID) {
        uint64_t index = read_reg(cpu, info->index_reg);
        switch (info->index_ext) {
        case ARM64_EXT_UXTB: index = (uint8_t)index; break;
        case ARM64_EXT_UXTH: index = (uint16_t)index; break;
        case ARM64_EXT_UXTW: index = (uint32_t)index; break;
        case ARM64_EXT_SXTB: index = (uint64_t)(int64_t)(int8_t)index; break;
        case ARM64_EXT_SXTH: index = (uint64_t)(int64_t)(int16_t)index; break;
        case ARM64_EXT_SXTW: index = (uint64_t)(int64_t)(int32_t)index; break;
        case ARM64_EXT_SXTX: index = (uint64_t)(int64_t)index; break;
        default: break;
        }
        ea += index << info->index_shift;
    }
    return ea;
}

static bool is_in_pgas_range(uint64_t ea, uint64_t base, uint64_t size) {
    return size != 0 && ea >= base && (ea - base) < size;
}

static void store_le(uint8_t *buf, uint64_t val, size_t size) {
    for (size_t i = 0; i < size && i < 8; i++) {
        buf[i] = (uint8_t)((val >> (i * 8)) & 0xff);
    }
}

static void copy_to_shadow(uint64_t ea, const uint8_t *buf, size_t size) {
    volatile uint8_t *dst = (volatile uint8_t *)ea;
    for (size_t i = 0; i < size; i++) {
        dst[i] = buf[i];
    }
}

struct arm64_callout_data {
    uint64_t pgas_base;
    uint64_t pgas_size;
    uint16_t local_node_id;
    uint16_t num_nodes;
    pgas_stalker_stats_t *stats;
    arm64_mem_info info;
};

#define CALLOUT_POOL_CAPACITY (1024 * 1024)
static arm64_callout_data g_callout_pool_storage[CALLOUT_POOL_CAPACITY];
static uint64_t g_callout_pool_next = 0;

static arm64_callout_data *alloc_callout_data() {
    uint64_t idx = __atomic_fetch_add(&g_callout_pool_next, 1, __ATOMIC_RELAXED);
    if (idx >= CALLOUT_POOL_CAPACITY) {
        SPDLOG_ERROR("Callout pool exhausted ({} entries)", CALLOUT_POOL_CAPACITY);
        return nullptr;
    }
    return &g_callout_pool_storage[idx];
}

static uint16_t route_node(const arm64_callout_data *cd, uint64_t ea) {
    uint64_t region_per_node = cd->pgas_size / cd->num_nodes;
    if (region_per_node == 0) return cd->local_node_id;
    uint64_t offset = ea - cd->pgas_base;
    uint16_t node = (uint16_t)(offset / region_per_node);
    if (node >= cd->num_nodes) node = cd->num_nodes - 1;
    return node;
}

static void arm64_load_callout(GumCpuContext *cpu_context, gpointer user_data) {
    auto *cd = (arm64_callout_data *)user_data;
    __atomic_fetch_add(&cd->stats->callouts_fired, 1, __ATOMIC_RELAXED);
    uint64_t ea = compute_ea(cpu_context, &cd->info);
    if (!is_in_pgas_range(ea, cd->pgas_base, cd->pgas_size) ||
        cd->num_nodes == 0) {
        return;
    }

    uint16_t node = route_node(cd, ea);
    if (node == cd->local_node_id) {
        __atomic_fetch_add(&cd->stats->local_passthrough, 1, __ATOMIC_RELAXED);
        return;
    }

    uint8_t buf[16] = {};
    size_t sz = cd->info.access_size;
    auto &hooker = pgas_cxlmemsim_hooker::instance();
    hooker.remote_read(node, ea, buf, sz);
    copy_to_shadow(ea, buf, sz);

    __atomic_fetch_add(&cd->stats->remote_loads, 1, __ATOMIC_RELAXED);
}

static void arm64_store_callout(GumCpuContext *cpu_context, gpointer user_data) {
    auto *cd = (arm64_callout_data *)user_data;
    __atomic_fetch_add(&cd->stats->callouts_fired, 1, __ATOMIC_RELAXED);
    uint64_t ea = compute_ea(cpu_context, &cd->info);
    if (!is_in_pgas_range(ea, cd->pgas_base, cd->pgas_size) ||
        cd->num_nodes == 0) {
        return;
    }

    uint16_t node = route_node(cd, ea);
    if (node == cd->local_node_id) {
        __atomic_fetch_add(&cd->stats->local_passthrough, 1, __ATOMIC_RELAXED);
        return;
    }

    uint8_t buf[16] = {};
    for (uint8_t i = 0; i < cd->info.reg_count; i++) {
        const size_t off = (size_t)i * cd->info.per_reg_size;
        store_le(buf + off, read_reg(cpu_context, cd->info.regs[i]),
                 cd->info.per_reg_size);
    }

    auto &hooker = pgas_cxlmemsim_hooker::instance();
    hooker.remote_write(node, ea, buf, cd->info.access_size);

    __atomic_fetch_add(&cd->stats->remote_stores, 1, __ATOMIC_RELAXED);
}

static void transform_block(GumStalkerIterator *iterator,
                            GumStalkerOutput *output, gpointer user_data) {
    (void)output;
    auto *ctx = (pgas_stalker_ctx *)user_data;
    const cs_insn *insn;

    __atomic_fetch_add(&ctx->stats.blocks_transformed, 1, __ATOMIC_RELAXED);

    while (gum_stalker_iterator_next(iterator, &insn)) {
        __atomic_fetch_add(&ctx->stats.insns_scanned, 1, __ATOMIC_RELAXED);

        arm64_mem_info info;
        if (!analyze_arm64_mem(insn, &ctx->config, &info)) {
            gum_stalker_iterator_keep(iterator);
            continue;
        }

        if (is_stack_relative(info.base_reg)) {
            gum_stalker_iterator_keep(iterator);
            continue;
        }

        bool needs_runtime = (info.base_reg != ARM64_REG_INVALID ||
                              info.index_reg != ARM64_REG_INVALID);
        if (!needs_runtime) {
            uint64_t ea = (uint64_t)info.disp;
            if (!is_in_pgas_range(ea, ctx->config.pgas_base_addr,
                                  ctx->config.pgas_region_size)) {
                gum_stalker_iterator_keep(iterator);
                continue;
            }
        }

        auto *cd = alloc_callout_data();
        if (!cd) {
            gum_stalker_iterator_keep(iterator);
            continue;
        }

        cd->pgas_base = ctx->config.pgas_base_addr;
        cd->pgas_size = ctx->config.pgas_region_size;
        cd->local_node_id = ctx->config.local_node_id;
        cd->num_nodes = ctx->config.num_nodes;
        cd->stats = &ctx->stats;
        cd->info = info;

        gum_stalker_iterator_put_callout(iterator,
            info.is_load ? arm64_load_callout : arm64_store_callout, cd, NULL);
        gum_stalker_iterator_keep(iterator);

        if (info.is_load) {
            __atomic_fetch_add(&ctx->stats.mov_loads_hooked, 1,
                               __ATOMIC_RELAXED);
        } else {
            __atomic_fetch_add(&ctx->stats.mov_stores_hooked, 1,
                               __ATOMIC_RELAXED);
        }
    }
}

extern "C" {

pgas_stalker_ctx_t *pgas_stalker_init(const pgas_stalker_config_t *config) {
    auto *ctx = new pgas_stalker_ctx();
    memset(&ctx->stats, 0, sizeof(ctx->stats));
    ctx->config = *config;
    ctx->active = false;

    if (!config->hook_mov && !config->hook_movzx &&
        !config->hook_movnti && !config->hook_rep_movs) {
        ctx->config.hook_mov = true;
    }

    ctx->stalker = gum_stalker_new();
    if (!ctx->stalker) {
        SPDLOG_ERROR("gum_stalker_new() failed");
        delete ctx;
        return nullptr;
    }

    int trust = config->trust_threshold;
    if (trust == 0) trust = -1;
    gum_stalker_set_trust_threshold(ctx->stalker, trust);

    ctx->transformer = gum_stalker_transformer_make_from_callback(
        transform_block, ctx, NULL);

    SPDLOG_INFO("PGAS ARM64 Stalker initialized: base=0x{:x} size={} nodes={} trust={}",
                config->pgas_base_addr, config->pgas_region_size,
                config->num_nodes, trust);

    return ctx;
}

int pgas_stalker_follow_me(pgas_stalker_ctx_t *ctx) {
    if (!ctx || !ctx->stalker) return -1;
    gum_stalker_follow_me(ctx->stalker, ctx->transformer, NULL);
    ctx->active = true;
    SPDLOG_INFO("ARM64 Stalker following current thread");
    return 0;
}

int pgas_stalker_follow(pgas_stalker_ctx_t *ctx, GumThreadId thread_id) {
    if (!ctx || !ctx->stalker) return -1;
    gum_stalker_follow(ctx->stalker, thread_id, ctx->transformer, NULL);
    ctx->active = true;
    SPDLOG_INFO("ARM64 Stalker following thread {}", thread_id);
    return 0;
}

void pgas_stalker_unfollow_me(pgas_stalker_ctx_t *ctx) {
    if (!ctx || !ctx->stalker) return;
    gum_stalker_unfollow_me(ctx->stalker);
    SPDLOG_INFO("ARM64 Stalker unfollowed current thread");
}

void pgas_stalker_unfollow(pgas_stalker_ctx_t *ctx, GumThreadId thread_id) {
    if (!ctx || !ctx->stalker) return;
    gum_stalker_unfollow(ctx->stalker, thread_id);
}

void pgas_stalker_activate(pgas_stalker_ctx_t *ctx, const void *target) {
    if (!ctx || !ctx->stalker) return;
    gum_stalker_activate(ctx->stalker, target);
}

void pgas_stalker_deactivate(pgas_stalker_ctx_t *ctx) {
    if (!ctx || !ctx->stalker) return;
    gum_stalker_deactivate(ctx->stalker);
}

void pgas_stalker_exclude(pgas_stalker_ctx_t *ctx, uint64_t base, uint64_t size) {
    if (!ctx || !ctx->stalker) return;
    GumMemoryRange range;
    range.base_address = (GumAddress)base;
    range.size = (gsize)size;
    gum_stalker_exclude(ctx->stalker, &range);
}

void pgas_stalker_get_stats(pgas_stalker_ctx_t *ctx, pgas_stalker_stats_t *stats) {
    if (!ctx || !stats) return;
    *stats = ctx->stats;
}

void pgas_stalker_print_stats(pgas_stalker_ctx_t *ctx) {
    if (!ctx) return;
    auto &s = ctx->stats;
    uint64_t total_hooked = s.mov_loads_hooked + s.mov_stores_hooked;
    uint64_t range_hits = s.remote_loads + s.remote_stores + s.local_passthrough;

    printf("\n=== PGAS Stalker ARM64 Load/Store Statistics ===\n");
    printf("JIT phase:\n");
    printf("  Blocks transformed:   %lu\n", s.blocks_transformed);
    printf("  Instructions scanned: %lu\n", s.insns_scanned);
    printf("  Loads hooked:         %lu\n", s.mov_loads_hooked);
    printf("  Stores hooked:        %lu\n", s.mov_stores_hooked);
    printf("  Instrumentation rate: %.1f%%\n",
           s.insns_scanned ? 100.0 * total_hooked / s.insns_scanned : 0);
    printf("Runtime:\n");
    printf("  Callouts fired:       %lu\n", s.callouts_fired);
    printf("  PGAS range hits:      %lu\n", range_hits);
    printf("  Remote loads:         %lu\n", s.remote_loads);
    printf("  Remote stores:        %lu\n", s.remote_stores);
    printf("  Local passthrough:    %lu\n", s.local_passthrough);
    printf("  Callout pool used:    %lu / %d\n",
           g_callout_pool_next, CALLOUT_POOL_CAPACITY);
    printf("===============================================\n\n");
}

void pgas_stalker_print_json(
    pgas_stalker_ctx_t *, const pgas_stalker_lifecycle_stats_t *)
{
}

void pgas_stalker_finalize(pgas_stalker_ctx_t *ctx) {
    if (!ctx) return;
    if (ctx->stalker) {
        gum_stalker_flush(ctx->stalker);
        gum_stalker_garbage_collect(ctx->stalker);
        g_object_unref(ctx->stalker);
    }
    if (ctx->transformer)
        g_object_unref(ctx->transformer);

    g_callout_pool_next = 0;

    delete ctx;
    SPDLOG_INFO("PGAS ARM64 Stalker finalized");
}

} // extern "C"

#else

extern "C" {

pgas_stalker_ctx_t *pgas_stalker_init(const pgas_stalker_config_t *config) {
    (void)config;
    fprintf(stderr, "[PGAS_STALKER] instruction-level Stalker is not supported on this architecture; use function-level preload hooks.\n");
    return nullptr;
}

int pgas_stalker_follow_me(pgas_stalker_ctx_t *ctx) { (void)ctx; return -1; }
int pgas_stalker_follow(pgas_stalker_ctx_t *ctx, GumThreadId thread_id) {
    (void)ctx;
    (void)thread_id;
    return -1;
}
void pgas_stalker_unfollow_me(pgas_stalker_ctx_t *ctx) { (void)ctx; }
void pgas_stalker_unfollow(pgas_stalker_ctx_t *ctx, GumThreadId thread_id) {
    (void)ctx;
    (void)thread_id;
}
void pgas_stalker_activate(pgas_stalker_ctx_t *ctx, const void *target) {
    (void)ctx;
    (void)target;
}
void pgas_stalker_deactivate(pgas_stalker_ctx_t *ctx) { (void)ctx; }
void pgas_stalker_exclude(pgas_stalker_ctx_t *ctx, uint64_t base, uint64_t size) {
    (void)ctx;
    (void)base;
    (void)size;
}
void pgas_stalker_get_stats(pgas_stalker_ctx_t *ctx, pgas_stalker_stats_t *stats) {
    (void)ctx;
    if (stats) memset(stats, 0, sizeof(*stats));
}
void pgas_stalker_print_stats(pgas_stalker_ctx_t *ctx) { (void)ctx; }
void pgas_stalker_print_json(
    pgas_stalker_ctx_t *, const pgas_stalker_lifecycle_stats_t *) {}
void pgas_stalker_finalize(pgas_stalker_ctx_t *ctx) { (void)ctx; }

} // extern "C"

#endif
