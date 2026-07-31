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
#include "pgas_x86_memory_access.hpp"
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
#include <unordered_map>

#include <dlfcn.h>
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

struct pgas_stalker_ctx {
    GumStalker *stalker;
    GumStalkerTransformer *transformer;

    pgas_stalker_config_t config;
    pgas_stalker_stats_t stats;
    pgas_x86_runtime *runtime;
    std::unique_ptr<pgas_stalker_module_policy> module_policy;
    std::string main_basename;
    std::mutex module_cache_mutex;
    std::unordered_map<uintptr_t, bool> module_cache;
    std::mutex thread_mutex;
    std::vector<std::unique_ptr<stalker_thread_record>> threads;
    uint64_t next_runtime_id;

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

static bool is_atomic_instruction(const cs_insn *insn)
{
    const auto &x86 = insn->detail->x86;
    if (x86.prefix[0] == X86_PREFIX_LOCK || x86.prefix[1] == X86_PREFIX_LOCK ||
        x86.prefix[2] == X86_PREFIX_LOCK || x86.prefix[3] == X86_PREFIX_LOCK)
        return true;
    switch (insn->id) {
    case X86_INS_XCHG:
    case X86_INS_CMPXCHG:
    case X86_INS_CMPXCHG8B:
    case X86_INS_CMPXCHG16B:
    case X86_INS_XADD:
        return true;
    default:
        return false;
    }
}

static bool is_prefetch_instruction(const cs_insn *insn)
{
    return strncmp(insn->mnemonic, "prefetch", 8) == 0;
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
    out->atomic = is_atomic_instruction(insn);
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
            out->scale = x86->operands[i].mem.scale;
            out->displacement = x86->operands[i].mem.disp;
            out->width = x86->operands[i].size;

            const auto access = x86->operands[i].access;
            if (is_prefetch_instruction(insn)) {
                out->access_class = pgas_x86_access_class::prefetch;
            } else if ((access & CS_AC_READ) && (access & CS_AC_WRITE)) {
                out->access_class = pgas_x86_access_class::read_modify_write;
            } else if (access & CS_AC_READ) {
                out->access_class = pgas_x86_access_class::read;
            } else if (access & CS_AC_WRITE) {
                out->access_class = pgas_x86_access_class::write;
            } else if (i != 0) {
                out->access_class = pgas_x86_access_class::read;
            } else if (is_mov_insn(insn->id)) {
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

    for (uint8_t i = 0; i < x86->op_count; ++i) {
        if (i == out->memory_operand_index)
            continue;
        if (x86->operands[i].type == X86_OP_REG) {
            out->data_register = x86->operands[i].reg;
            out->register_class =
                register_class(static_cast<x86_reg>(out->data_register));
            break;
        }
    }

    const bool scalar_width = out->width == 1 || out->width == 2 ||
                              out->width == 4 || out->width == 8;
    const bool simple_access =
        out->access_class == pgas_x86_access_class::read ||
        out->access_class == pgas_x86_access_class::write;
    out->executable_scalar_mov =
        memory_count == 1 && is_mov_insn(insn->id) &&
        mov_is_enabled(insn->id, cfg) && simple_access && scalar_width &&
        out->register_class == pgas_x86_register_class::gpr && !out->atomic;
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

// ---------------------------------------------------------------------------
// OPT 4: Lock-free bump allocator for callout metadata
// ---------------------------------------------------------------------------

struct memory_callout_data {
    uint64_t pgas_base;
    uint64_t pgas_size;
    uint16_t local_node_id;
    pgas_stalker_stats_t *stats;
    pgas_x86_runtime *runtime;
    pgas_stalker_ctx *context;
    pgas_x86_memory_descriptor descriptor;
    char labels[5];
};

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
    pgas_x86_access_event event{};
    bool active{};
};

static thread_local pending_access current_access;

[[noreturn]] static void strict_access_failure(
    const memory_callout_data *cd, uint64_t effective_address, int error)
{
    const auto &descriptor = cd->descriptor;
    if (current_thread_record != nullptr &&
        current_thread_context == cd->context) {
        if (error == -ENOTSUP)
            ++current_thread_record->stats.unsupported;
        else
            ++current_thread_record->stats.failures;
    }
    dprintf(STDERR_FILENO,
            "Splash x86 PGAS validation failure: pc=0x%lx insn=%s(%u) "
            "ea=0x%lx width=%u class=%u error=%d\n",
            descriptor.instruction_address, descriptor.mnemonic,
            descriptor.instruction_id, effective_address, descriptor.width,
            static_cast<unsigned>(descriptor.access_class), error);
    _exit(125);
}

static void runtime_failure(void *, const pgas_x86_failure &failure)
{
    if (current_thread_record != nullptr)
        ++current_thread_record->stats.failures;
    dprintf(STDERR_FILENO,
            "Splash x86 PGAS transport failure: pc=0x%lx insn=%u "
            "ea=0x%lx width=%zu class=%u segment=%u node=%u error=%d\n",
            failure.instruction_address, failure.instruction_id,
            failure.effective_address, failure.width,
            static_cast<unsigned>(failure.access_class),
            failure.segment_index, failure.target_node,
            failure.transport_error);
    _exit(125);
}

static uint64_t read_data_register(const GumCpuContext *cpu, x86_reg reg)
{
    uint64_t value = read_reg(cpu, reg);
    if (reg == X86_REG_AH || reg == X86_REG_BH || reg == X86_REG_CH ||
        reg == X86_REG_DH)
        value >>= 8;
    return value;
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
    if (!cd->descriptor.executable_scalar_mov ||
        cd->descriptor.access_class == pgas_x86_access_class::prefetch)
        strict_access_failure(cd, effective_address, -ENOTSUP);
    if (current_access.active)
        strict_access_failure(cd, effective_address, -EBUSY);

    current_access.event = {};
    current_access.event.descriptor = &cd->descriptor;
    current_access.event.effective_address = effective_address;

    int result{};
    if (cd->descriptor.access_class == pgas_x86_access_class::read) {
        result = pgas_x86_begin_load(cd->runtime, &current_access.event);
    } else if (cd->descriptor.access_class == pgas_x86_access_class::write) {
        const uint64_t value = read_data_register(
            cpu_context, static_cast<x86_reg>(cd->descriptor.data_register));
        result = pgas_x86_begin_store(cd->runtime, &current_access.event,
                                      &value, cd->descriptor.width);
    } else {
        strict_access_failure(cd, effective_address, -ENOTSUP);
    }
    if (result != 0)
        strict_access_failure(cd, effective_address, result);

    current_access.active = true;
    __atomic_fetch_add(&cd->stats->callouts_fired, 1, __ATOMIC_RELAXED);
    if (current_access.event.target_node == cd->local_node_id) {
        __atomic_fetch_add(&cd->stats->local_passthrough, 1,
                           __ATOMIC_RELAXED);
    } else if (cd->descriptor.access_class == pgas_x86_access_class::read) {
        __atomic_fetch_add(&cd->stats->remote_loads, 1, __ATOMIC_RELAXED);
        ++current_thread_record->stats.remote_loads;
        current_thread_record->stats.bytes_read += cd->descriptor.width;
    } else {
        __atomic_fetch_add(&cd->stats->remote_stores, 1, __ATOMIC_RELAXED);
        ++current_thread_record->stats.remote_stores;
        current_thread_record->stats.bytes_written += cd->descriptor.width;
    }
    if (current_access.event.segments.count > 1)
        ++current_thread_record->stats.cross_line_splits;
}

static void memory_post_callout(GumCpuContext *, gpointer)
{
    if (!current_access.active)
        return;
    pgas_x86_finish_access(&current_access.event);
    current_access.active = false;
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

static void emit_memory_access(GumStalkerIterator *iterator,
                               GumStalkerOutput *output,
                               memory_callout_data *cd)
{
    auto *writer = output->writer.x86;
    const auto &descriptor = cd->descriptor;
    const bool simple_address =
        descriptor.base_register != X86_REG_INVALID &&
        descriptor.base_register != X86_REG_RIP &&
        descriptor.index_register == X86_REG_INVALID;
    std::array<GumX86Reg, 3> scratch{};
    const bool can_inline = simple_address &&
                            choose_scratch_registers(descriptor, scratch);

    if (!can_inline) {
        gum_stalker_iterator_put_callout(iterator, memory_pre_callout, cd,
                                         nullptr);
        gum_stalker_iterator_keep(iterator);
        gum_stalker_iterator_put_callout(iterator, memory_post_callout, cd,
                                         nullptr);
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
    gum_stalker_iterator_put_callout(iterator, memory_pre_callout, cd, nullptr);
    gum_x86_writer_put_jmp_near_label(writer, original);

    gum_x86_writer_put_label(writer, outside);
    gum_x86_writer_put_jmp_near_label(writer, original);

    gum_x86_writer_put_label(writer, partial);
    gum_stalker_iterator_put_callout(iterator, memory_pre_callout, cd, nullptr);
    gum_x86_writer_put_breakpoint(writer);

    gum_x86_writer_put_label(writer, overflow);
    gum_stalker_iterator_put_callout(iterator, memory_pre_callout, cd, nullptr);
    gum_x86_writer_put_breakpoint(writer);

    gum_x86_writer_put_label(writer, original);
    gum_stalker_iterator_keep(iterator);
    gum_stalker_iterator_put_callout(iterator, memory_post_callout, cd, nullptr);
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
        cd->stats = &ctx->stats;
        cd->runtime = ctx->runtime;
        cd->context = ctx;
        cd->descriptor = descriptor;

        emit_memory_access(iterator, output, cd);
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

pgas_stalker_ctx_t *pgas_stalker_init(const pgas_stalker_config_t *config) {
    if (config == nullptr)
        return nullptr;
    auto *ctx = new pgas_stalker_ctx();
    memset(&ctx->stats, 0, sizeof(ctx->stats));
    ctx->config = *config;
    ctx->runtime = nullptr;
    ctx->next_runtime_id = 1;
    ctx->active = false;

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
    if (ctx->runtime == nullptr) {
        SPDLOG_ERROR("Invalid x86 PGAS runtime configuration");
        delete ctx;
        return nullptr;
    }

    ctx->stalker = gum_stalker_new();
    if (!ctx->stalker) {
        SPDLOG_ERROR("gum_stalker_new() failed");
        pgas_x86_runtime_destroy(ctx->runtime);
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
    register_current_thread(ctx);
    gum_stalker_follow_me(ctx->stalker, ctx->transformer, NULL);
    ctx->active = true;
    SPDLOG_INFO("Stalker following current thread");
    return 0;
}

int pgas_stalker_follow(pgas_stalker_ctx_t *ctx, GumThreadId thread_id) {
    if (!ctx || !ctx->stalker) return -1;
    create_thread_record(ctx, static_cast<uint64_t>(thread_id));
    gum_stalker_follow(ctx->stalker, thread_id, ctx->transformer, NULL);
    ctx->active = true;
    SPDLOG_INFO("Stalker following thread {}", thread_id);
    return 0;
}

void pgas_stalker_unfollow_me(pgas_stalker_ctx_t *ctx) {
    if (!ctx || !ctx->stalker) return;
    gum_stalker_unfollow_me(ctx->stalker);
    unregister_current_thread(ctx);
    SPDLOG_INFO("Stalker unfollowed current thread");
}

void pgas_stalker_unfollow(pgas_stalker_ctx_t *ctx, GumThreadId thread_id) {
    if (!ctx || !ctx->stalker) return;
    gum_stalker_unfollow(ctx->stalker, thread_id);
    unregister_thread_id(ctx, static_cast<uint64_t>(thread_id));
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

    printf("\n=== PGAS Stalker MOV Statistics ===\n");
    printf("JIT phase:\n");
    printf("  Blocks transformed:   %lu\n", s.blocks_transformed);
    printf("  Instructions scanned: %lu\n", s.insns_scanned);
    printf("  MOV loads hooked:     %lu\n", s.mov_loads_hooked);
    printf("  MOV stores hooked:    %lu\n", s.mov_stores_hooked);
    printf("  Instrumentation rate: %.1f%%\n",
           s.insns_scanned ? 100.0 * total_hooked / s.insns_scanned : 0);
    printf("Runtime:\n");
    printf("  Callouts fired:       %lu\n", total_runtime);
    printf("  Remote loads:         %lu\n", s.remote_loads);
    printf("  Remote stores:        %lu\n", s.remote_stores);
    printf("  Local passthrough:    %lu\n", s.local_passthrough);
    printf("  Callout pool used:    %lu / %d\n",
           g_callout_pool_next, CALLOUT_POOL_CAPACITY);
    printf("==================================\n\n");
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

    pgas_x86_runtime_destroy(ctx->runtime);

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
void pgas_stalker_finalize(pgas_stalker_ctx_t *ctx) { (void)ctx; }

} // extern "C"

#endif
