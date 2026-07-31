// SPDX-License-Identifier: MIT
// Portable fallback for architectures without PGAS instruction-level Stalker.

#include "pgas_stalker_mov.hpp"
#include <cstdio>
#include <cstring>

struct pgas_stalker_ctx {
    pgas_stalker_config_t config;
    pgas_stalker_stats_t stats;
};

extern "C" {

pgas_stalker_ctx_t *pgas_stalker_init(const pgas_stalker_config_t *config) {
    std::fprintf(stderr,
                 "[PGAS_STALKER] instruction-level Stalker is not supported "
                 "on this architecture; use function-level preload hooks.\n");

    auto *ctx = new pgas_stalker_ctx();
    if (config) {
        ctx->config = *config;
    } else {
        std::memset(&ctx->config, 0, sizeof(ctx->config));
    }
    std::memset(&ctx->stats, 0, sizeof(ctx->stats));
    delete ctx;
    return nullptr;
}

int pgas_stalker_follow_me(pgas_stalker_ctx_t *ctx) {
    (void)ctx;
    return -1;
}

int pgas_stalker_follow(pgas_stalker_ctx_t *ctx, GumThreadId thread_id) {
    (void)ctx;
    (void)thread_id;
    return -1;
}

void pgas_stalker_unfollow_me(pgas_stalker_ctx_t *ctx) {
    (void)ctx;
}

void pgas_stalker_unfollow(pgas_stalker_ctx_t *ctx, GumThreadId thread_id) {
    (void)ctx;
    (void)thread_id;
}

void pgas_stalker_activate(pgas_stalker_ctx_t *ctx, const void *target) {
    (void)ctx;
    (void)target;
}

void pgas_stalker_deactivate(pgas_stalker_ctx_t *ctx) {
    (void)ctx;
}

void pgas_stalker_exclude(pgas_stalker_ctx_t *ctx, uint64_t base, uint64_t size) {
    (void)ctx;
    (void)base;
    (void)size;
}

void pgas_stalker_get_stats(pgas_stalker_ctx_t *ctx, pgas_stalker_stats_t *stats) {
    (void)ctx;
    if (stats) {
        std::memset(stats, 0, sizeof(*stats));
    }
}

size_t pgas_stalker_snapshot_threads(pgas_stalker_ctx_t *,
                                     pgas_stalker_thread_stats_t *, size_t) {
    return 0;
}

int pgas_stalker_should_follow_creator(pgas_stalker_ctx_t *, const char *) {
    return 0;
}

int pgas_stalker_may_instrument_module(pgas_stalker_ctx_t *, const char *) {
    return 0;
}

int pgas_stalker_strict_valid(pgas_stalker_ctx_t *) {
    return 0;
}

void pgas_stalker_print_stats(pgas_stalker_ctx_t *ctx) {
    (void)ctx;
}

void pgas_stalker_finalize(pgas_stalker_ctx_t *ctx) {
    (void)ctx;
}

} // extern "C"
