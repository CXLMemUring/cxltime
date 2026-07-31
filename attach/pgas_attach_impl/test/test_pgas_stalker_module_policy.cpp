// SPDX-License-Identifier: MIT
#include <catch2/catch_test_macros.hpp>

#include "pgas_stalker_module_policy.hpp"
#include "pgas_stalker_mov.hpp"
#include "pgas_x86_memory_access.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>
#include <thread>
#include <vector>

using namespace bpftime::attach;

TEST_CASE("x86 memory descriptors preserve decoded metadata",
          "[pgas][x86][descriptor]")
{
    pgas_x86_memory_descriptor descriptor{};
    descriptor.instruction_address = 0x123456789abcdef0ULL;
    descriptor.instruction_id = 17;
    std::strcpy(descriptor.mnemonic, "mov");
    descriptor.access_class = pgas_x86_access_class::read;
    descriptor.memory_operand_index = 1;
    descriptor.width = 8;
    descriptor.base_register = 2;
    descriptor.index_register = 3;
    descriptor.scale = 4;
    descriptor.displacement = -16;
    descriptor.data_register = 5;
    descriptor.register_class = pgas_x86_register_class::gpr;
    descriptor.atomic = false;
    descriptor.executable_scalar_mov = true;

    REQUIRE(descriptor.instruction_address == 0x123456789abcdef0ULL);
    REQUIRE(descriptor.instruction_id == 17);
    REQUIRE(std::strcmp(descriptor.mnemonic, "mov") == 0);
    REQUIRE(descriptor.access_class == pgas_x86_access_class::read);
    REQUIRE(descriptor.memory_operand_index == 1);
    REQUIRE(descriptor.width == 8);
    REQUIRE(descriptor.base_register == 2);
    REQUIRE(descriptor.index_register == 3);
    REQUIRE(descriptor.scale == 4);
    REQUIRE(descriptor.displacement == -16);
    REQUIRE(descriptor.data_register == 5);
    REQUIRE(descriptor.register_class == pgas_x86_register_class::gpr);
    REQUIRE_FALSE(descriptor.atomic);
    REQUIRE(descriptor.executable_scalar_mov);
}

TEST_CASE("main executable and exact allowlist basenames are instrumented",
          "[pgas][stalker][module]")
{
    pgas_stalker_module_policy policy(" libggml.so , libllama.so ");

    REQUIRE(policy.should_instrument("splash-llm", true));
    REQUIRE(policy.should_instrument("libggml.so", false));
    REQUIRE(policy.may_instrument("libllama.so", false));
    REQUIRE_FALSE(policy.should_instrument("libggml-extra.so", false));
    REQUIRE_FALSE(policy.should_instrument("libother.so", false));

    const auto unseen = policy.requested_but_unseen();
    REQUIRE(unseen.size() == 1);
    REQUIRE(unseen[0] == "libllama.so");
    REQUIRE(policy.requested() ==
            std::vector<std::string>{ "libggml.so", "libllama.so" });
    REQUIRE(policy.observed() == std::vector<std::string>{ "libggml.so" });
}

TEST_CASE("hard-denied modules cannot be re-enabled",
          "[pgas][stalker][module]")
{
    pgas_stalker_module_policy policy(
        "libfrida-gum.so,libpgas_preload.so,libcxlmemsim_client.so");

    REQUIRE_FALSE(policy.should_instrument("libfrida-gum.so", false));
    REQUIRE_FALSE(policy.should_instrument("libpgas_preload.so", false));
    REQUIRE_FALSE(policy.should_instrument("libcxlmemsim_client.so", false));
    REQUIRE_FALSE(policy.should_instrument("libpgas_preload.so", true));
    REQUIRE(policy.requested_but_unseen().size() == 3);

    pgas_stalker_module_policy versioned_policy(
        "libfrida-gum.so.1,libpgas_preload.so.1.0.0,"
        "libcxlmemsim_client.so.2");
    REQUIRE_FALSE(versioned_policy.should_instrument("libfrida-gum.so.1", false));
    REQUIRE_FALSE(
        versioned_policy.should_instrument("libpgas_preload.so.1.0.0", false));
    REQUIRE_FALSE(
        versioned_policy.should_instrument("libcxlmemsim_client.so.2", false));
    REQUIRE(versioned_policy.requested_but_unseen().size() == 3);

    pgas_stalker_module_policy system_policy(
        "libc.so.6,libpthread.so.0,ld-linux-x86-64.so.2");
    REQUIRE_FALSE(system_policy.should_instrument("libc.so.6", false));
    REQUIRE_FALSE(system_policy.should_instrument("libpthread.so.0", false));
    REQUIRE_FALSE(
        system_policy.should_instrument("ld-linux-x86-64.so.2", false));
}

TEST_CASE("empty allowlist entries are rejected", "[pgas][stalker][module]")
{
    REQUIRE_NOTHROW(pgas_stalker_module_policy(""));
    REQUIRE_THROWS_AS(pgas_stalker_module_policy("libggml.so,,libllama.so"),
                      std::invalid_argument);
    REQUIRE_THROWS_AS(pgas_stalker_module_policy("libggml.so,   "),
                      std::invalid_argument);
}

TEST_CASE("Stalker snapshots stable per-thread follow records",
          "[pgas][stalker][thread]")
{
    gum_init_embedded();
    pgas_stalker_config_t config{};
    config.pgas_base_addr = 0x4000000000ULL;
    config.pgas_region_size = 4096;
    config.local_node_id = 0;
    config.num_nodes = 1;
    config.include_modules = "librequested-but-unseen.so";
    config.strict_validation = true;

    auto *context = pgas_stalker_init(&config);
    REQUIRE(context != nullptr);
    // This test links the Stalker implementation into the main executable,
    // so exclude it to avoid treating Frida's own statically linked code as
    // application code while exercising only the thread registry API.
    pgas_stalker_exclude(context, 0x1000, UINT64_MAX - 0x1000);

    std::array<int, 2> follow_results{ -1, -1 };
    for (int i = 0; i != 2; ++i) {
        std::thread worker([context, &follow_results, i] {
            follow_results[static_cast<size_t>(i)] =
                pgas_stalker_follow_me(context);
            pgas_stalker_unfollow_me(context);
        });
        worker.join();
    }
    REQUIRE(follow_results[0] == 0);
    REQUIRE(follow_results[1] == 0);

    const size_t count = pgas_stalker_snapshot_threads(context, nullptr, 0);
    REQUIRE(count == 2);
    std::vector<pgas_stalker_thread_stats_t> snapshot(count);
    REQUIRE(pgas_stalker_snapshot_threads(context, snapshot.data(),
                                          snapshot.size()) == count);
    std::ranges::sort(snapshot, {},
                      &pgas_stalker_thread_stats_t::runtime_id);
    REQUIRE(snapshot[0].runtime_id == 1);
    REQUIRE(snapshot[1].runtime_id == 2);
    REQUIRE(snapshot[0].os_tid != 0);
    REQUIRE(snapshot[1].os_tid != 0);
    REQUIRE(snapshot[0].os_tid != snapshot[1].os_tid);

    uint64_t follow_sum{};
    uint64_t unfollow_sum{};
    for (const auto &record : snapshot) {
        follow_sum += record.follow_events;
        unfollow_sum += record.unfollow_events;
    }
    REQUIRE(follow_sum == 2);
    REQUIRE(unfollow_sum == 2);
    REQUIRE(pgas_stalker_strict_valid(context) == 0);
    REQUIRE(pgas_stalker_should_follow_creator(
                context, "/tmp/librequested-but-unseen.so") == 1);
    REQUIRE(pgas_stalker_should_follow_creator(
                context, "/tmp/libpgas_preload.so") == 0);
    REQUIRE(pgas_stalker_strict_valid(context) == 1);

    pgas_stalker_finalize(context);
    gum_deinit_embedded();
}
