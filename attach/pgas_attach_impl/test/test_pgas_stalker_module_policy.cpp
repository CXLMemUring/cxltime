// SPDX-License-Identifier: MIT
#include <catch2/catch_test_macros.hpp>

#include "pgas_stalker_module_policy.hpp"
#include "pgas_x86_memory_access.hpp"

#include <cstring>
#include <stdexcept>

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
    REQUIRE_FALSE(policy.should_instrument("libggml-extra.so", false));
    REQUIRE_FALSE(policy.should_instrument("libother.so", false));

    const auto unseen = policy.requested_but_unseen();
    REQUIRE(unseen.size() == 1);
    REQUIRE(unseen[0] == "libllama.so");
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
}

TEST_CASE("empty allowlist entries are rejected", "[pgas][stalker][module]")
{
    REQUIRE_NOTHROW(pgas_stalker_module_policy(""));
    REQUIRE_THROWS_AS(pgas_stalker_module_policy("libggml.so,,libllama.so"),
                      std::invalid_argument);
    REQUIRE_THROWS_AS(pgas_stalker_module_policy("libggml.so,   "),
                      std::invalid_argument);
}
