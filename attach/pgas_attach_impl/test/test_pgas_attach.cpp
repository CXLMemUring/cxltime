// SPDX-License-Identifier: MIT
// Test for PGAS attach implementation
#include <catch2/catch_test_macros.hpp>
#include "pgas_attach_impl.hpp"
#include <cstring>
#include <cstdio>
#include <atomic>

using namespace bpftime::attach;

// Test buffer for memory operations
static char test_src[1024] = "Hello PGAS World!";
static char test_dest[1024];

// Counter for hook invocations
static std::atomic<int> hook_count{0};
static std::atomic<int> remote_access_count{0};

// Test function that uses memcpy
void test_memcpy_function(void *dest, const void *src, size_t n) {
    memcpy(dest, src, n);
}

TEST_CASE("PGAS attach basic functionality", "[pgas]") {
    pgas_attach_impl impl;

    SECTION("Initialize and destroy") {
        // Just test that construction/destruction works
        REQUIRE(impl.get_local_accesses() == 0);
        REQUIRE(impl.get_remote_accesses() == 0);
    }

    SECTION("Set PGAS region") {
        impl.set_pgas_region(0x1000000, 0x10000000);
        // No direct way to verify, but should not crash
        REQUIRE(true);
    }
}

TEST_CASE("PGAS hook memcpy", "[pgas]") {
    pgas_attach_impl impl;
    hook_count = 0;

    // Configure PGAS region
    impl.set_pgas_region(0, 0xFFFFFFFFFFFFFFFF);

    // Create private data for hooking memcpy
    pgas_attach_private_data priv;
    priv.target_address = (void *)memcpy;
    priv.op_type = pgas_op_type::MEMCPY;
    priv.local_node_id = 0;
    priv.num_nodes = 4;

    // Create hook with callback
    int id = impl.create_attach_with_ebpf_callback(
        [](void *memory, size_t mem_size, uint64_t *ret) -> int {
            auto *ctx = (pgas_memory_context *)memory;
            hook_count++;

            printf("PGAS memcpy: dest=%p src=%p size=%zu target_node=%d\n",
                   ctx->address, ctx->data, ctx->size, ctx->target_node);

            if (ctx->is_remote) {
                remote_access_count++;
            }

            return 0;
        },
        priv,
        ATTACH_PGAS_MEMCPY);

    REQUIRE(id >= 0);

    SECTION("Hook intercepts memcpy calls") {
        // Perform memcpy - should trigger hook
        memcpy(test_dest, test_src, strlen(test_src) + 1);

        // Verify hook was called
        REQUIRE(hook_count > 0);

        // Verify memcpy still worked
        REQUIRE(strcmp(test_dest, test_src) == 0);
    }

    SECTION("Detach hook") {
        int result = impl.detach_by_id(id);
        REQUIRE(result == 0);

        // Detaching again should fail
        result = impl.detach_by_id(id);
        REQUIRE(result == -ENOENT);
    }
}

TEST_CASE("PGAS private data parsing", "[pgas]") {
    pgas_attach_private_data priv;

    SECTION("Parse address format") {
        int err = priv.initialize_from_string("0x12345678:load:0:4");
        REQUIRE(err == 0);
        REQUIRE(priv.target_address == (void *)0x12345678);
        REQUIRE(priv.op_type == pgas_op_type::LOAD);
        REQUIRE(priv.local_node_id == 0);
        REQUIRE(priv.num_nodes == 4);
    }

    SECTION("Parse module:symbol format") {
        int err = priv.initialize_from_string("libc.so.6:memcpy:memcpy:1:8");
        REQUIRE(err == 0);
        REQUIRE(priv.module_name == "libc.so.6");
        REQUIRE(priv.symbol_name == "memcpy");
    }

    SECTION("Parse different operation types") {
        priv.initialize_from_string("0x1000:store:0:1");
        REQUIRE(priv.op_type == pgas_op_type::STORE);

        priv.initialize_from_string("0x1000:atomic_add:0:1");
        REQUIRE(priv.op_type == pgas_op_type::ATOMIC_ADD);

        priv.initialize_from_string("0x1000:atomic_cas:0:1");
        REQUIRE(priv.op_type == pgas_op_type::ATOMIC_CAS);

        priv.initialize_from_string("0x1000:memcpy:0:1");
        REQUIRE(priv.op_type == pgas_op_type::MEMCPY);
    }

    SECTION("Convert to string") {
        priv.target_address = (void *)0xABCD;
        priv.op_type = pgas_op_type::STORE;
        priv.local_node_id = 2;
        priv.num_nodes = 8;

        std::string str = priv.to_string();
        REQUIRE(str.find("store") != std::string::npos);
        REQUIRE(str.find("2") != std::string::npos);
        REQUIRE(str.find("8") != std::string::npos);
    }
}

TEST_CASE("PGAS node routing", "[pgas]") {
    pgas_attach_impl impl;

    // Setup 4-node configuration
    impl.set_pgas_region(0x10000000, 0x40000000);  // 1GB total

    pgas_attach_private_data priv;
    priv.target_address = (void *)memcpy;
    priv.op_type = pgas_op_type::MEMCPY;
    priv.local_node_id = 0;
    priv.num_nodes = 4;

    // Track which nodes are accessed
    std::atomic<uint16_t> last_target_node{0};

    int id = impl.create_attach_with_ebpf_callback(
        [&last_target_node](void *memory, size_t, uint64_t *) -> int {
            auto *ctx = (pgas_memory_context *)memory;
            last_target_node = ctx->target_node;
            return 0;
        },
        priv,
        ATTACH_PGAS_MEMCPY);

    REQUIRE(id >= 0);

    // Test that different addresses route to different nodes
    // Node 0: 0x10000000 - 0x1FFFFFFF
    // Node 1: 0x20000000 - 0x2FFFFFFF
    // Node 2: 0x30000000 - 0x3FFFFFFF
    // Node 3: 0x40000000 - 0x4FFFFFFF

    // This would require actually performing memcpy to addresses
    // in those ranges, which we can't do in a simple test
    // So we just verify the hook was created successfully

    impl.detach_by_id(id);
}

TEST_CASE("PGAS multiple hooks", "[pgas]") {
    pgas_attach_impl impl;
    impl.set_pgas_region(0, 0xFFFFFFFFFFFFFFFF);

    std::atomic<int> load_count{0};
    std::atomic<int> store_count{0};

    // Create load hook
    pgas_attach_private_data load_priv;
    load_priv.target_address = (void *)memcpy;
    load_priv.op_type = pgas_op_type::LOAD;
    load_priv.local_node_id = 0;
    load_priv.num_nodes = 2;

    int load_id = impl.create_attach_with_ebpf_callback(
        [&load_count](void *, size_t, uint64_t *) -> int {
            load_count++;
            return 0;
        },
        load_priv,
        ATTACH_PGAS_LOAD);

    // Create store hook
    pgas_attach_private_data store_priv;
    store_priv.target_address = (void *)memcpy;
    store_priv.op_type = pgas_op_type::STORE;
    store_priv.local_node_id = 0;
    store_priv.num_nodes = 2;

    int store_id = impl.create_attach_with_ebpf_callback(
        [&store_count](void *, size_t, uint64_t *) -> int {
            store_count++;
            return 0;
        },
        store_priv,
        ATTACH_PGAS_STORE);

    REQUIRE(load_id >= 0);
    REQUIRE(store_id >= 0);
    REQUIRE(load_id != store_id);

    // Cleanup
    impl.detach_by_id(load_id);
    impl.detach_by_id(store_id);
}
