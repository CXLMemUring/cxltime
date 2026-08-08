// SPDX-License-Identifier: MIT
#include <catch2/catch_test_macros.hpp>

#include "pgas_x86_memory_access.hpp"

#include <cstdint>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <limits>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>

using namespace bpftime::attach;

TEST_CASE("high PGAS base is not truncated", "[pgas][x86][range]")
{
    REQUIRE(pgas_x86_classify_range(0x4000000000ULL, 8,
                                    0x4000000000ULL, 4096) ==
            pgas_x86_range_result::inside);
    REQUIRE(pgas_x86_classify_range(0, 8, 0x4000000000ULL, 4096) ==
            pgas_x86_range_result::outside);
}

TEST_CASE("half-open PGAS boundaries are classified", "[pgas][x86][range]")
{
    constexpr uint64_t base = 0x4000000000ULL;
    constexpr uint64_t size = 4096;

    REQUIRE(pgas_x86_classify_range(base - 8, 8, base, size) ==
            pgas_x86_range_result::outside);
    REQUIRE(pgas_x86_classify_range(base + size, 8, base, size) ==
            pgas_x86_range_result::outside);
    REQUIRE(pgas_x86_classify_range(base + size - 8, 8, base, size) ==
            pgas_x86_range_result::inside);
    REQUIRE(pgas_x86_classify_range(base - 4, 8, base, size) ==
            pgas_x86_range_result::partial);
    REQUIRE(pgas_x86_classify_range(base + size - 4, 8, base, size) ==
            pgas_x86_range_result::partial);
}

TEST_CASE("invalid or overflowing PGAS intervals are rejected",
          "[pgas][x86][range]")
{
    constexpr uint64_t max = std::numeric_limits<uint64_t>::max();

    REQUIRE(pgas_x86_classify_range(0x4000000000ULL, 0,
                                    0x4000000000ULL, 4096) ==
            pgas_x86_range_result::overflow);
    REQUIRE(pgas_x86_classify_range(0x4000000000ULL, 65,
                                    0x4000000000ULL, 4096) ==
            pgas_x86_range_result::overflow);
    REQUIRE(pgas_x86_classify_range(max - 3, 8, 0, max) ==
            pgas_x86_range_result::overflow);
    REQUIRE(pgas_x86_classify_range(0, 8, max - 3, 8) ==
            pgas_x86_range_result::overflow);
}

TEST_CASE("scalar access splits at a cache line", "[pgas][x86][segment]")
{
    const auto segments = pgas_x86_split_cachelines(0x400000003cULL, 8);

    REQUIRE(segments.count == 2);
    REQUIRE(segments.value[0].address == 0x400000003cULL);
    REQUIRE(segments.value[0].offset == 0);
    REQUIRE(segments.value[0].size == 4);
    REQUIRE(segments.value[1].address == 0x4000000040ULL);
    REQUIRE(segments.value[1].offset == 4);
    REQUIRE(segments.value[1].size == 4);
}

TEST_CASE("scalar widths retain exact segment sizes", "[pgas][x86][segment]")
{
    for (const uint8_t width : { uint8_t{ 1 }, uint8_t{ 2 }, uint8_t{ 4 },
                                 uint8_t{ 8 } }) {
        const auto segments =
            pgas_x86_split_cachelines(0x4000000020ULL, width);
        REQUIRE(segments.count == 1);
        REQUIRE(segments.value[0].address == 0x4000000020ULL);
        REQUIRE(segments.value[0].offset == 0);
        REQUIRE(segments.value[0].size == width);
    }
}

TEST_CASE("invalid segment widths return no segments", "[pgas][x86][segment]")
{
    REQUIRE(pgas_x86_split_cachelines(0x4000000000ULL, 0).count == 0);
    REQUIRE(pgas_x86_split_cachelines(0x4000000000ULL, 65).count == 0);
}

namespace {

struct transport_call {
    bool write{};
    uint16_t node{};
    uint64_t address{};
    size_t size{};
};

struct fake_transport_state {
    std::mutex mutex;
    std::condition_variable changed;
    std::array<uint8_t, 128> remote{};
    std::vector<transport_call> calls;
    std::optional<pgas_x86_failure> failure;
    int read_count{};
    int fail_read_call{};
    int write_entries{};
    bool block_first_write{};
    bool release_first_write{};
};

int fake_read(void *opaque, uint16_t node, uint64_t address, void *dest,
              size_t size)
{
    auto &state = *static_cast<fake_transport_state *>(opaque);
    std::lock_guard lock(state.mutex);
    state.calls.push_back({ false, node, address, size });
    ++state.read_count;
    if (state.read_count == state.fail_read_call)
        return -EIO;
    std::memcpy(dest, state.remote.data() + address, size);
    return 0;
}

int fake_write(void *opaque, uint16_t node, uint64_t address,
               const void *source, size_t size)
{
    auto &state = *static_cast<fake_transport_state *>(opaque);
    std::unique_lock lock(state.mutex);
    state.calls.push_back({ true, node, address, size });
    ++state.write_entries;
    state.changed.notify_all();
    if (state.block_first_write && state.write_entries == 1) {
        state.changed.wait(lock,
                           [&] { return state.release_first_write; });
    }
    std::memcpy(state.remote.data() + address, source, size);
    return 0;
}

void record_failure(void *opaque, const pgas_x86_failure &failure)
{
    auto &state = *static_cast<fake_transport_state *>(opaque);
    std::lock_guard lock(state.mutex);
    state.failure = failure;
}

pgas_x86_memory_descriptor scalar_descriptor(pgas_x86_access_class access)
{
    pgas_x86_memory_descriptor descriptor{};
    descriptor.instruction_address = 0x1234;
    descriptor.instruction_id = 17;
    std::strcpy(descriptor.mnemonic, "mov");
    descriptor.access_class = access;
    descriptor.width = 8;
    descriptor.register_class = pgas_x86_register_class::gpr;
    descriptor.replayable = true;
    return descriptor;
}

pgas_x86_runtime *make_runtime(fake_transport_state &state, uint64_t base)
{
    pgas_x86_runtime_config config{};
    config.pgas_base = base;
    config.pgas_size = 256;
    config.local_node_id = 1;
    config.num_nodes = 2;
    config.transport = { fake_read, fake_write, &state };
    config.fail = record_failure;
    config.fail_opaque = &state;
    return pgas_x86_runtime_create(config);
}

} // namespace

TEST_CASE("cross-line load refreshes shadow only after all reads succeed",
          "[pgas][x86][transport]")
{
    alignas(64) std::array<uint8_t, 256> shadow{};
    fake_transport_state state;
    for (size_t i = 0; i < 8; ++i)
        state.remote[60 + i] = static_cast<uint8_t>(0xa0 + i);

    auto descriptor = scalar_descriptor(pgas_x86_access_class::read);
    auto *runtime = make_runtime(
        state, reinterpret_cast<uint64_t>(shadow.data()));
    REQUIRE(runtime != nullptr);

    pgas_x86_access_event event{};
    event.descriptor = &descriptor;
    event.effective_address =
        reinterpret_cast<uint64_t>(shadow.data() + 60);

    REQUIRE(pgas_x86_begin_load(runtime, &event) == 0);
    REQUIRE(event.locks_held);
    REQUIRE(std::memcmp(shadow.data() + 60, state.remote.data() + 60, 8) ==
            0);
    REQUIRE(state.calls.size() == 2);
    REQUIRE_FALSE(state.calls[0].write);
    REQUIRE(state.calls[0].node == 0);
    REQUIRE(state.calls[0].address == 60);
    REQUIRE(state.calls[0].size == 4);
    REQUIRE(state.calls[1].address == 64);
    REQUIRE(state.calls[1].size == 4);

    pgas_x86_finish_access(&event);
    REQUIRE_FALSE(event.locks_held);
    pgas_x86_runtime_destroy(runtime);
}

TEST_CASE("cross-line store publishes remote bytes before original shadow store",
          "[pgas][x86][transport]")
{
    alignas(64) std::array<uint8_t, 256> shadow{};
    const std::array<uint8_t, 8> source{ 1, 2, 3, 4, 5, 6, 7, 8 };
    fake_transport_state state;
    auto descriptor = scalar_descriptor(pgas_x86_access_class::write);
    auto *runtime = make_runtime(
        state, reinterpret_cast<uint64_t>(shadow.data()));
    REQUIRE(runtime != nullptr);

    pgas_x86_access_event event{};
    event.descriptor = &descriptor;
    event.effective_address =
        reinterpret_cast<uint64_t>(shadow.data() + 60);

    REQUIRE(pgas_x86_begin_store(runtime, &event, source.data(),
                                 source.size()) == 0);
    REQUIRE(std::memcmp(state.remote.data() + 60, source.data(), 8) == 0);
    REQUIRE(std::memcmp(shadow.data() + 60, source.data(), 8) != 0);
    REQUIRE(state.calls.size() == 2);
    REQUIRE(state.calls[0].write);
    REQUIRE(state.calls[0].address == 60);
    REQUIRE(state.calls[0].size == 4);
    REQUIRE(state.calls[1].address == 64);
    REQUIRE(state.calls[1].size == 4);

    std::memcpy(shadow.data() + 60, source.data(), source.size());
    pgas_x86_finish_access(&event);
    REQUIRE(std::memcmp(shadow.data() + 60, source.data(), 8) == 0);
    pgas_x86_runtime_destroy(runtime);
}

TEST_CASE("read-only shadow views refresh through alias and suppress stores",
          "[pgas][x86][transport][shadow-alias]")
{
    alignas(64) std::array<uint8_t, 256> public_shadow{};
    alignas(64) std::array<uint8_t, 256> write_alias{};
    fake_transport_state state;
    for (size_t i = 0; i < 8; ++i)
        state.remote[32 + i] = static_cast<uint8_t>(0xc0 + i);
    auto *runtime = make_runtime(
        state, reinterpret_cast<uint64_t>(public_shadow.data()));
    REQUIRE(runtime != nullptr);
    REQUIRE(pgas_x86_runtime_configure_shadow_alias(
                runtime, reinterpret_cast<uint64_t>(public_shadow.data()),
                public_shadow.size(), write_alias.data(),
                reinterpret_cast<uint64_t>(public_shadow.data()), 128) == 0);

    auto load_descriptor = scalar_descriptor(pgas_x86_access_class::read);
    pgas_x86_access_event load{};
    load.descriptor = &load_descriptor;
    load.effective_address =
        reinterpret_cast<uint64_t>(public_shadow.data() + 32);
    REQUIRE(pgas_x86_begin_load(runtime, &load) == 0);
    CHECK(std::memcmp(write_alias.data() + 32, state.remote.data() + 32, 8) ==
          0);
    CHECK(std::memcmp(public_shadow.data() + 32, state.remote.data() + 32,
                      8) != 0);
    pgas_x86_finish_access(&load);

    state.calls.clear();
    const std::array<uint8_t, 8> source{ 1, 2, 3, 4, 5, 6, 7, 8 };
    auto store_descriptor = scalar_descriptor(pgas_x86_access_class::write);
    pgas_x86_access_event store{};
    store.descriptor = &store_descriptor;
    store.effective_address =
        reinterpret_cast<uint64_t>(public_shadow.data() + 32);
    REQUIRE(pgas_x86_begin_store(runtime, &store, source.data(),
                                 source.size()) == 0);
    CHECK(state.calls.empty());
    CHECK(store.locks_held);
    pgas_x86_finish_access(&store);
    pgas_x86_runtime_destroy(runtime);
}

TEST_CASE("failed second load segment leaves shadow unchanged",
          "[pgas][x86][transport][failure]")
{
    alignas(64) std::array<uint8_t, 256> shadow{};
    shadow.fill(0x55);
    fake_transport_state state;
    state.remote.fill(0xaa);
    state.fail_read_call = 2;
    auto descriptor = scalar_descriptor(pgas_x86_access_class::read);
    auto *runtime = make_runtime(
        state, reinterpret_cast<uint64_t>(shadow.data()));
    REQUIRE(runtime != nullptr);

    pgas_x86_access_event event{};
    event.descriptor = &descriptor;
    event.effective_address =
        reinterpret_cast<uint64_t>(shadow.data() + 60);

    REQUIRE(pgas_x86_begin_load(runtime, &event) == -EIO);
    REQUIRE_FALSE(event.locks_held);
    for (size_t i = 0; i < 8; ++i)
        REQUIRE(shadow[60 + i] == 0x55);
    REQUIRE(state.failure.has_value());
    REQUIRE(state.failure->segment_index == 1);
    REQUIRE(state.failure->target_node == 0);
    REQUIRE(state.failure->transport_error == -EIO);
    REQUIRE(std::strcmp(state.failure->mnemonic, "mov") == 0);
    pgas_x86_runtime_destroy(runtime);
}

TEST_CASE("same-line stores remain excluded until finish",
          "[pgas][x86][transport][locking]")
{
    alignas(64) std::array<uint8_t, 256> shadow{};
    const std::array<uint8_t, 8> first{ 1, 1, 1, 1, 1, 1, 1, 1 };
    const std::array<uint8_t, 8> second{ 2, 2, 2, 2, 2, 2, 2, 2 };
    fake_transport_state state;
    state.block_first_write = true;
    auto descriptor = scalar_descriptor(pgas_x86_access_class::write);
    auto *runtime = make_runtime(
        state, reinterpret_cast<uint64_t>(shadow.data()));
    REQUIRE(runtime != nullptr);

    pgas_x86_access_event event_a{};
    event_a.descriptor = &descriptor;
    event_a.effective_address =
        reinterpret_cast<uint64_t>(shadow.data() + 16);
    pgas_x86_access_event event_b = event_a;
    int result_a = -1;
    int result_b = -1;

    std::thread thread_a([&] {
        result_a = pgas_x86_begin_store(runtime, &event_a, first.data(),
                                        first.size());
        if (result_a == 0) {
            std::memcpy(shadow.data() + 16, first.data(), first.size());
            pgas_x86_finish_access(&event_a);
        }
    });

    {
        std::unique_lock lock(state.mutex);
        state.changed.wait(lock, [&] { return state.write_entries == 1; });
    }

    std::thread thread_b([&] {
        result_b = pgas_x86_begin_store(runtime, &event_b, second.data(),
                                        second.size());
        if (result_b == 0) {
            std::memcpy(shadow.data() + 16, second.data(), second.size());
            pgas_x86_finish_access(&event_b);
        }
    });

    {
        std::unique_lock lock(state.mutex);
        REQUIRE_FALSE(state.changed.wait_for(
            lock, std::chrono::milliseconds(100),
            [&] { return state.write_entries > 1; }));
        state.release_first_write = true;
        state.changed.notify_all();
    }

    thread_a.join();
    thread_b.join();
    REQUIRE(result_a == 0);
    REQUIRE(result_b == 0);
    REQUIRE(state.write_entries == 2);
    pgas_x86_runtime_destroy(runtime);
}
