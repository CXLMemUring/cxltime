// SPDX-License-Identifier: MIT
#include <catch2/catch_test_macros.hpp>

#include "pgas_model_mapping.hpp"

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

using namespace bpftime::attach;

namespace {

constexpr size_t page_size = 4096;
constexpr size_t node_size = 64 * 1024;

struct transport_state {
    std::array<std::vector<uint8_t>, 3> nodes;
    int reads{};
    int writes{};
    int fail_read_number{};
    int fail_write_number{};
    transport_state()
    {
        for (auto &node : nodes)
            node.resize(node_size + page_size);
    }
};

int transport_read(void *opaque, uint16_t node, uint64_t offset,
                   void *destination, size_t size)
{
    auto &state = *static_cast<transport_state *>(opaque);
    ++state.reads;
    if (state.fail_read_number == state.reads)
        return -EIO;
    if (node >= state.nodes.size() ||
        offset + size > state.nodes[node].size())
        return -ERANGE;
    std::memcpy(destination, state.nodes[node].data() + offset, size);
    return 0;
}

int transport_write(void *opaque, uint16_t node, uint64_t offset,
                    const void *source, size_t size)
{
    auto &state = *static_cast<transport_state *>(opaque);
    ++state.writes;
    if (state.fail_write_number == state.writes)
        return -EIO;
    if (node >= state.nodes.size() ||
        offset + size > state.nodes[node].size())
        return -ERANGE;
    std::memcpy(state.nodes[node].data() + offset, source, size);
    return 0;
}

struct temporary_file {
    std::string path;
    int fd{ -1 };
    std::vector<uint8_t> bytes;

    explicit temporary_file(uint8_t seed, size_t size = 3 * page_size)
        : bytes(size)
    {
        char name[] = "/tmp/pgas-model-XXXXXX";
        fd = mkstemp(name);
        REQUIRE(fd >= 0);
        path = name;
        for (size_t index = 0; index < bytes.size(); ++index)
            bytes[index] = static_cast<uint8_t>(seed + index * 13);
        REQUIRE(write(fd, bytes.data(), bytes.size()) ==
                static_cast<ssize_t>(bytes.size()));
    }

    ~temporary_file()
    {
        if (fd >= 0)
            close(fd);
        if (!path.empty())
            unlink(path.c_str());
    }
};

struct mapper_fixture {
    uint8_t *shadow{};
    transport_state transport;
    pgas_x86_runtime *runtime{};

    mapper_fixture()
    {
        shadow = static_cast<uint8_t *>(mmap(
            nullptr, 3 * node_size, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
        REQUIRE(shadow != MAP_FAILED);
        pgas_x86_runtime_config config{};
        config.pgas_base = reinterpret_cast<uint64_t>(shadow);
        config.pgas_size = 3 * node_size;
        config.local_node_id = 0;
        config.num_nodes = 3;
        config.transport = { transport_read, transport_write, &transport };
        runtime = pgas_x86_runtime_create(config);
        REQUIRE(runtime != nullptr);
    }

    ~mapper_fixture()
    {
        pgas_x86_runtime_destroy(runtime);
        munmap(shadow, 3 * node_size);
    }
};

} // namespace

TEST_CASE("model mapper matches exact file identity and seeds node one",
          "[pgas][model][mapping]")
{
    mapper_fixture fixture;
    temporary_file selected(17);
    temporary_file other(91);
    const std::string alias = selected.path + ".alias";
    REQUIRE(symlink(selected.path.c_str(), alias.c_str()) == 0);
    const int alias_fd = open(alias.c_str(), O_RDONLY);
    REQUIRE(alias_fd >= 0);

    pgas_model_mapper mapper;
    const pgas_model_mapping_config config{
        selected.path,
        reinterpret_cast<uint64_t>(fixture.shadow + node_size),
        3 * page_size,
        page_size,
        page_size,
        fixture.runtime,
    };
    REQUIRE(mapper.configure(config) == 0);
    CHECK(mapper.matches_fd(selected.fd));
    CHECK(mapper.matches_fd(alias_fd));
    CHECK_FALSE(mapper.matches_fd(other.fd));

    int error{};
    void *first = mapper.map_fd(alias_fd, page_size, 0, error);
    REQUIRE(first == fixture.shadow + node_size);
    CHECK(error == 0);
    CHECK(std::memcmp(first, selected.bytes.data(), page_size) == 0);
    CHECK(std::memcmp(fixture.transport.nodes[1].data(),
                      selected.bytes.data(), page_size) == 0);

    void *repeated = mapper.map_fd(selected.fd, page_size, 0, error);
    CHECK(repeated == first);
    auto inventory = mapper.inventory();
    CHECK(inventory.views == 1);
    CHECK(inventory.mapped_bytes == page_size);
    CHECK(inventory.seeded_bytes == page_size);
    CHECK(inventory.node0_model_bytes == 0);
    CHECK(inventory.node1_model_bytes == page_size);
    CHECK(inventory.dram_fallbacks == 0);

    REQUIRE(mapper.unmap(first, page_size, error));
    CHECK(mapper.inventory().views == 1);
    REQUIRE(mapper.unmap(first, page_size, error));
    CHECK(mapper.inventory().views == 0);
    CHECK(mapper.inventory().mapped_bytes == 0);
    close(alias_fd);
    unlink(alias.c_str());
}

TEST_CASE("model mapper tracks overlapping views and rejects every bound",
          "[pgas][model][mapping][bounds]")
{
    mapper_fixture fixture;
    temporary_file selected(43);
    pgas_model_mapper mapper;
    const uint64_t arena =
        reinterpret_cast<uint64_t>(fixture.shadow + node_size);
    REQUIRE(mapper.configure({ selected.path, arena, 3 * page_size,
                               page_size, 1024, fixture.runtime }) == 0);

    int error{};
    REQUIRE(mapper.map_fd(selected.fd, 2 * page_size, 0, error) ==
            reinterpret_cast<void *>(arena));
    REQUIRE(mapper.map_fd(selected.fd, 2 * page_size, page_size, error) ==
            reinterpret_cast<void *>(arena + page_size));
    auto inventory = mapper.inventory();
    CHECK(inventory.views == 2);
    CHECK(inventory.mapped_bytes == 4 * page_size);
    CHECK(inventory.seeded_bytes == 3 * page_size);
    CHECK(inventory.node1_model_bytes == 4 * page_size);

    CHECK(mapper.map_fd(selected.fd, page_size, 1, error) == nullptr);
    CHECK(error == EINVAL);
    CHECK(mapper.map_fd(selected.fd, page_size + 1,
                        2 * page_size, error) == nullptr);
    CHECK(error == EOVERFLOW);
    CHECK(mapper.map_fd(selected.fd, 0, 0, error) == nullptr);
    CHECK(error == EINVAL);
    CHECK_FALSE(mapper.unmap(reinterpret_cast<void *>(arena + 17),
                             page_size, error));
    CHECK(error == EINVAL);
    CHECK(mapper.inventory().rejected_mappings == 3);
}

TEST_CASE("model mapper reports unique seeded file coverage",
          "[pgas][model][mapping][coverage]")
{
    mapper_fixture fixture;
    temporary_file selected(47);
    pgas_model_mapper mapper;
    const uint64_t arena =
        reinterpret_cast<uint64_t>(fixture.shadow + node_size);
    REQUIRE(mapper.configure({ selected.path, arena, 3 * page_size,
                               page_size, page_size, fixture.runtime }) == 0);

    int error{};
    REQUIRE(mapper.map_fd(selected.fd, page_size, 0, error) ==
            reinterpret_cast<void *>(arena));
    REQUIRE(mapper.map_fd(selected.fd, page_size, 2 * page_size, error) ==
            reinterpret_cast<void *>(arena + 2 * page_size));
    CHECK(mapper.inventory().seeded_bytes == 2 * page_size);
}

TEST_CASE("model mapper refreshes active native shadow replicas",
          "[pgas][model][mapping][refresh]")
{
    mapper_fixture fixture;
    temporary_file selected(31);
    pgas_model_mapper mapper;
    const uint64_t arena =
        reinterpret_cast<uint64_t>(fixture.shadow + node_size);
    REQUIRE(mapper.configure({ selected.path, arena, 3 * page_size,
                               page_size, page_size, fixture.runtime }) == 0);

    int error{};
    auto *mapped = static_cast<uint8_t *>(
        mapper.map_fd(selected.fd, 2 * page_size, 0, error));
    REQUIRE(mapped == reinterpret_cast<void *>(arena));

    std::fill(fixture.transport.nodes[1].begin(),
              fixture.transport.nodes[1].begin() + 2 * page_size, 0xa5);
    std::memset(mapped, 0, 2 * page_size);
    REQUIRE(mapper.refresh_all() == 0);
    CHECK(std::all_of(mapped, mapped + 2 * page_size,
                      [](uint8_t value) { return value == 0xa5; }));
    auto inventory = mapper.inventory();
    CHECK(inventory.refresh_calls == 1);
    CHECK(inventory.refresh_requested_bytes == 2 * page_size);
    CHECK(inventory.refreshed_bytes == 2 * page_size);
    CHECK(inventory.refresh_failures == 0);

    fixture.transport.fail_read_number = fixture.transport.reads + 1;
    CHECK(mapper.refresh_all() == -EIO);
    inventory = mapper.inventory();
    CHECK(inventory.refresh_calls == 2);
    CHECK(inventory.refresh_requested_bytes == 4 * page_size);
    CHECK(inventory.refreshed_bytes == 2 * page_size);
    CHECK(inventory.refresh_failures == 1);
}

TEST_CASE("model mapper refreshes overlapping replicas only once",
          "[pgas][model][mapping][refresh][coverage]")
{
    mapper_fixture fixture;
    temporary_file selected(37);
    pgas_model_mapper mapper;
    const uint64_t arena =
        reinterpret_cast<uint64_t>(fixture.shadow + node_size);
    REQUIRE(mapper.configure({ selected.path, arena, 3 * page_size,
                               page_size, page_size, fixture.runtime }) == 0);

    int error{};
    REQUIRE(mapper.map_fd(selected.fd, 2 * page_size, 0, error) ==
            reinterpret_cast<void *>(arena));
    REQUIRE(mapper.map_fd(selected.fd, 2 * page_size, page_size, error) ==
            reinterpret_cast<void *>(arena + page_size));
    std::fill(fixture.transport.nodes[1].begin(),
              fixture.transport.nodes[1].begin() + 3 * page_size, 0x6b);
    std::memset(reinterpret_cast<void *>(arena), 0, 3 * page_size);

    REQUIRE(mapper.refresh_all() == 0);
    const auto inventory = mapper.inventory();
    CHECK(inventory.refresh_requested_bytes == 3 * page_size);
    CHECK(inventory.refreshed_bytes == 3 * page_size);
    CHECK(std::all_of(reinterpret_cast<uint8_t *>(arena),
                      reinterpret_cast<uint8_t *>(arena + 3 * page_size),
                      [](uint8_t value) { return value == 0x6b; }));
}

TEST_CASE("model mapper trims and splits partial unmaps",
          "[pgas][model][mapping][unmap]")
{
    mapper_fixture fixture;
    temporary_file selected(59);
    pgas_model_mapper mapper;
    const uint64_t arena =
        reinterpret_cast<uint64_t>(fixture.shadow + node_size);
    REQUIRE(mapper.configure({ selected.path, arena, 3 * page_size,
                               page_size, page_size, fixture.runtime }) == 0);

    int error{};
    REQUIRE(mapper.map_fd(selected.fd, 3 * page_size, 0, error) ==
            reinterpret_cast<void *>(arena));
    REQUIRE(mapper.unmap(reinterpret_cast<void *>(arena + page_size),
                         page_size, error));
    CHECK(mapper.inventory().views == 2);
    CHECK(mapper.inventory().mapped_bytes == 2 * page_size);
    CHECK(mapper.inventory().node1_model_bytes == 2 * page_size);

    REQUIRE(mapper.unmap(reinterpret_cast<void *>(arena), page_size, error));
    REQUIRE(mapper.unmap(reinterpret_cast<void *>(arena + 2 * page_size),
                         page_size, error));
    CHECK(mapper.inventory().views == 0);
    CHECK(mapper.inventory().mapped_bytes == 0);
    CHECK(mapper.inventory().seeded_bytes == 3 * page_size);
}

TEST_CASE("model mapper rounds munmap length to Linux page granularity",
          "[pgas][model][mapping][unmap][pages]")
{
    mapper_fixture fixture;
    temporary_file selected(61);
    pgas_model_mapper mapper;
    const uint64_t arena =
        reinterpret_cast<uint64_t>(fixture.shadow + node_size);
    REQUIRE(mapper.configure({ selected.path, arena, 3 * page_size,
                               page_size, page_size, fixture.runtime }) == 0);

    int error{};
    REQUIRE(mapper.map_fd(selected.fd, 3 * page_size, 0, error) ==
            reinterpret_cast<void *>(arena));
    REQUIRE(mapper.unmap(reinterpret_cast<void *>(arena), 1, error));
    CHECK(mapper.inventory().mapped_bytes == 2 * page_size);
    CHECK(mapper.inventory().views == 1);
    REQUIRE(mapper.unmap(reinterpret_cast<void *>(arena + page_size),
                         2 * page_size, error));
    CHECK(mapper.inventory().mapped_bytes == 0);
}

TEST_CASE("model mapper unmaps across adjacent views and holes",
          "[pgas][model][mapping][unmap][ranges]")
{
    mapper_fixture fixture;
    temporary_file selected(63);
    pgas_model_mapper mapper;
    const uint64_t arena =
        reinterpret_cast<uint64_t>(fixture.shadow + node_size);
    REQUIRE(mapper.configure({ selected.path, arena, 3 * page_size,
                               page_size, page_size, fixture.runtime }) == 0);

    int error{};
    REQUIRE(mapper.map_fd(selected.fd, page_size, 0, error) ==
            reinterpret_cast<void *>(arena));
    REQUIRE(mapper.map_fd(selected.fd, page_size, 2 * page_size, error) ==
            reinterpret_cast<void *>(arena + 2 * page_size));
    REQUIRE(mapper.unmap(reinterpret_cast<void *>(arena + page_size),
                         page_size, error));
    CHECK(mapper.inventory().views == 2);
    REQUIRE(mapper.unmap(reinterpret_cast<void *>(arena),
                         3 * page_size, error));
    CHECK(mapper.inventory().views == 0);
    CHECK(mapper.inventory().mapped_bytes == 0);
}

TEST_CASE("model mapper rejects overflowing and insufficient arenas",
          "[pgas][model][mapping][configure]")
{
    mapper_fixture fixture;
    temporary_file selected(67);
    pgas_model_mapper mapper;
    CHECK(mapper.configure({ selected.path, UINT64_MAX - page_size + 1,
                             2 * page_size, page_size, page_size,
                             fixture.runtime }) == -EOVERFLOW);
    CHECK(mapper.configure({ selected.path,
                             reinterpret_cast<uint64_t>(fixture.shadow),
                             2 * page_size, page_size, page_size,
                             fixture.runtime }) == -ENOSPC);
}

TEST_CASE("model mapper preserves configuration and poisons partial seeding",
          "[pgas][model][mapping][failure]")
{
    mapper_fixture fixture;
    temporary_file selected(101);
    temporary_file other(149);
    pgas_model_mapper mapper;
    const uint64_t arena =
        reinterpret_cast<uint64_t>(fixture.shadow + node_size);
    const pgas_model_mapping_config config{
        selected.path, arena, 3 * page_size, page_size, page_size,
        fixture.runtime
    };
    REQUIRE(mapper.configure(config) == 0);

    int error{};
    void *active = mapper.map_fd(selected.fd, page_size, 0, error);
    REQUIRE(active == reinterpret_cast<void *>(arena));
    CHECK(mapper.configure({ other.path, arena, 3 * page_size, page_size,
                             page_size, fixture.runtime }) == -EBUSY);
    CHECK(mapper.matches_fd(selected.fd));
    REQUIRE(mapper.unmap(active, page_size, error));

    CHECK(mapper.configure({ "/no/such/model.gguf", arena,
                             3 * page_size, page_size, page_size,
                             fixture.runtime }) == -ENOENT);
    CHECK(mapper.matches_fd(selected.fd));

    fixture.transport.writes = 0;
    fixture.transport.fail_write_number = 2;
    CHECK(mapper.map_fd(selected.fd, 3 * page_size, 0, error) == nullptr);
    CHECK(error == EIO);
    const auto inventory = mapper.inventory();
    CHECK(inventory.views == 0);
    CHECK(inventory.mapped_bytes == 0);
    CHECK(inventory.seeded_bytes == page_size);
    CHECK(mapper.map_fd(selected.fd, page_size, 0, error) == nullptr);
    CHECK(error == EIO);
}

TEST_CASE("model inventory assigns division remainder to the final node",
          "[pgas][model][mapping][inventory]")
{
    constexpr size_t region_size = 2 * node_size + 1;
    auto *shadow = static_cast<uint8_t *>(mmap(
        nullptr, region_size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    REQUIRE(shadow != MAP_FAILED);
    transport_state transport;
    pgas_x86_runtime_config runtime_config{};
    runtime_config.pgas_base = reinterpret_cast<uint64_t>(shadow);
    runtime_config.pgas_size = region_size;
    runtime_config.local_node_id = 0;
    runtime_config.num_nodes = 2;
    runtime_config.transport = { transport_read, transport_write,
                                 &transport };
    auto *runtime = pgas_x86_runtime_create(runtime_config);
    REQUIRE(runtime != nullptr);
    temporary_file selected(191, node_size + 1);
    pgas_model_mapper mapper;
    const uint64_t arena = reinterpret_cast<uint64_t>(shadow + node_size);
    REQUIRE(mapper.configure({ selected.path, arena, node_size + 1,
                               page_size, 64 * 1024, runtime }) == 0);
    int error{};
    REQUIRE(mapper.map_fd(selected.fd, node_size + 1, 0, error) ==
            reinterpret_cast<void *>(arena));
    const auto inventory = mapper.inventory();
    CHECK(inventory.node0_model_bytes == 0);
    CHECK(inventory.node1_model_bytes == node_size + 1);
    CHECK(inventory.mapped_bytes == node_size + 1);
    pgas_x86_runtime_destroy(runtime);
    munmap(shadow, region_size);
}
