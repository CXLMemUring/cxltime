cmake_minimum_required(VERSION 3.15)

# PGAS Attach Implementation using Frida with CXLMemSim integration
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|i[3-6]86)$")
    set(PGAS_STALKER_SOURCE src/pgas_stalker_mov.cpp)
    message(STATUS "PGAS instruction-level Stalker enabled for ${CMAKE_SYSTEM_PROCESSOR}")
else()
    set(PGAS_STALKER_SOURCE src/pgas_stalker_stub.cpp)
    message(STATUS "PGAS instruction-level Stalker disabled for ${CMAKE_SYSTEM_PROCESSOR}; using function-level preload hooks only")
endif()

set(PGAS_ATTACH_SOURCES
    src/pgas_attach_impl.cpp
    src/pgas_cxlmemsim_integration.cpp
    src/pgas_model_mapping.cpp
    src/pgas_stalker_module_policy.cpp
    src/pgas_x86_bulk.cpp
    src/pgas_x86_memory_access.cpp
    src/pgas_x86_replay.cpp
    src/pgas_x86_xstate.cpp
    ${PGAS_STALKER_SOURCE}
)

set(PGAS_ATTACH_HEADERS
    include/pgas_attach_impl.hpp
    include/pgas_attach_private_data.hpp
    include/pgas_cxlmemsim_integration.hpp
    include/pgas_model_mapping.h
    include/pgas_model_mapping.hpp
    include/pgas_stalker_mov.hpp
    include/pgas_stalker_module_policy.hpp
    include/pgas_x86_bulk.hpp
    include/pgas_x86_memory_access.hpp
    include/pgas_x86_replay.hpp
    include/pgas_x86_xstate.hpp
)

# CXLMemSim client library path (from libpgas)
set(CXLMEMSIM_CLIENT_SRC ${CMAKE_SOURCE_DIR}/src/libpgas/src/cxlmemsim_client.c)
set(CXLMEMSIM_CLIENT_INCLUDE ${CMAKE_SOURCE_DIR}/src/libpgas/include ${CMAKE_SOURCE_DIR}/src/libpgas/include/pgas)

if(NOT EXISTS "${CXLMEMSIM_CLIENT_SRC}" OR NOT EXISTS "${CMAKE_SOURCE_DIR}/src/libpgas/include")
    message(WARNING "Skipping pgas_attach_impl: libpgas client files were not found")
    return()
endif()

# Create library
add_library(bpftime_pgas_attach_impl STATIC
    ${PGAS_ATTACH_SOURCES}
    ${PGAS_ATTACH_HEADERS}
    ${CXLMEMSIM_CLIENT_SRC}
)
add_dependencies(bpftime_pgas_attach_impl FridaGum spdlog::spdlog)

# Include directories
target_include_directories(bpftime_pgas_attach_impl BEFORE PRIVATE
    ${SPDLOG_INCLUDE}
)
target_include_directories(bpftime_pgas_attach_impl PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../base_attach_impl
    ${CMAKE_CURRENT_SOURCE_DIR}/../frida_uprobe_attach_impl/include
    ${CXLMEMSIM_CLIENT_INCLUDE}
    ${FRIDA_GUM_INSTALL_DIR}
)

# Link dependencies
target_link_libraries(bpftime_pgas_attach_impl
    ${FRIDA_GUM_INSTALL_DIR}/libfrida-gum.a
    spdlog::spdlog
    pthread
    dl
    resolv
)

# Platform-specific settings
if(UNIX AND NOT APPLE)
    target_link_libraries(bpftime_pgas_attach_impl rt)
endif()

# Compiler flags
target_compile_options(bpftime_pgas_attach_impl PRIVATE
    -Wall -Wextra -Wpedantic
)

# Export include directories
set(PGAS_ATTACH_IMPL_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/include PARENT_SCOPE)

# Tests
if(BUILD_TESTING)
    add_executable(test_pgas_attach
        test/test_pgas_attach.cpp
    )

    target_link_libraries(test_pgas_attach
        bpftime_pgas_attach_impl
        Catch2::Catch2WithMain
    )

    target_include_directories(test_pgas_attach PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )

    add_test(NAME test_pgas_attach COMMAND test_pgas_attach)

    add_executable(test_pgas_x86_memory_access
        test/test_pgas_x86_memory_access.cpp
    )

    target_link_libraries(test_pgas_x86_memory_access
        bpftime_pgas_attach_impl
        Catch2::Catch2WithMain
    )

    target_include_directories(test_pgas_x86_memory_access PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )

    add_test(NAME test_pgas_x86_memory_access
        COMMAND test_pgas_x86_memory_access)

    add_executable(test_pgas_x86_xstate
        test/test_pgas_x86_xstate.cpp
    )

    target_link_libraries(test_pgas_x86_xstate
        bpftime_pgas_attach_impl
        Catch2::Catch2WithMain
    )

    target_include_directories(test_pgas_x86_xstate PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )

    if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64)$")
        target_compile_options(test_pgas_x86_xstate PRIVATE -mavx512f)
    endif()

    add_test(NAME test_pgas_x86_xstate
        COMMAND test_pgas_x86_xstate)

    add_executable(test_pgas_x86_replay
        test/test_pgas_x86_replay.cpp
    )

    target_link_libraries(test_pgas_x86_replay
        bpftime_pgas_attach_impl
        Catch2::Catch2WithMain
    )

    target_include_directories(test_pgas_x86_replay PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )

    add_test(NAME test_pgas_x86_replay
        COMMAND test_pgas_x86_replay)

    add_executable(test_pgas_x86_bulk
        test/test_pgas_x86_bulk.cpp
    )

    target_link_libraries(test_pgas_x86_bulk
        bpftime_pgas_attach_impl
        Catch2::Catch2WithMain
    )

    target_include_directories(test_pgas_x86_bulk PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )

    add_test(NAME test_pgas_x86_bulk
        COMMAND test_pgas_x86_bulk)

    add_executable(test_pgas_model_mapping
        test/test_pgas_model_mapping.cpp
    )

    target_link_libraries(test_pgas_model_mapping
        bpftime_pgas_attach_impl
        Catch2::Catch2WithMain
    )

    target_include_directories(test_pgas_model_mapping PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )

    add_test(NAME test_pgas_model_mapping
        COMMAND test_pgas_model_mapping)

    add_executable(test_pgas_stalker_module_policy
        test/test_pgas_stalker_module_policy.cpp
    )

    target_link_libraries(test_pgas_stalker_module_policy
        bpftime_pgas_attach_impl
        Catch2::Catch2WithMain
    )

    target_include_directories(test_pgas_stalker_module_policy PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )

    add_test(NAME test_pgas_stalker_module_policy
        COMMAND test_pgas_stalker_module_policy)

    if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64)$")
        add_executable(test_pgas_x86_range_jit
            test/test_pgas_x86_range_jit.cpp
        )

        target_link_libraries(test_pgas_x86_range_jit
            bpftime_pgas_attach_impl
            Catch2::Catch2WithMain
        )

        target_include_directories(test_pgas_x86_range_jit PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )

        add_test(NAME test_pgas_x86_range_jit
            COMMAND test_pgas_x86_range_jit)
    endif()

    # CXLMemSim hook test (standalone, requires CXLMemSim server)
    add_executable(test_cxlmemsim_hook
        test/test_cxlmemsim_hook.cpp
        ${CMAKE_SOURCE_DIR}/src/libpgas/src/cxlmemsim_client.c
    )

    target_link_libraries(test_cxlmemsim_hook
        bpftime_pgas_attach_impl
    )

    target_include_directories(test_cxlmemsim_hook PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CXLMEMSIM_CLIENT_INCLUDE}
    )
endif()

message(STATUS "PGAS attach implementation configured")
