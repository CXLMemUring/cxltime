cmake_minimum_required(VERSION 3.15)

# PGAS Attach Implementation using Frida
set(PGAS_ATTACH_SOURCES
    src/pgas_attach_impl.cpp
)

set(PGAS_ATTACH_HEADERS
    include/pgas_attach_impl.hpp
    include/pgas_attach_private_data.hpp
)

# Create library
add_library(bpftime_pgas_attach_impl STATIC
    ${PGAS_ATTACH_SOURCES}
    ${PGAS_ATTACH_HEADERS}
)

# Include directories
target_include_directories(bpftime_pgas_attach_impl PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../base_attach_impl
    ${CMAKE_CURRENT_SOURCE_DIR}/../frida_uprobe_attach_impl/include
    ${SPDLOG_INCLUDE}
    ${FRIDA_GUM_INSTALL_DIR}
)

# Link dependencies
target_link_libraries(bpftime_pgas_attach_impl
    ${FRIDA_GUM_INSTALL_DIR}/libfrida-gum.a
    spdlog
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
endif()

message(STATUS "PGAS attach implementation configured")
