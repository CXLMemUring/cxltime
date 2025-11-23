cmake_minimum_required(VERSION 3.15)

# PGAS Memory Hook Demo
add_executable(pgas_memory_hook_demo
    pgas_demo.cpp
)

target_include_directories(pgas_memory_hook_demo PRIVATE
    ${CMAKE_SOURCE_DIR}/attach/pgas_attach_impl/include
    ${CMAKE_SOURCE_DIR}/attach/base_attach_impl
    ${CMAKE_SOURCE_DIR}/attach/frida_uprobe_attach_impl/include
    ${SPDLOG_INCLUDE}
    ${FRIDA_GUM_INSTALL_DIR}
)

target_link_libraries(pgas_memory_hook_demo
    bpftime_pgas_attach_impl
    spdlog
    pthread
    dl
)

message(STATUS "PGAS memory hook demo configured")
