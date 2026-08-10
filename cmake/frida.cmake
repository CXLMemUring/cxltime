# add frida as external project
set(FRIDA_DOWNLOAD_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/third_party/frida)

set(FRIDA_DOWNLOAD_URL_PREFIX "" CACHE STRING "The prefix added to the frida download url. For example, https://ghproxy.com/")

message(STATUS "System Name: ${CMAKE_SYSTEM_NAME}")
message(STATUS "System Version: ${CMAKE_SYSTEM_VERSION}")
message(STATUS "System Processor: ${CMAKE_SYSTEM_PROCESSOR}")

set(FRIDA_OS_ARCH_RAW "${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")
string(TOLOWER ${FRIDA_OS_ARCH_RAW} FRIDA_OS_ARCH)
set(FRIDA_VERSION "17.17.0")

message(STATUS "Using frida: arch=${FRIDA_OS_ARCH}, version=${FRIDA_VERSION}")

if(${FRIDA_OS_ARCH} STREQUAL "linux-x86_64")
  set(FRIDA_CORE_DEVKIT_SHA256 "483e1a25945cebaa69e61c09d7804692c42d234cab0c58261a73382163027a2e")
  set(FRIDA_GUM_DEVKIT_SHA256 "0987dd51e9901a6dddd9d55bc9ef02cd90d95012a4947e29dab942ec7f5348b7")
elseif(${FRIDA_OS_ARCH} STREQUAL "linux-aarch64")
  set(FRIDA_CORE_DEVKIT_SHA256 "93ace484ed610961ba153b176c6363a5ac598a1db3b245ef785175a8229568b0")
  set(FRIDA_GUM_DEVKIT_SHA256 "a035cb1f9f58f03822fa87d6dd578bbadb7c3452bc1b8c08ee31c1f14e29025f")
  # Cmake uses aarch64, but frida uses arm64
  set(FRIDA_OS_ARCH "linux-arm64")
elseif(${FRIDA_OS_ARCH} MATCHES "linux-arm.*")
  set(FRIDA_CORE_DEVKIT_SHA256 "6e32568777c941e7fc5353ae0ffa6f162514e3aa65222ed801c55df63040f650")
  set(FRIDA_GUM_DEVKIT_SHA256 "45d8122f326371589da0c2481dc82ac75586debe9ca1f6527a00d1a00646dece")
  # Frida only has armhf builds..
  set(FRIDA_OS_ARCH "linux-armhf")
elseif(${FRIDA_OS_ARCH} MATCHES "darwin-arm64")
  set(FRIDA_CORE_DEVKIT_SHA256 "4011638a61a9003367b475168c6e43b2f5f72d10ee2a925c445f4daea1a5050a")
  set(FRIDA_GUM_DEVKIT_SHA256 "543a8704f3566606c3bfe1e5cf0ad42696ffbf8ff8fa1d8649ce8ea153a617fd")
  # for macos-arm m* chip series 
  set(FRIDA_OS_ARCH "macos-arm64")
else()
  message(FATAL_ERROR "Unsupported frida arch ${FRIDA_OS_ARCH}")
endif()

set(FRIDA_CORE_FILE_NAME "frida-core-devkit-${FRIDA_VERSION}-${FRIDA_OS_ARCH}.tar.xz")
set(FRIDA_GUM_FILE_NAME "frida-gum-devkit-${FRIDA_VERSION}-${FRIDA_OS_ARCH}.tar.xz")
set(FRIDA_CORE_DEVKIT_URL "${FRIDA_DOWNLOAD_URL_PREFIX}https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/${FRIDA_CORE_FILE_NAME}")
set(FRIDA_GUM_DEVKIT_URL "${FRIDA_DOWNLOAD_URL_PREFIX}https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/${FRIDA_GUM_FILE_NAME}")

set(FRIDA_CORE_DEVKIT_PATH ${FRIDA_DOWNLOAD_LOCATION}/${FRIDA_CORE_FILE_NAME})
set(FRIDA_GUM_DEVKIT_PATH ${FRIDA_DOWNLOAD_LOCATION}/${FRIDA_GUM_FILE_NAME})

set(FRIDA_CORE_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/FridaCore-prefix/src/FridaCore)
set(FRIDA_GUM_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/FridaGum-prefix/src/FridaGum)

# if file exists, skip download
if(NOT EXISTS ${FRIDA_CORE_DEVKIT_PATH})
  message(STATUS "Downloading Frida Core Devkit")
  set(FRIDA_CORE_DOWNLOAD_URL ${FRIDA_CORE_DEVKIT_URL})
else()
  message(STATUS "Frida Core Devkit already downloaded")
  set(FRIDA_CORE_DOWNLOAD_URL ${FRIDA_CORE_DEVKIT_PATH})
endif()

# if file exists, skip download
if(NOT EXISTS ${FRIDA_GUM_DEVKIT_PATH})
  message(STATUS "Downloading Frida GUM Devkit")
  set(FRIDA_GUM_DOWNLOAD_URL ${FRIDA_GUM_DEVKIT_URL})
else()
  message(STATUS "Frida GUM Devkit already downloaded")
  set(FRIDA_GUM_DOWNLOAD_URL ${FRIDA_GUM_DEVKIT_PATH})
endif()

message(STATUS "Downloading FridaCore from ${FRIDA_CORE_DOWNLOAD_URL}")
include(ExternalProject)
ExternalProject_Add(FridaCore
  URL ${FRIDA_CORE_DOWNLOAD_URL}
  DOWNLOAD_DIR ${FRIDA_DOWNLOAD_LOCATION}
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND ""
  BUILD_BYPRODUCTS ${FRIDA_CORE_INSTALL_DIR}/libfrida-core.a
  URL_HASH SHA256=${FRIDA_CORE_DEVKIT_SHA256}
)

message(STATUS "Downloading FridaGum from ${FRIDA_GUM_DOWNLOAD_URL}")
ExternalProject_Add(FridaGum
  URL ${FRIDA_GUM_DOWNLOAD_URL}
  DOWNLOAD_DIR ${FRIDA_DOWNLOAD_LOCATION}
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
  INSTALL_COMMAND ""
  BUILD_BYPRODUCTS ${FRIDA_GUM_INSTALL_DIR}/libfrida-gum.a
  URL_HASH SHA256=${FRIDA_GUM_DEVKIT_SHA256}
)
