cmake_minimum_required(VERSION 3.20)

# Version.cmake before project(): project(VERSION ...) needs the strict
# MAJOR.MINOR.PATCH form, and CI passes -DBSFCHAT_ID_VERSION on tag builds
# so the number in the image matches the tag that produced it.
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/Version.cmake)

project(bsfchat-id VERSION ${BSFCHAT_ID_VERSION_DOTS} LANGUAGES CXX)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/Ccache.cmake)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(GAMECHAT_ID_BUILD_TESTS "Build identity service tests" ON)

include(cmake/Dependencies.cmake)

add_executable(bsfchat-id
    src/main.cpp
    src/core/ClientAddress.cpp
    src/core/Config.cpp
    src/core/Logger.cpp
    src/core/IdentityServer.cpp
    src/core/RateLimiter.cpp
    src/core/Username.cpp
    src/core/WebUtil.cpp
    src/http/HttpServer.cpp
    src/crypto/KeyManager.cpp
    src/crypto/PasswordHash.cpp
    src/crypto/Secrets.cpp
    src/crypto/Totp.cpp
    src/store/IdentityStore.cpp
    src/api/AccountHandler.cpp
    src/api/OidcHandler.cpp
    src/api/AdminHandler.cpp
)

target_include_directories(bsfchat-id PRIVATE src)

# src/core/Version.h reads these. Defined on the target rather than
# globally so a stale definition cannot leak in from a parent scope.
target_compile_definitions(bsfchat-id PRIVATE
    BSFCHAT_ID_VERSION="${BSFCHAT_ID_VERSION}"
    BSFCHAT_ID_REVISION="${BSFCHAT_ID_REVISION}")

target_link_libraries(bsfchat-id PRIVATE
    bsfchat_protocol
    httplib::httplib
    spdlog::spdlog
    tomlplusplus::tomlplusplus
    SQLite::SQLite3
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Copy example config to build dir
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/config/bsfchat-id.example.toml
    ${CMAKE_CURRENT_BINARY_DIR}/bsfchat-id.example.toml
    COPYONLY
)

# Copy web assets to build dir
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/web DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

if(GAMECHAT_ID_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
