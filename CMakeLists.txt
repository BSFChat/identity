cmake_minimum_required(VERSION 3.20)
project(bsfchat-id VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(GAMECHAT_ID_BUILD_TESTS "Build identity service tests" ON)

include(cmake/Dependencies.cmake)

add_executable(bsfchat-id
    src/main.cpp
    src/core/Config.cpp
    src/core/Logger.cpp
    src/core/IdentityServer.cpp
    src/http/HttpServer.cpp
    src/crypto/KeyManager.cpp
    src/crypto/PasswordHash.cpp
    src/crypto/Totp.cpp
    src/store/IdentityStore.cpp
    src/api/AccountHandler.cpp
    src/api/OidcHandler.cpp
    src/api/SsoHandler.cpp
    src/api/AdminHandler.cpp
)

target_include_directories(bsfchat-id PRIVATE src)

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
