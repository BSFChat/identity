include(FetchContent)

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.14.0
    GIT_SHALLOW    TRUE
)
set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(identity_tests
    test_identity_store.cpp
    test_oidc.cpp
    test_accounts.cpp
)

target_include_directories(identity_tests PRIVATE ${CMAKE_SOURCE_DIR}/src)

target_link_libraries(identity_tests PRIVATE
    bsfchat_protocol
    spdlog::spdlog
    tomlplusplus::tomlplusplus
    SQLite::SQLite3
    OpenSSL::SSL
    OpenSSL::Crypto
    GTest::gtest_main
)

# Compile required source files for testing
target_sources(identity_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/src/core/Logger.cpp
    ${CMAKE_SOURCE_DIR}/src/core/Config.cpp
    ${CMAKE_SOURCE_DIR}/src/crypto/KeyManager.cpp
    ${CMAKE_SOURCE_DIR}/src/crypto/PasswordHash.cpp
    ${CMAKE_SOURCE_DIR}/src/store/IdentityStore.cpp
)

include(GoogleTest)
gtest_discover_tests(identity_tests)
