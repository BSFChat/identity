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
    test_auth_flows.cpp
    test_token_audience.cpp
    test_security_fixes.cpp
    test_version.cpp
)

target_include_directories(identity_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Same definitions the service target gets, so test_version.cpp checks the
# string the shipped binary would actually report rather than the
# #ifndef fallback inside the header.
target_compile_definitions(identity_tests PRIVATE
    BSFCHAT_ID_VERSION="${BSFCHAT_ID_VERSION}"
    BSFCHAT_ID_REVISION="${BSFCHAT_ID_REVISION}")

target_link_libraries(identity_tests PRIVATE
    bsfchat_protocol
    httplib::httplib
    spdlog::spdlog
    tomlplusplus::tomlplusplus
    SQLite::SQLite3
    OpenSSL::SSL
    OpenSSL::Crypto
    GTest::gtest_main
)

# Compile required source files for testing
target_sources(identity_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/src/core/ClientAddress.cpp
    ${CMAKE_SOURCE_DIR}/src/core/ClientRegistration.cpp
    ${CMAKE_SOURCE_DIR}/src/core/Logger.cpp
    ${CMAKE_SOURCE_DIR}/src/core/Config.cpp
    ${CMAKE_SOURCE_DIR}/src/core/RateLimiter.cpp
    ${CMAKE_SOURCE_DIR}/src/core/Username.cpp
    ${CMAKE_SOURCE_DIR}/src/core/WebUtil.cpp
    ${CMAKE_SOURCE_DIR}/src/crypto/KeyManager.cpp
    ${CMAKE_SOURCE_DIR}/src/crypto/PasswordHash.cpp
    ${CMAKE_SOURCE_DIR}/src/crypto/Secrets.cpp
    ${CMAKE_SOURCE_DIR}/src/crypto/Totp.cpp
    ${CMAKE_SOURCE_DIR}/src/store/IdentityStore.cpp
    ${CMAKE_SOURCE_DIR}/src/api/AccountHandler.cpp
    ${CMAKE_SOURCE_DIR}/src/api/AdminHandler.cpp
    ${CMAKE_SOURCE_DIR}/src/api/OidcHandler.cpp
)

include(GoogleTest)
gtest_discover_tests(identity_tests)

# --- release-channel script --------------------------------------------------
#
# scripts/channel_tags.py decides which of :latest / :latest-beta a pushed
# git tag takes. It runs in CI, but it is registered here too so that
# breaking the semver rule fails the same `ctest` run everyone already
# does before pushing, instead of only being caught by a release.
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
    add_test(NAME channel_tags
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_SOURCE_DIR}/scripts/test_channel_tags.py)
else()
    message(STATUS "python3 not found - skipping the channel_tags test "
                   "(CI always has it; this only affects local ctest runs)")
endif()

# --- security audit proof tests ----------------------------------------------
#
# docs/security-audit-2026-09.md. Each test asserts the behaviour the service
# should have and FAILS on the audited revision; the failure is the proof.
# Not registered wholesale (no gtest_discover_tests), so the regular suite
# and CI stay green while findings are open; the proofs for fixed findings are
# registered individually at the end of this file. Run all of them by hand:
#   ./build/tests/identity_security_audit_tests
add_executable(identity_security_audit_tests
    test_security_audit.cpp
    ${CMAKE_SOURCE_DIR}/src/core/ClientAddress.cpp
    ${CMAKE_SOURCE_DIR}/src/core/ClientRegistration.cpp
    ${CMAKE_SOURCE_DIR}/src/core/Logger.cpp
    ${CMAKE_SOURCE_DIR}/src/core/Config.cpp
    ${CMAKE_SOURCE_DIR}/src/core/RateLimiter.cpp
    ${CMAKE_SOURCE_DIR}/src/core/Username.cpp
    ${CMAKE_SOURCE_DIR}/src/core/WebUtil.cpp
    ${CMAKE_SOURCE_DIR}/src/crypto/KeyManager.cpp
    ${CMAKE_SOURCE_DIR}/src/crypto/PasswordHash.cpp
    ${CMAKE_SOURCE_DIR}/src/crypto/Secrets.cpp
    ${CMAKE_SOURCE_DIR}/src/crypto/Totp.cpp
    ${CMAKE_SOURCE_DIR}/src/store/IdentityStore.cpp
    ${CMAKE_SOURCE_DIR}/src/api/AccountHandler.cpp
    ${CMAKE_SOURCE_DIR}/src/api/OidcHandler.cpp
)
target_include_directories(identity_security_audit_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(identity_security_audit_tests PRIVATE
    bsfchat_protocol
    httplib::httplib
    spdlog::spdlog
    tomlplusplus::tomlplusplus
    SQLite::SQLite3
    OpenSSL::SSL
    OpenSSL::Crypto
    GTest::gtest_main
)

# Proofs whose findings are FIXED are registered with ctest one by one, so
# they guard against regression in CI while the proofs for findings still open
# stay out of the run. Fixed on fix/security-audit-2026-09: H1, H2, H3, H4
# (the proof is named H2b), M1, M2, M3 and the L2 email case. Fixed on
# fix/token-audience: C1, M4 and the nonce proof. That is all thirteen; any
# proof added to test_security_audit.cpp later goes here once its finding is
# fixed, never while it still fails.
foreach(proof
        C1_IdTokenAudienceIsBoundToTheChatServer
        M4_IdTokenOmitsEmailWithoutEmailScope
        Lnonce_NonceIsEchoedIntoIdToken
        H1_DisabledAccountCannotKeepMintingIdTokens
        H2_OneClientsFailuresDoNotLockOutEveryone
        H2b_PasswordChangeRevokesOtherSessionsAndRefreshTokens
        H3_LoginRejectsNonJsonContentType
        H3b_ConfusableUsernamesAreRefused
        M1_ServerUrlCannotCarryScript
        M2_TotpCodeCannotBeReplayed
        M2b_SecondFactorGuessingIsLimitedPerAccount
        M3_SessionsCanBeRevokedFromTheList
        Lenum_TakenEmailIsNotDistinguishableAsServerError)
    add_test(NAME SecurityAudit.${proof}
             COMMAND identity_security_audit_tests --gtest_filter=SecurityAudit.${proof})
endforeach()
