#pragma once

// Unique filesystem paths for tests.
//
// `gtest_discover_tests` registers every TEST/TEST_F as its own ctest test,
// so `ctest -j4` runs several *processes* over the same binary at the same
// time. A fixture that hard-codes e.g. /tmp/bsfchat_id_test_keys then has
// one process deleting the key directory another one is mid-way through
// reading — which is exactly why OidcTest.KeyManagerLoadsExistingKeys,
// AuthFlowTest.*, TokenSeparationTest.* and TwoFactorTest.* failed under
// -j4 and passed serially.
//
// Every path handed out here carries the pid and a per-process counter, so
// it is unique across concurrent processes and across tests within one.

#include <atomic>
#include <filesystem>
#include <string>

#if defined(_WIN32)
#include <process.h>
#define BSFCHAT_TEST_GETPID _getpid
#else
#include <unistd.h>
#define BSFCHAT_TEST_GETPID getpid
#endif

namespace bsfchat::test {

inline std::string unique_suffix() {
    static std::atomic<unsigned> counter{0};
    return std::to_string(static_cast<long>(BSFCHAT_TEST_GETPID())) + "-"
         + std::to_string(counter.fetch_add(1, std::memory_order_relaxed));
}

// A directory path unique to this process+call. Not created — callers hand
// it to KeyManager and friends, which create it themselves.
inline std::filesystem::path unique_temp_dir(const std::string& prefix) {
    auto p = std::filesystem::temp_directory_path()
           / (prefix + "-" + unique_suffix());
    std::error_code ec;
    std::filesystem::remove_all(p, ec);
    return p;
}

// A file path (e.g. a SQLite database) unique to this process+call.
inline std::filesystem::path unique_temp_file(const std::string& prefix,
                                              const std::string& extension) {
    return std::filesystem::temp_directory_path()
         / (prefix + "-" + unique_suffix() + extension);
}

} // namespace bsfchat::test
