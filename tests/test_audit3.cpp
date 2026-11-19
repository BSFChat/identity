// Audit 3 (2026-11-19), "Identity: browser walkthrough": the service-side
// half of each finding. The pages' half is checked by hand; see the commit
// messages.

#include <gtest/gtest.h>

#include "api/AccountHandler.h"
#include "api/AdminHandler.h"
#include "api/OidcHandler.h"
#include "core/ClientRegistration.h"
#include "core/Config.h"
#include "core/WebUtil.h"
#include "crypto/KeyManager.h"
#include "crypto/PasswordHash.h"
#include "http/HttpServer.h"
#include "store/IdentityStore.h"
#include "TempPaths.h"

#include <nlohmann/json.hpp>

#include <chrono>
#include <filesystem>

using namespace bsfchat::id;
using json = nlohmann::json;

namespace {

int64_t now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

int status_of(const httplib::Response& res) {
    return res.status < 0 ? 200 : res.status;
}

std::string header_of(const httplib::Response& res, const std::string& name) {
    auto it = res.headers.find(name);
    return it == res.headers.end() ? std::string{} : it->second;
}

} // namespace

// ---------------------------------------------------------------------------
// M1: a port that is in use is a startup error, not a shared port
// ---------------------------------------------------------------------------

TEST(Audit3Startup, SecondInstanceOnTheSamePortFailsToStart) {
    Config first_config;
    first_config.bind_address = "127.0.0.1";
    HttpServer first(first_config);
    const int port = first.server().bind_to_any_port("127.0.0.1");
    ASSERT_GT(port, 0);

    Config second_config;
    second_config.bind_address = "127.0.0.1";
    second_config.port = port;
    HttpServer second(second_config);
    // With httplib's default SO_REUSEPORT this bound happily and the two
    // processes split the connections.
    EXPECT_THROW(second.start(), std::runtime_error);
}
