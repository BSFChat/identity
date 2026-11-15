// Sign-in and sign-up usability fixes (audit 2026-11-15, section 7: I-2 to
// I-7): what the static pages are told about the deployment, password
// recovery by the operator, username normalisation at login, and the HTML
// pages a person in a browser gets instead of raw JSON.

#include <gtest/gtest.h>

#include "api/AccountHandler.h"
#include "core/Config.h"
#include "crypto/PasswordHash.h"
#include "store/IdentityStore.h"
#include "TempPaths.h"

#include <nlohmann/json.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>

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

} // namespace

// ---------------------------------------------------------------------------
// GET /api/instance and [server] support_contact
// ---------------------------------------------------------------------------

TEST(InstanceInfoTest, ReportsRegistrationFlagAndSupportContact) {
    Config config;
    config.registration_enabled = false;
    config.support_contact = "help@example.com";
    IdentityStore store(":memory:");
    store.initialize();
    AccountHandler accounts(store, config);

    httplib::Request req;
    req.method = "GET";
    httplib::Response res;
    accounts.handle_instance_info(req, res);
    EXPECT_EQ(status_of(res), 200);
    auto body = json::parse(res.body);
    EXPECT_EQ(body["registration_enabled"], false);
    EXPECT_EQ(body["support_contact"], "help@example.com");
}

TEST(InstanceInfoTest, SupportContactIsReadTrimmedAndBounded) {
    auto path = bsfchat::test::unique_temp_file("bsfchat_id_support_cfg", ".toml");
    {
        std::ofstream f(path);
        f << "[server]\nsupport_contact = \"  https://help.example.com/id  \"\n";
    }
    EXPECT_EQ(Config::load(path.string()).support_contact, "https://help.example.com/id");
    {
        // A control character (here a newline) is dropped, not shown.
        std::ofstream f(path);
        f << "[server]\nsupport_contact = \"a\\nb\"\n";
    }
    EXPECT_TRUE(Config::load(path.string()).support_contact.empty());
    {
        std::ofstream f(path);
        f << "[server]\nname = \"x\"\n";
    }
    EXPECT_TRUE(Config::load(path.string()).support_contact.empty());
    std::filesystem::remove(path);
}
