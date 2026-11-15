// Sign-in and sign-up usability fixes (audit 2026-11-15, section 7: I-2 to
// I-7): what the static pages are told about the deployment, password
// recovery by the operator, username normalisation at login, and the HTML
// pages a person in a browser gets instead of raw JSON.

#include <gtest/gtest.h>

#include "api/AccountHandler.h"
#include "core/Config.h"
#include "core/PasswordReset.h"
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

// ---------------------------------------------------------------------------
// --reset-password (core/PasswordReset.h)
// ---------------------------------------------------------------------------

namespace {

Account make_account(const std::string& id, const std::string& username, const std::string& password) {
    Account a;
    a.id = id;
    a.username = username;
    a.display_name = username;
    a.password_hash = hash_password(password, kMinPbkdf2Iterations);
    a.created_at = now_seconds();
    a.updated_at = a.created_at;
    return a;
}

Session browser_session_for(const std::string& id, const std::string& account_id) {
    Session s;
    s.session_id = id;
    s.account_id = account_id;
    s.created_at = now_seconds();
    s.expires_at = s.created_at + 3600;
    s.token_type = token_type::kBrowserSession;
    return s;
}

} // namespace

TEST(PasswordResetTest, SetsThePasswordAndSignsTheAccountOutEverywhere) {
    IdentityStore store(":memory:");
    store.initialize();
    ASSERT_TRUE(store.create_account(make_account("acct-r", "rita", "old password here")));
    ASSERT_TRUE(store.create_account(make_account("acct-o", "otto", "otto's password")));
    ASSERT_TRUE(store.create_session(browser_session_for("rita-laptop", "acct-r")));
    ASSERT_TRUE(store.create_session(browser_session_for("rita-phone", "acct-r")));
    ASSERT_TRUE(store.create_session(browser_session_for("otto-laptop", "acct-o")));

    auto result = reset_account_password(store, "rita", "brand new password", kMinPbkdf2Iterations);
    ASSERT_EQ(result.status, PasswordResetResult::Status::Reset) << result.message;
    EXPECT_EQ(result.account_id, "acct-r");
    EXPECT_GE(result.signed_out, 2);

    auto rita = store.get_account_by_username("rita");
    ASSERT_TRUE(rita);
    EXPECT_TRUE(verify_password("brand new password", rita->password_hash));
    EXPECT_FALSE(verify_password("old password here", rita->password_hash));

    // Every one of Rita's sessions is gone — none is kept, unlike a password
    // change from the account page — and nobody else's is touched.
    EXPECT_FALSE(store.get_browser_session("rita-laptop"));
    EXPECT_FALSE(store.get_browser_session("rita-phone"));
    EXPECT_TRUE(store.get_browser_session("otto-laptop"));
}

TEST(PasswordResetTest, AppliesThePasswordPolicyAndChangesNothingOnRefusal) {
    IdentityStore store(":memory:");
    store.initialize();
    ASSERT_TRUE(store.create_account(make_account("acct-r", "rita", "old password here")));
    ASSERT_TRUE(store.create_session(browser_session_for("rita-laptop", "acct-r")));

    auto short_one = reset_account_password(store, "rita", "short", kMinPbkdf2Iterations);
    EXPECT_EQ(short_one.status, PasswordResetResult::Status::PolicyRejected);
    auto long_one = reset_account_password(store, "rita", std::string(kMaxPasswordLength + 1, 'x'),
                                           kMinPbkdf2Iterations);
    EXPECT_EQ(long_one.status, PasswordResetResult::Status::PolicyRejected);

    auto rita = store.get_account_by_username("rita");
    ASSERT_TRUE(rita);
    EXPECT_TRUE(verify_password("old password here", rita->password_hash));
    EXPECT_TRUE(store.get_browser_session("rita-laptop"));
}

TEST(PasswordResetTest, UnknownUsernameIsReported) {
    IdentityStore store(":memory:");
    store.initialize();
    auto result = reset_account_password(store, "nobody", "a fine password", kMinPbkdf2Iterations);
    EXPECT_EQ(result.status, PasswordResetResult::Status::NoSuchAccount);
}

TEST(PasswordResetTest, PolicyIsSharedWithRegistration) {
    EXPECT_TRUE(password_policy_error("1234567"));
    EXPECT_FALSE(password_policy_error("12345678"));
    EXPECT_FALSE(password_policy_error(std::string(kMaxPasswordLength, 'x')));
    EXPECT_TRUE(password_policy_error(std::string(kMaxPasswordLength + 1, 'x')));
}
