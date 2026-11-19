// Audit 3 (2026-11-19), "Identity: browser walkthrough": the service-side
// half of each finding. The pages' half is checked by hand; see the commit
// messages.

#include <gtest/gtest.h>

#include "api/AccountHandler.h"
#include "api/AdminHandler.h"
#include "api/OidcHandler.h"
#include "core/ClientRegistration.h"
#include "core/Config.h"
#include "core/OperatorCommands.h"
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

httplib::Request json_request(const json& body, const std::string& addr = "10.0.0.1") {
    httplib::Request req;
    req.method = "POST";
    req.set_header("Content-Type", "application/json");
    req.body = body.dump();
    req.remote_addr = addr;
    return req;
}

Account make_account(const std::string& id, const std::string& username,
                     const std::string& password = "correct horse battery") {
    Account a;
    a.id = id;
    a.username = username;
    a.display_name = username;
    a.password_hash = hash_password(password, kMinPbkdf2Iterations);
    a.created_at = now_seconds();
    a.updated_at = a.created_at;
    return a;
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

// ---------------------------------------------------------------------------
// M3: granting admin, and the first account on a fresh database
// ---------------------------------------------------------------------------

TEST(Audit3Admin, FirstRegisteredAccountBecomesAdminOnlyOnAFreshDatabase) {
    Config config;
    config.password_hash_iterations = kMinPbkdf2Iterations;
    config.login_rate_limit = 1000;
    IdentityStore store(":memory:");
    store.initialize();
    AccountHandler accounts(store, config);

    httplib::Response first;
    accounts.handle_register(json_request({{"username", "founder"}, {"password", "founder password"}}),
                             first);
    ASSERT_EQ(status_of(first), 201) << first.body;
    EXPECT_TRUE(store.get_account_by_username("founder")->is_admin);

    httplib::Response second;
    accounts.handle_register(json_request({{"username", "newcomer"}, {"password", "newcomer password"}}),
                             second);
    ASSERT_EQ(status_of(second), 201) << second.body;
    EXPECT_FALSE(store.get_account_by_username("newcomer")->is_admin);
}

TEST(Audit3Admin, ExistingDeploymentWithoutAdminDoesNotPromoteTheNextSignUp) {
    IdentityStore store(":memory:");
    store.initialize();
    ASSERT_TRUE(store.create_account(make_account("acct-old", "oldtimer")));
    ASSERT_TRUE(store.create_account(make_account("acct-new", "newbie")));
    EXPECT_FALSE(store.promote_if_first_account("acct-new"));
    EXPECT_FALSE(store.get_account_by_id("acct-new")->is_admin);
}

TEST(Audit3Admin, GrantAndRevokeByUsernameKeepAtLeastOneAdmin) {
    IdentityStore store(":memory:");
    store.initialize();
    ASSERT_TRUE(store.create_account(make_account("acct-a", "anna")));
    ASSERT_TRUE(store.create_account(make_account("acct-b", "bert")));

    EXPECT_FALSE(set_admin_by_username(store, "nobody", true).ok);
    auto granted = set_admin_by_username(store, "anna", true);
    EXPECT_TRUE(granted.ok) << granted.message;
    EXPECT_TRUE(store.get_account_by_id("acct-a")->is_admin);
    EXPECT_TRUE(set_admin_by_username(store, "anna", true).ok);  // already

    // The only administrator cannot be revoked...
    auto refused = set_admin_by_username(store, "anna", false);
    EXPECT_FALSE(refused.ok);
    EXPECT_NE(refused.message.find("only administrator"), std::string::npos);
    EXPECT_TRUE(store.get_account_by_id("acct-a")->is_admin);

    // ...until there is another.
    ASSERT_TRUE(set_admin_by_username(store, "bert", true).ok);
    EXPECT_TRUE(set_admin_by_username(store, "anna", false).ok);
    EXPECT_FALSE(store.get_account_by_id("acct-a")->is_admin);
}

TEST(Audit3Admin, DeletedAccountCannotBeGrantedAdmin) {
    IdentityStore store(":memory:");
    store.initialize();
    ASSERT_TRUE(store.create_account(make_account("acct-d", "dora")));
    ASSERT_EQ(store.delete_account("acct-d"), IdentityStore::DeleteAccountResult::Deleted);
    EXPECT_EQ(store.set_admin("acct-d", true), IdentityStore::SetAdminResult::Deleted);
}

TEST(Audit3Admin, OperatorCanRemoveTwoFactorForRecovery) {
    IdentityStore store(":memory:");
    store.initialize();
    ASSERT_TRUE(store.create_account(make_account("acct-t", "tina")));
    store.set_totp_secret("acct-t", "JBSWY3DPEHPK3PXP", {"AAAAAAAAAA"});
    store.enable_totp("acct-t");
    Session s;
    s.session_id = "tina-browser";
    s.account_id = "acct-t";
    s.created_at = now_seconds();
    s.expires_at = s.created_at + 3600;
    ASSERT_TRUE(store.create_session(s));

    auto result = disable_2fa_by_username(store, "tina");
    EXPECT_TRUE(result.ok) << result.message;
    EXPECT_FALSE(store.get_totp("acct-t").has_value());
    EXPECT_FALSE(store.get_browser_session("tina-browser").has_value());
    EXPECT_FALSE(disable_2fa_by_username(store, "nobody").ok);
}
