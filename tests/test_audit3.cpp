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
#include "core/Username.h"
#include "core/RateLimiter.h"
#include "core/WebUtil.h"
#include "crypto/KeyManager.h"
#include "crypto/PasswordHash.h"
#include "crypto/Totp.h"
#include "http/HttpServer.h"
#include "store/IdentityStore.h"
#include "TempPaths.h"

#include <nlohmann/json.hpp>
#include <sqlite3.h>

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

// ---------------------------------------------------------------------------
// Sign-in limits: failures only, and they say how long
// ---------------------------------------------------------------------------

TEST(Audit3Limits, RateLimiterRetryAfterIsTheTimeLeft) {
    RateLimiter limiter(2, std::chrono::seconds(300));
    EXPECT_TRUE(limiter.would_allow("k"));
    EXPECT_EQ(limiter.retry_after("k"), 0);
    limiter.record("k");
    limiter.record("k");
    EXPECT_FALSE(limiter.would_allow("k"));
    const auto left = limiter.retry_after("k");
    EXPECT_GT(left, 290);
    EXPECT_LE(left, 300);
}

namespace {

struct LimitsFixture {
    Config config;
    std::unique_ptr<IdentityStore> store;
    std::unique_ptr<AccountHandler> accounts;

    explicit LimitsFixture(int rate_limit) {
        config.password_hash_iterations = kMinPbkdf2Iterations;
        config.login_rate_limit = rate_limit;
        config.login_max_failures = 100;
        store = std::make_unique<IdentityStore>(":memory:");
        store->initialize();
        store->create_account(make_account("acct-1", "alice"));
        accounts = std::make_unique<AccountHandler>(*store, config);
    }

    httplib::Response login(const std::string& password) {
        httplib::Response res;
        accounts->handle_login(json_request({{"username", "alice"}, {"password", password}},
                                            "192.0.2.10"),
                               res);
        return res;
    }
};

} // namespace

TEST(Audit3Limits, SuccessfulSignInsDoNotSpendTheAddressBudget) {
    LimitsFixture f(3);
    // A busy office behind one address: many successful sign-ins.
    for (int i = 0; i < 10; ++i) {
        EXPECT_EQ(status_of(f.login("correct horse battery")), 200) << i;
    }
    // Failures still do.
    for (int i = 0; i < 3; ++i) EXPECT_EQ(status_of(f.login("wrong")), 401);
    auto res = f.login("correct horse battery");
    EXPECT_EQ(status_of(res), 429);
    const auto retry = std::stoll(header_of(res, "Retry-After"));
    EXPECT_GT(retry, 0);
    EXPECT_LE(retry, f.config.login_rate_window);
    EXPECT_NE(json::parse(res.body)["error"].get<std::string>().find("Try again in"),
              std::string::npos);
}

TEST(Audit3Limits, LockoutMessageNamesTheDuration) {
    LimitsFixture f(1000);
    f.config.login_max_failures = 2;
    f.accounts = std::make_unique<AccountHandler>(*f.store, f.config);
    f.login("wrong");
    f.login("wrong");
    auto res = f.login("correct horse battery");
    ASSERT_EQ(status_of(res), 429);
    EXPECT_EQ(header_of(res, "Retry-After"), std::to_string(json::parse(res.body)["retry_after"].get<int64_t>()));
    EXPECT_NE(json::parse(res.body)["error"].get<std::string>().find("15 minutes"), std::string::npos)
        << res.body;
}

// ---------------------------------------------------------------------------
// Two-factor: backup codes, disabling, replayed codes, burned login tokens
// ---------------------------------------------------------------------------

TEST(Audit3BackupCodes, NewCodesAvoidLookalikesAndIgnoreCase) {
    for (const auto& code : bsfchat::generate_backup_codes(50)) {
        ASSERT_EQ(code.size(), 11u) << code;
        EXPECT_EQ(code[5], '-');
        EXPECT_EQ(code.find_first_of("O0IL1ilo"), std::string::npos) << code;
    }
    EXPECT_EQ(bsfchat::normalize_backup_code(" abcde-fghjk "), "ABCDEFGHJK");

    IdentityStore store(":memory:");
    store.initialize();
    ASSERT_TRUE(store.create_account(make_account("acct-1", "alice")));
    store.set_totp_secret("acct-1", "JBSWY3DPEHPK3PXP", {"ABCDE-FGHJK", "MNPQR-STUVW"});
    EXPECT_TRUE(store.consume_backup_code("acct-1", "abcde fghjk"));
    EXPECT_FALSE(store.consume_backup_code("acct-1", "ABCDEFGHJK"));  // spent
    EXPECT_TRUE(store.consume_backup_code("acct-1", "mnpqrstuvw"));
}

TEST(Audit3BackupCodes, CodesIssuedBeforeTheChangeAreStillComparedExactly) {
    auto path = bsfchat::test::unique_temp_file("bsfchat_id_old_codes", ".db");
    {
        IdentityStore store(path.string());
        store.initialize();
        ASSERT_TRUE(store.create_account(make_account("acct-1", "alice")));
        store.set_totp_secret("acct-1", "JBSWY3DPEHPK3PXP", {});
    }
    {
        // What an older build stored: a hash of the exact, mixed-case code.
        sqlite3* raw = nullptr;
        ASSERT_EQ(sqlite3_open(path.string().c_str(), &raw), SQLITE_OK);
        const auto codes = json::array({hash_password("aB3dE5gH", kMinPbkdf2Iterations)}).dump();
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(raw, "UPDATE user_totp SET backup_codes = ?", -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, codes.c_str(), -1, SQLITE_TRANSIENT);
        ASSERT_EQ(sqlite3_step(stmt), SQLITE_DONE);
        sqlite3_finalize(stmt);
        sqlite3_close(raw);
    }
    IdentityStore store(path.string());
    store.initialize();
    EXPECT_FALSE(store.consume_backup_code("acct-1", "AB3DE5GH"));
    EXPECT_TRUE(store.consume_backup_code("acct-1", "aB3dE5gH"));
    std::filesystem::remove(path);
}

namespace {

class Audit3TwoFactor : public ::testing::Test {
protected:
    void SetUp() override {
        config.password_hash_iterations = kMinPbkdf2Iterations;
        config.login_rate_limit = 1000;
        config.totp_max_attempts = 2;
        store = std::make_unique<IdentityStore>(":memory:");
        store->initialize();
        ASSERT_TRUE(store->create_account(make_account("acct-1", "alice", kPassword)));
        store->set_totp_secret("acct-1", kSecret, {"ABCDE-FGHJK", "MNPQR-STUVW", "XYZ23-45678"});
        store->enable_totp("acct-1");
        Session s;
        s.session_id = "alice-browser";
        s.account_id = "acct-1";
        s.created_at = now_seconds();
        s.expires_at = s.created_at + 3600;
        ASSERT_TRUE(store->create_session(s));
        accounts = std::make_unique<AccountHandler>(*store, config);
    }

    httplib::Request with_session(const json& body) {
        auto req = json_request(body);
        req.set_header("Cookie", "session=alice-browser");
        return req;
    }

    std::string current_code() {
        return bsfchat::compute_totp(kSecret, static_cast<uint64_t>(now_seconds()) / 30);
    }

    static constexpr const char* kPassword = "correct horse battery";
    static constexpr const char* kSecret = "JBSWY3DPEHPK3PXP";
    Config config;
    std::unique_ptr<IdentityStore> store;
    std::unique_ptr<AccountHandler> accounts;
};

} // namespace

TEST_F(Audit3TwoFactor, StatusReportsRemainingBackupCodes) {
    httplib::Request req;
    req.set_header("Cookie", "session=alice-browser");
    httplib::Response res;
    accounts->handle_2fa_status(req, res);
    EXPECT_EQ(json::parse(res.body)["backup_codes_remaining"], 3);
    ASSERT_TRUE(store->consume_backup_code("acct-1", "ABCDE-FGHJK"));
    httplib::Response again;
    accounts->handle_2fa_status(req, again);
    EXPECT_EQ(json::parse(again.body)["backup_codes_remaining"], 2);
}

TEST_F(Audit3TwoFactor, DisablingNeedsTheCodeAsWellAsThePassword) {
    httplib::Response no_code;
    accounts->handle_2fa_disable(with_session({{"password", kPassword}}), no_code);
    EXPECT_EQ(status_of(no_code), 400) << no_code.body;
    httplib::Response wrong_code;
    accounts->handle_2fa_disable(with_session({{"password", kPassword}, {"code", "XXXXX-XXXXX"}}),
                                 wrong_code);
    EXPECT_EQ(status_of(wrong_code), 403);
    EXPECT_TRUE(store->get_totp("acct-1")->enabled);

    httplib::Response ok;
    accounts->handle_2fa_disable(with_session({{"password", kPassword}, {"code", current_code()}}),
                                 ok);
    EXPECT_EQ(status_of(ok), 200) << ok.body;
    EXPECT_FALSE(store->get_totp("acct-1").has_value());
}

TEST_F(Audit3TwoFactor, AnAlreadyUsedCodeSaysToWaitAndIsNotCountedAsAGuess) {
    const auto code = current_code();
    ASSERT_TRUE(store->accept_totp_step("acct-1", static_cast<uint64_t>(now_seconds()) / 30 + 1));
    for (int i = 0; i < 10; ++i) {
        httplib::Response res;
        accounts->handle_2fa_disable(with_session({{"password", kPassword}, {"code", code}}), res);
        ASSERT_EQ(status_of(res), 403) << res.body;
        EXPECT_NE(json::parse(res.body)["error"].get<std::string>().find("already used"),
                  std::string::npos);
    }
    // Not locked: a backup code still works.
    httplib::Response res;
    accounts->handle_2fa_disable(with_session({{"password", kPassword}, {"code", "abcde-fghjk"}}), res);
    EXPECT_EQ(status_of(res), 200) << res.body;
}

TEST_F(Audit3TwoFactor, BackupCodesCanBeRegenerated) {
    httplib::Response refused;
    accounts->handle_2fa_regenerate_backup_codes(with_session({{"password", kPassword}}), refused);
    EXPECT_EQ(status_of(refused), 400);

    httplib::Response res;
    accounts->handle_2fa_regenerate_backup_codes(
        with_session({{"password", kPassword}, {"code", current_code()}}), res);
    ASSERT_EQ(status_of(res), 200) << res.body;
    auto codes = json::parse(res.body)["backup_codes"];
    ASSERT_EQ(codes.size(), 8u);
    EXPECT_FALSE(store->consume_backup_code("acct-1", "MNPQR-STUVW")) << "old codes still work";
    EXPECT_TRUE(store->consume_backup_code("acct-1", codes[0].get<std::string>()));
}

TEST_F(Audit3TwoFactor, ABurnedLoginTokenSendsThePageBackToThePasswordStep) {
    httplib::Response lres;
    accounts->handle_login(json_request({{"username", "alice"}, {"password", kPassword}}), lres);
    const auto token = json::parse(lres.body).value("login_token", "");
    ASSERT_FALSE(token.empty()) << lres.body;

    httplib::Response first;
    accounts->handle_login_2fa(json_request({{"login_token", token}, {"code", "000000"}}), first);
    EXPECT_EQ(status_of(first), 401);
    EXPECT_FALSE(json::parse(first.body).value("restart", false));
    httplib::Response second;  // totp_max_attempts = 2: burned
    accounts->handle_login_2fa(json_request({{"login_token", token}, {"code", "000000"}}), second);
    EXPECT_EQ(status_of(second), 401);
    EXPECT_TRUE(json::parse(second.body).value("restart", false)) << second.body;
    httplib::Response third;
    accounts->handle_login_2fa(json_request({{"login_token", token}, {"code", current_code()}}),
                               third);
    EXPECT_TRUE(json::parse(third.body).value("restart", false)) << third.body;
}

// ---------------------------------------------------------------------------
// Data validation
// ---------------------------------------------------------------------------

TEST(Audit3Validation, ReservedAndPunctuatedUsernamesAreRefused) {
    for (const char* name : {"admin", "adm1n", "ad.min", "root", "support", "bsfchat",
                             "bsfchat-team", "moderator", "security", "system", "help"}) {
        EXPECT_TRUE(username_policy_error(name).has_value()) << name;
    }
    for (const char* name : {"-alice", "alice.", "_bob", "bob_"}) {
        EXPECT_TRUE(username_policy_error(name).has_value()) << name;
    }
    for (const char* name : {"alice", "a.b-c_d", "rootbeer", "helpful"}) {
        EXPECT_FALSE(username_policy_error(name).has_value()) << name;
    }
}

namespace {

class Audit3Profile : public ::testing::Test {
protected:
    void SetUp() override {
        config.password_hash_iterations = kMinPbkdf2Iterations;
        config.login_rate_limit = 1000;
        store = std::make_unique<IdentityStore>(":memory:");
        store->initialize();
        auto alice = make_account("acct-1", "alice");
        alice.email = "Alice@Example.com";
        ASSERT_TRUE(store->create_account(alice));
        ASSERT_TRUE(store->create_account(make_account("acct-2", "bob")));
        Session s;
        s.session_id = "bob-browser";
        s.account_id = "acct-2";
        s.created_at = now_seconds();
        s.expires_at = s.created_at + 3600;
        ASSERT_TRUE(store->create_session(s));
        accounts = std::make_unique<AccountHandler>(*store, config);
    }

    httplib::Response as_bob(void (AccountHandler::*handler)(const httplib::Request&, httplib::Response&),
                             const json& body) {
        auto req = json_request(body);
        req.set_header("Cookie", "session=bob-browser");
        httplib::Response res;
        ((*accounts).*handler)(req, res);
        return res;
    }

    Config config;
    std::unique_ptr<IdentityStore> store;
    std::unique_ptr<AccountHandler> accounts;
};

} // namespace

TEST_F(Audit3Profile, DisplayNameIsTrimmedAndCannotBeEmpty) {
    auto empty = as_bob(&AccountHandler::handle_update_profile, {{"display_name", "   "}});
    EXPECT_EQ(status_of(empty), 400);
    auto padded = as_bob(&AccountHandler::handle_update_profile, {{"display_name", "  Bob B.  "}});
    ASSERT_EQ(status_of(padded), 200) << padded.body;
    EXPECT_EQ(store->get_account_by_id("acct-2")->display_name, "Bob B.");
}

TEST_F(Audit3Profile, EmailUniquenessIgnoresCase) {
    auto res = as_bob(&AccountHandler::handle_update_profile, {{"email", "alice@example.COM"}});
    EXPECT_EQ(status_of(res), 409) << res.body;
    httplib::Response reg;
    accounts->handle_register(json_request({{"username", "carol"},
                                            {"password", "carol password"},
                                            {"email", "ALICE@example.com"}}),
                              reg);
    EXPECT_EQ(status_of(reg), 409) << reg.body;
}

TEST_F(Audit3Profile, ServerListIsCanonicalHttpsAndKeepsNamesOnReAdd) {
    auto add = [&](const json& body) {
        return as_bob(&AccountHandler::handle_add_server, body);
    };
    ASSERT_EQ(status_of(add({{"server_url", "https://Chat.Example.com:443/"},
                             {"server_name", "Team chat"}})), 200);
    // The same server spelled differently: one row, name kept.
    ASSERT_EQ(status_of(add({{"server_url", "https://chat.example.com"}})), 200);
    auto list = store->list_server_memberships("acct-2");
    ASSERT_EQ(list.size(), 1u);
    EXPECT_EQ(list[0].server_url, "https://chat.example.com");
    EXPECT_EQ(list[0].server_name, "Team chat");

    // Plain http only on loopback; errors do not name the JSON field.
    auto lan = add({{"server_url", "http://192.168.1.10:8448"}});
    EXPECT_EQ(status_of(lan), 400);
    EXPECT_EQ(json::parse(lan.body)["error"].get<std::string>().find("server_url"), std::string::npos);
    EXPECT_EQ(status_of(add({{"server_url", "http://localhost:8448"}})), 200);

    // Removing by any spelling.
    auto rm = as_bob(&AccountHandler::handle_remove_server, {{"server_url", "https://CHAT.example.com/"}});
    EXPECT_EQ(status_of(rm), 200);
    EXPECT_EQ(store->list_server_memberships("acct-2").size(), 1u);  // localhost left
}

TEST_F(Audit3Profile, DisabledAccountIsToldSoOnlyWithTheRightPassword) {
    ASSERT_TRUE(store->disable_account("acct-2"));
    httplib::Response wrong;
    accounts->handle_login(json_request({{"username", "bob"}, {"password", "nope nope"}}), wrong);
    EXPECT_EQ(status_of(wrong), 401);
    httplib::Response right;
    accounts->handle_login(json_request({{"username", "bob"}, {"password", "correct horse battery"}}),
                           right);
    EXPECT_EQ(status_of(right), 403);
    EXPECT_NE(json::parse(right.body)["error"].get<std::string>().find("disabled"), std::string::npos);
}

// ---------------------------------------------------------------------------
// Sessions: tell them apart; signing in again replaces the old one
// ---------------------------------------------------------------------------

TEST(Audit3Sessions, UserAgentSummaries) {
    EXPECT_EQ(describe_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) "
                                  "Gecko/20100101 Firefox/132.0"),
              "Firefox on Windows");
    EXPECT_EQ(describe_user_agent("Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) "
                                  "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 "
                                  "Mobile/15E148 Safari/604.1"),
              "Safari on iPhone");
    EXPECT_EQ(describe_user_agent("Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 "
                                  "(KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"),
              "Chrome on Android");
    EXPECT_EQ(describe_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                                  "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"),
              "Edge on Windows");
    EXPECT_EQ(describe_user_agent(""), "");
}

TEST(Audit3Sessions, ListShowsDeviceAndCoarseAddressAndReloginReplacesTheSession) {
    Config config;
    config.password_hash_iterations = kMinPbkdf2Iterations;
    config.login_rate_limit = 1000;
    IdentityStore store(":memory:");
    store.initialize();
    ASSERT_TRUE(store.create_account(make_account("acct-1", "alice")));
    AccountHandler accounts(store, config);

    auto login = [&](const std::string& cookie) {
        auto req = json_request({{"username", "alice"}, {"password", "correct horse battery"}},
                                "203.0.113.77");
        req.set_header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 "
                                     "Firefox/132.0");
        if (!cookie.empty()) req.set_header("Cookie", cookie);
        httplib::Response res;
        accounts.handle_login(req, res);
        EXPECT_EQ(status_of(res), 200) << res.body;
        EXPECT_FALSE(json::parse(res.body).contains("session_id"));
        auto set_cookie = header_of(res, "Set-Cookie");
        return set_cookie.substr(0, set_cookie.find(';'));
    };
    const auto first = login("");
    const auto second = login(first);  // signing in again in the same browser
    ASSERT_NE(first, second);

    httplib::Request list;
    list.set_header("Cookie", second);
    httplib::Response res;
    accounts.handle_list_sessions(list, res);
    auto sessions = json::parse(res.body);
    ASSERT_EQ(sessions.size(), 1u) << "the replaced session is still listed: " << res.body;
    EXPECT_EQ(sessions[0]["device"], "Firefox on Linux");
    EXPECT_EQ(sessions[0]["ip"], "203.0.113.0/24");

    httplib::Request old_cookie;
    old_cookie.set_header("Cookie", first);
    httplib::Response pres;
    accounts.handle_get_profile(old_cookie, pres);
    EXPECT_EQ(status_of(pres), 401);
}
