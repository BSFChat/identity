// Sign-in and sign-up usability fixes (audit 2026-11-15, section 7: I-2 to
// I-7): what the static pages are told about the deployment, password
// recovery by the operator, username normalisation at login, and the HTML
// pages a person in a browser gets instead of raw JSON.

#include <gtest/gtest.h>

#include "api/AccountHandler.h"
#include "api/OidcHandler.h"
#include "core/ClientRegistration.h"
#include "core/WebUtil.h"
#include "crypto/KeyManager.h"
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

// ---------------------------------------------------------------------------
// Login folds the case of a username (audit I-4)
// ---------------------------------------------------------------------------

namespace {

httplib::Request login_request(const std::string& username, const std::string& password) {
    httplib::Request req;
    req.method = "POST";
    req.set_header("Content-Type", "application/json");
    req.body = json{{"username", username}, {"password", password}}.dump();
    req.remote_addr = "10.0.0.1";
    return req;
}

} // namespace

class UsernameCaseTest : public ::testing::Test {
protected:
    void SetUp() override {
        config.password_hash_iterations = kMinPbkdf2Iterations;
        config.login_rate_limit = 1000;
        config.login_max_failures = 3;
        store = std::make_unique<IdentityStore>(":memory:");
        store->initialize();
        accounts = std::make_unique<AccountHandler>(*store, config);
        ASSERT_TRUE(store->create_account(make_account("acct-a", "alice", "correct horse battery")));
    }

    int login(const std::string& username, const std::string& password) {
        auto req = login_request(username, password);
        httplib::Response res;
        accounts->handle_login(req, res);
        return status_of(res);
    }

    Config config;
    std::unique_ptr<IdentityStore> store;
    std::unique_ptr<AccountHandler> accounts;
};

TEST_F(UsernameCaseTest, CapitalisedUsernameSignsInToTheLowercaseAccount) {
    // What a phone's autocapitalisation turns "alice" into.
    EXPECT_EQ(login("Alice", "correct horse battery"), 200);
    EXPECT_EQ(login("ALICE", "correct horse battery"), 200);
    EXPECT_EQ(login("Alice", "wrong"), 401);
}

TEST_F(UsernameCaseTest, CaseVariantsShareOneLockout) {
    // Spreading guesses over "alice", "Alice", "ALICE"... must not multiply
    // the attempts allowed: they all count against the folded name.
    EXPECT_EQ(login("alice", "wrong-1"), 401);
    EXPECT_EQ(login("Alice", "wrong-2"), 401);
    EXPECT_EQ(login("ALICE", "wrong-3"), 401);
    EXPECT_EQ(login("aLiCe", "correct horse battery"), 429);
}

TEST_F(UsernameCaseTest, AnExactLegacyUppercaseNameStillWins) {
    // Accounts from before the lowercase grammar keep signing in as typed.
    ASSERT_TRUE(store->create_account(make_account("acct-b", "Bob", "bob's long password")));
    EXPECT_EQ(login("Bob", "bob's long password"), 200);
}

// ---------------------------------------------------------------------------
// Browser-facing OIDC errors are pages, not JSON (audit I-5, I-6, I-7)
// ---------------------------------------------------------------------------

TEST(ContentNegotiationTest, OnlyBrowserNavigationsGetPages) {
    // What Chrome / Firefox / Safari send for a top-level navigation.
    EXPECT_TRUE(wants_html("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "navigate"));
    EXPECT_TRUE(wants_html("text/html", ""));
    EXPECT_TRUE(wants_html("", "navigate"));
    // fetch() from the pages, curl, httplib, and anything asking for JSON.
    EXPECT_FALSE(wants_html("*/*", "cors"));
    EXPECT_FALSE(wants_html("", ""));
    EXPECT_FALSE(wants_html("application/json", "navigate"));
    EXPECT_FALSE(wants_html("text/html, Application/JSON", ""));
}

namespace {

const char* kBrowserAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
const char* kRedirect = "http://localhost:41234/oauth/callback";
// 43 characters, the RFC 7636 minimum; /authorize only checks its length.
const char* kChallenge = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

std::string header_of(const httplib::Response& res, const std::string& name) {
    auto it = res.headers.find(name);
    return it == res.headers.end() ? "" : it->second;
}

std::string hidden_value(const std::string& html, const std::string& name) {
    const std::string marker = "name=\"" + name + "\" value=\"";
    auto pos = html.find(marker);
    if (pos == std::string::npos) return "";
    pos += marker.size();
    return html.substr(pos, html.find('"', pos) - pos);
}

std::string html_unescape_amp(std::string s) {
    for (size_t pos; (pos = s.find("&amp;")) != std::string::npos;) s.replace(pos, 5, "&");
    return s;
}

} // namespace

class BrowserFacingOidcTest : public ::testing::Test {
protected:
    void SetUp() override {
        keys_dir = bsfchat::test::unique_temp_dir("bsfchat_id_signin_ux_keys");
        config.password_hash_iterations = kMinPbkdf2Iterations;
        store = std::make_unique<IdentityStore>(":memory:");
        store->initialize();
        key_manager = std::make_unique<KeyManager>(keys_dir.string());
        accounts = std::make_unique<AccountHandler>(*store, config);
        oidc = std::make_unique<OidcHandler>(*store, *key_manager, *accounts, config);

        ASSERT_TRUE(store->create_account(make_account("acct-a", "alice", "correct horse battery")));
        OAuthClient client;
        client.client_id = "bsfchat-desktop";
        client.name = "BSFChat Desktop";
        client.redirect_uris = first_party_redirect_uris();
        client.created_at = now_seconds();
        ASSERT_TRUE(store->create_oauth_client(client));
        ASSERT_TRUE(store->create_session(browser_session_for("alice-browser", "acct-a")));
    }

    void TearDown() override { std::filesystem::remove_all(keys_dir); }

    httplib::Request authorize_request(bool browser, bool with_session = true) {
        httplib::Request req;
        req.method = "GET";
        req.remote_addr = "10.0.0.1";
        if (browser) req.set_header("Accept", kBrowserAccept);
        if (with_session) req.set_header("Cookie", "session=alice-browser");
        req.params.emplace("client_id", "bsfchat-desktop");
        req.params.emplace("redirect_uri", kRedirect);
        req.params.emplace("response_type", "code");
        req.params.emplace("scope", "openid");
        req.params.emplace("state", "st&te");
        req.params.emplace("code_challenge", kChallenge);
        req.params.emplace("code_challenge_method", "S256");
        return req;
    }

    // The consent page for alice, as a browser sees it.
    std::string consent_page() {
        auto req = authorize_request(true);
        httplib::Response res;
        oidc->handle_authorize(req, res);
        EXPECT_EQ(status_of(res), 200);
        return res.body;
    }

    httplib::Response decide(const std::string& page, const std::string& approve,
                             const std::string& cookie, bool browser = true) {
        httplib::Request req;
        req.method = "POST";
        req.remote_addr = "10.0.0.1";
        req.set_header("Content-Type", "application/x-www-form-urlencoded");
        if (browser) req.set_header("Accept", kBrowserAccept);
        if (!cookie.empty()) req.set_header("Cookie", "session=" + cookie);
        req.body = "consent_token=" + percent_encode(hidden_value(page, "consent_token")) +
                   "&restart=" + percent_encode(html_unescape_amp(hidden_value(page, "restart"))) +
                   "&approve=" + approve;
        httplib::Response res;
        oidc->handle_authorize_decision(req, res);
        return res;
    }

    std::filesystem::path keys_dir;
    Config config;
    std::unique_ptr<IdentityStore> store;
    std::unique_ptr<KeyManager> key_manager;
    std::unique_ptr<AccountHandler> accounts;
    std::unique_ptr<OidcHandler> oidc;
};

TEST_F(BrowserFacingOidcTest, AuthorizeErrorsArePagesForBrowsersAndJsonForApis) {
    for (bool browser : {true, false}) {
        auto req = authorize_request(browser);
        req.params.erase("client_id");
        httplib::Response res;
        oidc->handle_authorize(req, res);
        EXPECT_EQ(status_of(res), 400);
        if (browser) {
            EXPECT_NE(header_of(res, "Content-Type").find("text/html"), std::string::npos);
            EXPECT_NE(res.body.find("Sign-in link is incomplete"), std::string::npos);
        } else {
            EXPECT_EQ(json::parse(res.body)["error"], "client_id and redirect_uri are required");
        }
    }

    // An unregistered return address is still reported in-band, never followed.
    auto req = authorize_request(true);
    req.params.erase("redirect_uri");
    req.params.emplace("redirect_uri", "https://evil.example/cb");
    httplib::Response res;
    oidc->handle_authorize(req, res);
    EXPECT_EQ(status_of(res), 400);
    EXPECT_TRUE(header_of(res, "Location").empty());
    EXPECT_NE(res.body.find("<!DOCTYPE html>"), std::string::npos);
}

TEST_F(BrowserFacingOidcTest, SessionLostWhileConsentPageWasOpenOffersToSignInAgain) {
    const auto page = consent_page();
    ASSERT_FALSE(hidden_value(page, "restart").empty());

    // The cookie is gone (expired, or signed out in another tab).
    auto res = decide(page, "true", "");
    EXPECT_EQ(status_of(res), 401);
    EXPECT_TRUE(header_of(res, "Location").empty());
    EXPECT_NE(header_of(res, "Content-Type").find("text/html"), std::string::npos);
    EXPECT_NE(res.body.find("Your sign-in session ended"), std::string::npos);
    EXPECT_NE(res.body.find("Sign in again"), std::string::npos);
    EXPECT_NE(res.body.find("href=\"/authorize?client_id=bsfchat-desktop"), std::string::npos);

    // An API client still gets the JSON it always did.
    auto api = decide(page, "true", "", /*browser=*/false);
    EXPECT_EQ(status_of(api), 401);
    EXPECT_EQ(json::parse(api.body)["error"], "Not authenticated");

    // Nothing was spent: the rightful session can still approve.
    auto ok = decide(page, "true", "alice-browser");
    EXPECT_EQ(status_of(ok), 302);
    EXPECT_NE(header_of(ok, "Location").find("code="), std::string::npos);
}

TEST_F(BrowserFacingOidcTest, RestartLinkIsRebuiltNotEchoed) {
    const auto page = consent_page();
    httplib::Request req;
    req.method = "POST";
    req.set_header("Content-Type", "application/x-www-form-urlencoded");
    req.set_header("Accept", kBrowserAccept);
    // Anything that is not an /authorize request on this origin gets no link.
    req.body = "consent_token=" + hidden_value(page, "consent_token") +
               "&restart=" + percent_encode("https://evil.example/authorize?client_id=x&redirect_uri=y");
    httplib::Response res;
    oidc->handle_authorize_decision(req, res);
    EXPECT_EQ(status_of(res), 401);
    EXPECT_EQ(res.body.find("evil.example"), std::string::npos);
    EXPECT_EQ(res.body.find("Sign in again</a>"), std::string::npos);
}

TEST_F(BrowserFacingOidcTest, NotYouSignsOutAndPutsTheSameRequestAgain) {
    const auto page = consent_page();
    EXPECT_NE(page.find("Use a different account"), std::string::npos);

    auto res = decide(page, "switch", "alice-browser");
    EXPECT_EQ(status_of(res), 302);
    // This browser session is over, and the cookie is cleared.
    EXPECT_FALSE(store->get_browser_session("alice-browser"));
    EXPECT_NE(header_of(res, "Set-Cookie").find("Max-Age=0"), std::string::npos);
    // No code went anywhere; the same request is put again...
    const auto again = header_of(res, "Location");
    EXPECT_EQ(again.rfind("/authorize?", 0), 0u) << again;
    EXPECT_EQ(again.find("code="), std::string::npos);
    EXPECT_NE(again.find("state=st%26te"), std::string::npos) << again;
    EXPECT_NE(again.find("code_challenge="), std::string::npos) << again;

    // ...which, with no session, goes to the sign-in page with it preserved.
    httplib::Request follow;
    follow.method = "GET";
    follow.set_header("Accept", kBrowserAccept);
    follow.params.emplace("client_id", "bsfchat-desktop");
    follow.params.emplace("redirect_uri", kRedirect);
    follow.params.emplace("response_type", "code");
    follow.params.emplace("scope", "openid");
    follow.params.emplace("state", "st&te");
    follow.params.emplace("code_challenge", kChallenge);
    httplib::Response login;
    oidc->handle_authorize(follow, login);
    EXPECT_EQ(header_of(login, "Location").rfind("/login.html?", 0), 0u);

    // The prompt is spent: it cannot be approved afterwards.
    auto late = decide(page, "true", "alice-browser");
    EXPECT_NE(status_of(late), 302);
}

TEST_F(BrowserFacingOidcTest, NotYouFromAStrangerSignsNobodyOut) {
    ASSERT_TRUE(store->create_account(make_account("acct-m", "mallory", "mallory's password")));
    ASSERT_TRUE(store->create_session(browser_session_for("mallory-browser", "acct-m")));
    const auto page = consent_page();

    auto res = decide(page, "switch", "mallory-browser");
    EXPECT_EQ(status_of(res), 403);
    EXPECT_TRUE(store->get_browser_session("mallory-browser"));
    EXPECT_TRUE(store->get_browser_session("alice-browser"));
}

TEST_F(BrowserFacingOidcTest, ResubmittedDenyIsNotCalledAnApproval) {
    const auto page = consent_page();
    auto first = decide(page, "false", "alice-browser");
    EXPECT_EQ(status_of(first), 302);
    EXPECT_NE(header_of(first, "Location").find("error=access_denied"), std::string::npos);

    auto again = decide(page, "false", "alice-browser");
    EXPECT_EQ(status_of(again), 409);
    EXPECT_EQ(again.body.find("approved"), std::string::npos);
    EXPECT_NE(again.body.find("already answered"), std::string::npos);
}
