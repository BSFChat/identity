// Regression tests for the fixes to docs/security-audit-2026-09.md that the
// audit's own proof tests (test_security_audit.cpp) do not cover: trusted
// proxies, targeted lockout, same-origin checks, refresh-token lifetime and
// replay, credential visibility and revocation, hashing at rest, TOTP replay
// through enrolment, profile bounds, security headers and the v2 migration.
//
// Same approach as test_auth_flows.cpp: handlers driven directly with
// synthetic httplib::Request objects, nothing listens on a socket.

#include <gtest/gtest.h>

#include "api/AccountHandler.h"
#include "api/AdminHandler.h"
#include "api/OidcHandler.h"
#include "core/ClientAddress.h"
#include "core/Config.h"
#include "core/Username.h"
#include "core/WebUtil.h"
#include "crypto/PasswordHash.h"
#include "crypto/Secrets.h"
#include "crypto/Totp.h"
#include "store/IdentityStore.h"
#include "TempPaths.h"

#include <nlohmann/json.hpp>
#include <openssl/sha.h>

#include <sys/stat.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <regex>

using namespace bsfchat::id;
using json = nlohmann::json;

namespace {

int64_t now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string base64url(const unsigned char* data, size_t len) {
    static constexpr char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string result;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) n |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < len) n |= static_cast<uint32_t>(data[i + 2]);
        result += table[(n >> 18) & 0x3F];
        result += table[(n >> 12) & 0x3F];
        if (i + 1 < len) result += table[(n >> 6) & 0x3F];
        if (i + 2 < len) result += table[n & 0x3F];
    }
    return result;
}

std::string s256_challenge(const std::string& verifier) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(verifier.c_str()), verifier.size(), hash);
    return base64url(hash, SHA256_DIGEST_LENGTH);
}

const std::string kVerifier = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";
const std::string kRedirect = "http://localhost:41234/oauth/callback";
const std::string kPassword = "correct horse battery";

std::string form_encode(const std::map<std::string, std::string>& params) {
    std::string out;
    for (const auto& [k, v] : params) {
        if (!out.empty()) out += '&';
        out += percent_encode(k) + "=" + percent_encode(v);
    }
    return out;
}

httplib::Request form_request(const std::map<std::string, std::string>& params) {
    httplib::Request req;
    req.method = "POST";
    req.set_header("Content-Type", "application/x-www-form-urlencoded");
    req.body = form_encode(params);
    req.remote_addr = "10.0.0.1";
    return req;
}

httplib::Request json_request(const json& body, const std::string& ip = "10.0.0.1") {
    httplib::Request req;
    req.method = "POST";
    req.set_header("Content-Type", "application/json");
    req.body = body.dump();
    req.remote_addr = ip;
    return req;
}

int status_of(const httplib::Response& res) {
    return res.status < 0 ? 200 : res.status;
}

std::string header_of(const httplib::Response& res, const std::string& name) {
    auto it = res.headers.find(name);
    return it == res.headers.end() ? "" : it->second;
}

std::string query_param(const std::string& url, const std::string& key) {
    auto qpos = url.find('?');
    if (qpos == std::string::npos) return "";
    std::string query = url.substr(qpos + 1);
    size_t pos = 0;
    while (pos < query.size()) {
        auto amp = query.find('&', pos);
        auto pair = query.substr(pos, amp == std::string::npos ? std::string::npos : amp - pos);
        auto eq = pair.find('=');
        if (eq != std::string::npos && percent_decode(pair.substr(0, eq)) == key) {
            return percent_decode(pair.substr(eq + 1));
        }
        if (amp == std::string::npos) break;
        pos = amp + 1;
    }
    return "";
}

class SecurityFixTest : public ::testing::Test {
protected:
    void SetUp() override {
        keys_dir = bsfchat::test::unique_temp_dir("bsfchat_id_fix_keys");

        config.issuer_url = "https://id.example";
        config.password_hash_iterations = kMinPbkdf2Iterations;
        config.totp_max_attempts = 3;
        config.login_max_failures = 4;
        config.login_rate_limit = 1000;
        config.cookie_secure = true;
        configure(config);

        store = std::make_unique<IdentityStore>(":memory:");
        store->initialize();
        key_manager = std::make_unique<KeyManager>(keys_dir.string());
        accounts = std::make_unique<AccountHandler>(*store, config);
        oidc = std::make_unique<OidcHandler>(*store, *key_manager, *accounts, config);

        auto now = now_seconds();
        Account account;
        account.id = "acct-1";
        account.username = "alice";
        account.email = "alice@example.com";
        account.display_name = "Alice";
        account.password_hash = hash_password(kPassword, config.password_hash_iterations);
        account.created_at = now;
        account.updated_at = now;
        ASSERT_TRUE(store->create_account(account));

        OAuthClient desktop;
        desktop.client_id = "bsfchat-desktop";
        desktop.client_secret = "";
        desktop.name = "BSFChat Desktop";
        desktop.redirect_uris = R"(["http://127.0.0.1/oauth/callback","http://localhost/oauth/callback"])";
        desktop.created_at = now;
        ASSERT_TRUE(store->create_oauth_client(desktop));

        browser_session = new_browser_session("acct-1");
    }

    void TearDown() override { std::filesystem::remove_all(keys_dir); }

    // Fixtures that need a different Config override this.
    virtual void configure(Config&) {}

    std::string new_browser_session(const std::string& account_id) {
        auto id = secure_random_hex(32);
        auto now = now_seconds();
        Session s;
        s.session_id = id;
        s.account_id = account_id;
        s.created_at = now;
        s.expires_at = now + 86400;
        s.token_type = token_type::kBrowserSession;
        EXPECT_TRUE(store->create_session(s));
        return id;
    }

    httplib::Request cookie_request(const std::string& session, const std::string& method = "GET") {
        httplib::Request req;
        req.method = method;
        req.remote_addr = "10.0.0.1";
        req.set_header("Cookie", "session=" + session);
        return req;
    }

    httplib::Request cookie_json(const std::string& session, const json& body) {
        auto req = json_request(body);
        req.set_header("Cookie", "session=" + session);
        return req;
    }

    json desktop_login(const std::string& session) {
        auto req = cookie_request(session);
        req.params.emplace("client_id", "bsfchat-desktop");
        req.params.emplace("redirect_uri", kRedirect);
        req.params.emplace("response_type", "code");
        req.params.emplace("scope", "openid profile");
        req.params.emplace("state", "xyz");
        req.params.emplace("code_challenge", s256_challenge(kVerifier));
        req.params.emplace("code_challenge_method", "S256");
        httplib::Response res;
        oidc->handle_authorize(req, res);
        EXPECT_EQ(status_of(res), 200) << res.body;
        const std::string marker = "name=\"consent_token\" value=\"";
        auto pos = res.body.find(marker);
        EXPECT_NE(pos, std::string::npos);
        auto start = pos + marker.size();
        auto consent = res.body.substr(start, res.body.find('"', start) - start);

        auto decision = form_request({{"consent_token", consent}, {"approve", "true"}});
        decision.set_header("Cookie", "session=" + session);
        httplib::Response dres;
        oidc->handle_authorize_decision(decision, dres);
        auto code = query_param(header_of(dres, "Location"), "code");

        auto treq = form_request({{"grant_type", "authorization_code"},
                                  {"code", code},
                                  {"redirect_uri", kRedirect},
                                  {"client_id", "bsfchat-desktop"},
                                  {"code_verifier", kVerifier}});
        httplib::Response tres;
        oidc->handle_token(treq, tres);
        EXPECT_EQ(status_of(tres), 200) << tres.body;
        return json::parse(tres.body);
    }

    httplib::Response refresh(const std::string& refresh_token) {
        auto req = form_request({{"grant_type", "refresh_token"},
                                 {"refresh_token", refresh_token},
                                 {"client_id", "bsfchat-desktop"}});
        httplib::Response res;
        oidc->handle_token(req, res);
        return res;
    }

    int login(const std::string& ip, const std::string& password = kPassword,
              const std::string& xff = "", const std::string& username = "alice") {
        auto req = json_request(json{{"username", username}, {"password", password}}, ip);
        if (!xff.empty()) req.set_header("X-Forwarded-For", xff);
        httplib::Response res;
        accounts->handle_login(req, res);
        return status_of(res);
    }

    std::filesystem::path keys_dir;
    Config config;
    std::unique_ptr<IdentityStore> store;
    std::unique_ptr<KeyManager> key_manager;
    std::unique_ptr<AccountHandler> accounts;
    std::unique_ptr<OidcHandler> oidc;
    std::string browser_session;
};

// Behind the production shape: Cloudflare -> nginx (resolves the client with
// set_real_ip_from, builds X-Forwarded-For) -> docker bridge -> identity.
class TrustedProxyTest : public SecurityFixTest {
protected:
    void configure(Config& c) override { c.trusted_proxies = {"172.16.0.0/12"}; }
};

} // namespace

// ---------------------------------------------------------------------------
// H2 — client resolution through trusted proxies
// ---------------------------------------------------------------------------

TEST(ClientAddressTest, TrustsNothingByDefault) {
    Config defaults;
    EXPECT_TRUE(defaults.trusted_proxies.empty());

    ClientAddressResolver resolver(defaults.trusted_proxies);
    httplib::Request req;
    req.remote_addr = "172.18.0.1";
    req.set_header("X-Forwarded-For", "203.0.113.9");
    // The header is ignored; the peer is the identity.
    EXPECT_EQ(resolver.resolve(req).value_or(""), "172.18.0.1");
    EXPECT_TRUE(resolver.looks_like_untrusted_proxy(req));
}

TEST(ClientAddressTest, TakesTheRightmostUntrustedHop) {
    ClientAddressResolver resolver({"172.16.0.0/12"});
    httplib::Request req;
    req.remote_addr = "172.18.0.1";
    // A client-supplied first entry must not be believed: only the hop our
    // proxy appended is vouched for.
    req.set_header("X-Forwarded-For", "6.6.6.6, 198.51.100.7");
    EXPECT_EQ(resolver.resolve(req).value_or(""), "198.51.100.7");

    httplib::Request direct;
    direct.remote_addr = "198.51.100.8";
    direct.set_header("X-Forwarded-For", "6.6.6.6");
    EXPECT_EQ(resolver.resolve(direct).value_or(""), "198.51.100.8");

    // A trusted proxy with no header: the client is unknown, not the proxy.
    httplib::Request bare;
    bare.remote_addr = "172.18.0.1";
    EXPECT_FALSE(resolver.resolve(bare).has_value());
}

TEST(ClientAddressTest, ConfigRejectsAnUnparseableProxyEntry) {
    auto path = bsfchat::test::unique_temp_file("bsfchat_id_proxy_cfg", ".toml");
    {
        std::ofstream f(path);
        f << "[auth]\ntrusted_proxies = [\"172.16.0.0/12\", \"not-an-address\"]\n";
    }
    EXPECT_THROW(Config::load(path.string()), std::runtime_error);
    {
        std::ofstream f(path);
        f << "[auth]\ntrusted_proxies = \"172.16.0.0/12\"\n"
             "trusted_public_proxies = [\"173.245.48.0/20\"]\n"
             "trusted_public_proxies_reason = \"Cloudflare, refreshed 2026-09-22\"\n";
    }
    auto cfg = Config::load(path.string());
    // Acknowledged public ranges are merged into the one list the resolver reads.
    EXPECT_EQ(cfg.trusted_proxies, (std::vector<std::string>{"172.16.0.0/12", "173.245.48.0/20"}));
    std::filesystem::remove(path);
}

TEST_F(TrustedProxyTest, FailuresCountAgainstTheRealClientNotTheProxy) {
    const std::string proxy = "172.18.0.1";
    // The attacker exhausts its own allowance for alice...
    for (int i = 0; i < config.login_max_failures; ++i) {
        EXPECT_EQ(login(proxy, "wrong", "203.0.113.66"), 401);
    }
    EXPECT_EQ(login(proxy, kPassword, "203.0.113.66"), 429);
    // ...and alice, behind the same proxy, is unaffected.
    EXPECT_EQ(login(proxy, kPassword, "198.51.100.7"), 200);
}

TEST_F(TrustedProxyTest, RequestLimiterIsPerClient) {
    config.login_rate_limit = 2;
    accounts = std::make_unique<AccountHandler>(*store, config);
    EXPECT_EQ(login("172.18.0.1", "wrong", "203.0.113.66"), 401);
    EXPECT_EQ(login("172.18.0.1", "wrong", "203.0.113.66"), 401);
    EXPECT_EQ(login("172.18.0.1", "wrong", "203.0.113.66"), 429);
    EXPECT_EQ(login("172.18.0.1", kPassword, "198.51.100.7"), 200);
}

// ---------------------------------------------------------------------------
// L6 — a stranger cannot lock a named user out; a spread attack still hits a
// ceiling
// ---------------------------------------------------------------------------

TEST_F(SecurityFixTest, OneAddressCannotLockSomebodyElseOut) {
    for (int i = 0; i < config.login_max_failures; ++i) {
        EXPECT_EQ(login("10.9.9.9", "wrong"), 401);
    }
    EXPECT_EQ(login("10.9.9.9", kPassword), 429) << "the attacker's own address is locked";
    EXPECT_EQ(login("10.0.0.1", kPassword), 200) << "the owner is not";
}

TEST_F(SecurityFixTest, AccountWideCeilingStopsASpreadAttack) {
    // login_max_failures * 4 failures, no more than login_max_failures from
    // any one address.
    for (int ip = 1; ip <= 4; ++ip) {
        for (int i = 0; i < config.login_max_failures; ++i) {
            login("192.0.2." + std::to_string(ip), "wrong");
        }
    }
    EXPECT_EQ(login("198.51.100.200", kPassword), 429);
}

// ---------------------------------------------------------------------------
// H3 — cross-site requests and lookalike names
// ---------------------------------------------------------------------------

TEST_F(SecurityFixTest, CrossSiteJsonLoginIsRefused) {
    auto with = [&](const std::string& header, const std::string& value) {
        auto req = json_request(json{{"username", "alice"}, {"password", kPassword}});
        req.set_header(header, value);
        httplib::Response res;
        accounts->handle_login(req, res);
        return std::make_pair(status_of(res), header_of(res, "Set-Cookie"));
    };
    EXPECT_EQ(with("Origin", "https://attacker.example").first, 403);
    EXPECT_TRUE(with("Origin", "https://attacker.example").second.empty());
    EXPECT_EQ(with("Origin", "null").first, 403);
    EXPECT_EQ(with("Sec-Fetch-Site", "cross-site").first, 403);
    EXPECT_EQ(with("Sec-Fetch-Site", "same-site").first, 403);
    // The portal itself.
    EXPECT_EQ(with("Origin", "https://id.example").first, 200);
    EXPECT_EQ(with("Origin", "https://ID.example:443").first, 200);
    EXPECT_EQ(with("Sec-Fetch-Site", "same-origin").first, 200);
}

TEST_F(SecurityFixTest, CookieAuthenticatedWritesRequireJson) {
    auto req = cookie_request(browser_session, "PUT");
    req.set_header("Content-Type", "text/plain");
    req.body = R"({"display_name":"pwned"})";
    httplib::Response res;
    accounts->handle_update_profile(req, res);
    EXPECT_EQ(status_of(res), 415);
    EXPECT_EQ(store->get_account_by_id("acct-1")->display_name, "Alice");
}

TEST_F(SecurityFixTest, LookalikeUsernamesAreRefused) {
    auto reg = [&](const std::string& name) {
        auto req = json_request(json{{"username", name}, {"password", "another password"}}, "10.8.8.8");
        httplib::Response res;
        accounts->handle_register(req, res);
        return status_of(res);
    };
    EXPECT_EQ(reg("a1ice"), 409);
    EXPECT_EQ(reg("a.lice"), 409);
    EXPECT_EQ(reg("al_ice-"), 409);
    EXPECT_EQ(reg("..."), 400);
    EXPECT_EQ(reg("bob"), 201);
    EXPECT_EQ(reg("b0b"), 409);
}

TEST(UsernameTest, SkeletonMatchesTheChatServer) {
    EXPECT_EQ(username_skeleton("j0sh"), username_skeleton("josh"));
    EXPECT_EQ(username_skeleton("rnary"), username_skeleton("mary"));
    EXPECT_EQ(username_skeleton("vvill"), username_skeleton("will"));
    EXPECT_EQ(username_skeleton("r.n"), username_skeleton("m"));
    EXPECT_NE(username_skeleton("ian"), username_skeleton("lan"));
    EXPECT_TRUE(username_policy_error("Alice").has_value());
    EXPECT_TRUE(username_policy_error("al ice").has_value());
    EXPECT_TRUE(username_policy_error(std::string(65, 'a')).has_value());
    EXPECT_FALSE(username_policy_error("alice.b-c_1").has_value());
}

// ---------------------------------------------------------------------------
// H1 — disabling ends everything, and can be undone
// ---------------------------------------------------------------------------

TEST_F(SecurityFixTest, DisablingKillsAccessTokensAndLoginAndEnableRestoresLogin) {
    auto tokens = desktop_login(browser_session);
    auto access = tokens["access_token"].get<std::string>();

    ASSERT_TRUE(store->disable_account("acct-1"));

    httplib::Request ureq;
    ureq.set_header("Authorization", "Bearer " + access);
    httplib::Response ures;
    oidc->handle_userinfo(ureq, ures);
    EXPECT_EQ(status_of(ures), 401) << "access token of a disabled account still works";

    // Answers exactly like a wrong password.
    EXPECT_EQ(login("10.0.0.1"), 401);
    EXPECT_TRUE(store->list_refresh_tokens_for_account("acct-1").empty());

    ASSERT_TRUE(store->enable_account("acct-1"));
    EXPECT_EQ(login("10.0.0.2"), 200);
    // Nothing that was revoked came back.
    EXPECT_EQ(status_of(refresh(tokens["refresh_token"].get<std::string>())), 400);
}

TEST_F(SecurityFixTest, AdminCanDisableAndEnableButNotThemselves) {
    auto now = now_seconds();
    Account admin;
    admin.id = "admin-1";
    admin.username = "root";
    admin.password_hash = hash_password(kPassword, config.password_hash_iterations);
    admin.is_admin = true;
    admin.created_at = now;
    admin.updated_at = now;
    ASSERT_TRUE(store->create_account(admin));
    auto admin_session = new_browser_session("admin-1");
    AdminHandler admins(*store, *accounts, config);

    auto post = [&](const std::string& path) {
        auto req = cookie_request(admin_session, "POST");
        req.path = path;
        httplib::Response res;
        if (path.ends_with("/disable")) admins.handle_disable_user(req, res);
        else admins.handle_enable_user(req, res);
        return status_of(res);
    };
    EXPECT_EQ(post("/api/admin/users/admin-1/disable"), 400);
    EXPECT_EQ(post("/api/admin/users/acct-1/disable"), 200);
    EXPECT_TRUE(store->get_account_by_id("acct-1")->disabled());
    EXPECT_EQ(post("/api/admin/users/acct-1/enable"), 200);
    EXPECT_FALSE(store->get_account_by_id("acct-1")->disabled());
}

// ---------------------------------------------------------------------------
// H4 — refresh tokens: absolute lifetime, replay, visibility, revocation
// ---------------------------------------------------------------------------

TEST_F(SecurityFixTest, RotationNeverExtendsTheGrant) {
    auto tokens = desktop_login(browser_session);
    auto before = store->list_refresh_tokens_for_account("acct-1");
    ASSERT_EQ(before.size(), 1u);
    EXPECT_EQ(before[0].family_expires_at - before[0].created_at,
              int64_t{86400} * config.refresh_token_max_lifetime_days);

    auto res = refresh(tokens["refresh_token"].get<std::string>());
    ASSERT_EQ(status_of(res), 200) << res.body;
    auto after = store->list_refresh_tokens_for_account("acct-1");
    ASSERT_EQ(after.size(), 1u);
    EXPECT_EQ(after[0].family_id, before[0].family_id);
    EXPECT_EQ(after[0].family_expires_at, before[0].family_expires_at);
    EXPECT_LE(after[0].expires_at, after[0].family_expires_at);
}

TEST_F(SecurityFixTest, AGrantPastItsAbsoluteLifetimeCannotRefresh) {
    auto now = now_seconds();
    RefreshToken rt;
    rt.token = "old-grant-token";
    rt.client_id = "bsfchat-desktop";
    rt.account_id = "acct-1";
    rt.scope = "openid profile";
    rt.family_id = "f00d";
    rt.created_at = now - 91 * 86400;
    rt.family_expires_at = now - 1;       // grant is over...
    rt.expires_at = now + 20 * 86400;     // ...even though the token itself is fresh
    ASSERT_TRUE(store->store_refresh_token(rt));
    EXPECT_EQ(status_of(refresh("old-grant-token")), 400);
}

TEST_F(SecurityFixTest, ReplayingARotatedTokenRevokesTheGrant) {
    auto tokens = desktop_login(browser_session);
    auto first = tokens["refresh_token"].get<std::string>();
    auto res = refresh(first);
    ASSERT_EQ(status_of(res), 200);
    auto second = json::parse(res.body)["refresh_token"].get<std::string>();

    EXPECT_EQ(status_of(refresh(first)), 400);
    EXPECT_EQ(status_of(refresh(second)), 400) << "the successor survived a replay of its parent";
}

TEST_F(SecurityFixTest, RefreshTokensAreVisibleAndRevocable) {
    auto tokens = desktop_login(browser_session);

    httplib::Response lres;
    accounts->handle_list_apps(cookie_request(browser_session), lres);
    ASSERT_EQ(status_of(lres), 200);
    auto apps = json::parse(lres.body);
    ASSERT_EQ(apps.size(), 1u);
    EXPECT_EQ(apps[0]["client_name"], "BSFChat Desktop");

    auto req = cookie_request(browser_session, "DELETE");
    static std::string path;
    path = "/api/user/apps/" + apps[0]["id"].get<std::string>();
    static const std::regex re(R"(/api/user/apps/(.+))");
    ASSERT_TRUE(std::regex_match(path, req.matches, re));
    httplib::Response dres;
    accounts->handle_revoke_app(req, dres);
    EXPECT_EQ(status_of(dres), 200) << dres.body;
    EXPECT_EQ(status_of(refresh(tokens["refresh_token"].get<std::string>())), 400);

    // A grant that is gone (or belongs to someone else) is simply not found.
    httplib::Response again;
    accounts->handle_revoke_app(req, again);
    EXPECT_EQ(status_of(again), 404);
}

TEST_F(SecurityFixTest, PlainLogoutKeepsTheDesktopClientSignedIn) {
    auto tokens = desktop_login(browser_session);
    auto req = cookie_json(browser_session, json::object());
    httplib::Response res;
    accounts->handle_logout(req, res);
    ASSERT_EQ(status_of(res), 200);
    httplib::Response pres;
    accounts->handle_get_profile(cookie_request(browser_session), pres);
    EXPECT_EQ(status_of(pres), 401);
    EXPECT_EQ(status_of(refresh(tokens["refresh_token"].get<std::string>())), 200);
}

TEST_F(SecurityFixTest, SignOutEverywhereEndsEverything) {
    auto other = new_browser_session("acct-1");
    auto tokens = desktop_login(other);
    auto req = cookie_json(browser_session, json{{"everywhere", true}});
    httplib::Response res;
    accounts->handle_logout(req, res);
    ASSERT_EQ(status_of(res), 200);

    for (const auto& s : {browser_session, other}) {
        httplib::Response pres;
        accounts->handle_get_profile(cookie_request(s), pres);
        EXPECT_EQ(status_of(pres), 401);
    }
    EXPECT_EQ(status_of(refresh(tokens["refresh_token"].get<std::string>())), 400);
}

TEST_F(SecurityFixTest, EnablingTwoFactorSignsOutOtherSessions) {
    auto other = new_browser_session("acct-1");

    httplib::Response sres;
    accounts->handle_2fa_setup(cookie_request(browser_session, "POST"), sres);
    ASSERT_EQ(status_of(sres), 200);
    auto secret = json::parse(sres.body)["secret"].get<std::string>();
    auto code = bsfchat::compute_totp(secret, static_cast<uint64_t>(now_seconds()) / 30);

    httplib::Response vres;
    accounts->handle_2fa_verify(cookie_json(browser_session, json{{"code", code}}), vres);
    ASSERT_EQ(status_of(vres), 200) << vres.body;

    httplib::Response mine, theirs;
    accounts->handle_get_profile(cookie_request(browser_session), mine);
    accounts->handle_get_profile(cookie_request(other), theirs);
    EXPECT_EQ(status_of(mine), 200);
    EXPECT_EQ(status_of(theirs), 401);

    // M2: the enrolment code cannot be replayed at the login prompt.
    httplib::Response lres;
    accounts->handle_login(json_request(json{{"username", "alice"}, {"password", kPassword}}), lres);
    auto token = json::parse(lres.body).value("login_token", "");
    ASSERT_FALSE(token.empty());
    httplib::Response tres;
    accounts->handle_login_2fa(json_request(json{{"login_token", token}, {"code", code}}), tres);
    EXPECT_EQ(status_of(tres), 401);
}

// ---------------------------------------------------------------------------
// L5 — nothing usable at rest
// ---------------------------------------------------------------------------

TEST_F(SecurityFixTest, CredentialsAreHashedAtRest) {
    auto tokens = desktop_login(browser_session);
    auto access = tokens["access_token"].get<std::string>();
    auto refresh_token = tokens["refresh_token"].get<std::string>();

    auto sessions = store->list_sessions_for_account("acct-1");
    ASSERT_EQ(sessions.size(), 1u);
    EXPECT_NE(sessions[0].session_id, browser_session);
    EXPECT_EQ(sessions[0].session_id, hash_token(browser_session));

    auto rt = store->get_refresh_token(refresh_token);
    ASSERT_TRUE(rt.has_value());
    EXPECT_EQ(rt->token, hash_token(refresh_token));

    // The stored digest is not itself a credential.
    EXPECT_FALSE(store->get_oidc_access_token(hash_token(access)).has_value());
    EXPECT_FALSE(store->get_refresh_token(hash_token(refresh_token)).has_value());
}

TEST_F(SecurityFixTest, SigningKeyIsNotReadableByOthers) {
    struct stat st {};
    ASSERT_EQ(::stat((keys_dir / "private.pem").c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 0077, 0u) << std::oct << (st.st_mode & 0777);
}

// ---------------------------------------------------------------------------
// M3 / L10 / L2 — profile and session management details
// ---------------------------------------------------------------------------

TEST_F(SecurityFixTest, CurrentSessionCannotBeRevokedByHandle) {
    httplib::Response lres;
    accounts->handle_list_sessions(cookie_request(browser_session), lres);
    auto list = json::parse(lres.body);
    ASSERT_EQ(list.size(), 1u);
    ASSERT_TRUE(list[0]["is_current"].get<bool>());
    EXPECT_EQ(list[0]["session_id"].get<std::string>().find(browser_session.substr(0, 8)),
              std::string::npos) << "the handle leaks the session id";

    auto req = cookie_request(browser_session, "DELETE");
    static std::string path;
    path = "/api/user/sessions/" + list[0]["session_id"].get<std::string>();
    static const std::regex re(R"(/api/user/sessions/(.+))");
    ASSERT_TRUE(std::regex_match(path, req.matches, re));
    httplib::Response res;
    accounts->handle_revoke_session(req, res);
    EXPECT_EQ(status_of(res), 400);
}

TEST_F(SecurityFixTest, ProfileFieldsAreTypedAndBounded) {
    auto put = [&](const json& body) {
        auto req = cookie_json(browser_session, body);
        req.method = "PUT";
        httplib::Response res;
        accounts->handle_update_profile(req, res);
        return status_of(res);
    };
    EXPECT_EQ(put(json{{"display_name", 5}}), 400);
    EXPECT_EQ(put(json{{"display_name", std::string(129, 'x')}}), 400);
    EXPECT_EQ(put(json{{"display_name", "Alice\nAdmin"}}), 400);
    EXPECT_EQ(put(json{{"display_name", "Alice\xE2\x80\xAEnimda"}}), 400); // RLO
    EXPECT_EQ(put(json{{"avatar_url", "http://x.example/a.png"}}), 400);
    EXPECT_EQ(put(json{{"avatar_url", "https://x.example/a'.png"}}), 400);
    EXPECT_EQ(put(json{{"email", "not an email"}}), 400);
    EXPECT_EQ(put(json{{"display_name", "Äliçe 🎮"}, {"avatar_url", "https://x.example/a.png"}}), 200);
}

TEST_F(SecurityFixTest, TakenEmailOnProfileIsAnErrorNotASilentSuccess) {
    auto now = now_seconds();
    Account bob;
    bob.id = "acct-2";
    bob.username = "bob";
    bob.email = "bob@example.com";
    bob.password_hash = hash_password(kPassword, config.password_hash_iterations);
    bob.created_at = now;
    bob.updated_at = now;
    ASSERT_TRUE(store->create_account(bob));

    auto req = cookie_json(browser_session, json{{"email", "bob@example.com"}});
    req.method = "PUT";
    httplib::Response res;
    accounts->handle_update_profile(req, res);
    EXPECT_EQ(status_of(res), 409);
    EXPECT_EQ(store->get_account_by_id("acct-1")->email, "alice@example.com");
}

// ---------------------------------------------------------------------------
// L7 — security headers
// ---------------------------------------------------------------------------

TEST(SecurityHeadersTest, PagesCannotBeFramedOrRunInlineScript) {
    std::string csp;
    bool nosniff = false;
    for (const auto& [name, value] : default_security_headers()) {
        if (name == "Content-Security-Policy") csp = value;
        if (name == "X-Content-Type-Options") nosniff = value == "nosniff";
    }
    EXPECT_TRUE(nosniff);
    EXPECT_NE(csp.find("frame-ancestors 'none'"), std::string::npos);
    auto script = csp.substr(csp.find("script-src"));
    script = script.substr(0, script.find(';'));
    EXPECT_EQ(script, "script-src 'self'");
    // form-action would break the consent page's redirect to the loopback URI.
    EXPECT_EQ(csp.find("form-action"), std::string::npos);
}

// ---------------------------------------------------------------------------
// Schema v2 migration on a v1 database
// ---------------------------------------------------------------------------

TEST(SchemaMigrationV2Test, HashesCredentialsOnceAndKeepsThemWorking) {
    auto db_path = bsfchat::test::unique_temp_file("bsfchat_id_migration_v2", ".db");
    std::filesystem::remove(db_path);
    auto now = now_seconds();

    // A v1 database as the previous release leaves it.
    {
        IdentityStore v0(db_path.string());
        v0.initialize(); // creates v2; roll the relevant parts back to v1 below
    }
    {
        sqlite3* raw = nullptr;
        ASSERT_EQ(sqlite3_open(db_path.c_str(), &raw), SQLITE_OK);
        auto run = [&](const std::string& sql) {
            char* err = nullptr;
            ASSERT_EQ(sqlite3_exec(raw, sql.c_str(), nullptr, nullptr, &err), SQLITE_OK) << (err ? err : "");
        };
        run("DROP TABLE refresh_tokens");
        run("CREATE TABLE refresh_tokens (token TEXT PRIMARY KEY, client_id TEXT NOT NULL,"
            " account_id TEXT NOT NULL, scope TEXT, expires_at INTEGER NOT NULL)");
        run("DROP TABLE accounts");
        run("CREATE TABLE accounts (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE,"
            " password_hash TEXT, display_name TEXT, avatar_url TEXT, is_admin BOOLEAN DEFAULT FALSE,"
            " created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)");
        run("DROP TABLE user_totp");
        run("CREATE TABLE user_totp (account_id TEXT PRIMARY KEY, secret TEXT NOT NULL,"
            " enabled INTEGER NOT NULL DEFAULT 0, backup_codes TEXT, created_at INTEGER NOT NULL DEFAULT 0)");
        run("INSERT INTO accounts (id, username, created_at, updated_at) VALUES ('a1', 'Alice', 0, 0)");
        run("INSERT INTO accounts (id, username, created_at, updated_at) VALUES ('a2', 'al1ce', 0, 0)");
        run("INSERT INTO sessions (session_id, account_id, created_at, expires_at, token_type) VALUES"
            " ('raw-session', 'a1', " + std::to_string(now) + ", " + std::to_string(now + 3600) + ", 'session')");
        run("INSERT INTO refresh_tokens VALUES ('raw-refresh', 'c1', 'a1', 'openid', " +
            std::to_string(now + 86400) + ")");
        run("INSERT INTO oauth_clients VALUES ('c1', 'plain-secret', 'C', '[]', 0)");
        run("PRAGMA user_version = 1");
        sqlite3_close(raw);
    }

    for (int open = 0; open < 2; ++open) { // the second open must change nothing
        IdentityStore store(db_path.string());
        ASSERT_NO_THROW(store.initialize());

        auto session = store.get_browser_session("raw-session");
        ASSERT_TRUE(session.has_value()) << "open " << open;
        EXPECT_EQ(session->session_id, hash_token("raw-session"));

        auto rt = store.get_refresh_token("raw-refresh");
        ASSERT_TRUE(rt.has_value()) << "open " << open;
        EXPECT_FALSE(rt->family_id.empty());
        EXPECT_EQ(rt->family_expires_at, now + 86400 + 60 * 86400);

        auto client = store.get_oauth_client("c1");
        ASSERT_TRUE(client.has_value());
        EXPECT_TRUE(client_secret_matches(client->client_secret, "plain-secret"));

        // Pre-policy names keep working, and are skeleton-indexed.
        EXPECT_TRUE(store.get_account_by_username("Alice").has_value());
        EXPECT_TRUE(store.find_account_by_username_skeleton(username_skeleton("alice")).has_value());
        EXPECT_FALSE(store.get_account_by_id("a1")->disabled());
    }
    std::filesystem::remove(db_path);
    std::filesystem::remove(db_path.string() + "-wal");
    std::filesystem::remove(db_path.string() + "-shm");
}
