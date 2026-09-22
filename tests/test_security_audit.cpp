// Proof tests for docs/security-audit-2026-09.md.
//
// Every test here asserts the behaviour the service SHOULD have. On the
// audited revision (origin/main a6b6f6b) each of them FAILS, and the failure
// is the proof of the finding named in the test's comment. When a finding is
// fixed, its test starts passing and can be moved into the regular suite.
//
// These are deliberately built into a separate executable,
// `identity_security_audit_tests`, which is NOT registered with ctest, so the
// normal `ctest` run (and CI) stays green while the findings are open. Run it
// by hand:
//
//     ./build/tests/identity_security_audit_tests
//
// Like test_auth_flows.cpp, these drive the handlers directly with synthetic
// httplib::Request objects. No socket is opened and nothing is started.

#include <gtest/gtest.h>

#include "api/AccountHandler.h"
#include "api/OidcHandler.h"
#include "core/Config.h"
#include "core/WebUtil.h"
#include "crypto/PasswordHash.h"
#include "crypto/Totp.h"
#include "store/IdentityStore.h"
#include "TempPaths.h"

#include <bsfchat/JwtUtils.h>
#include <nlohmann/json.hpp>
#include <openssl/sha.h>

#include <chrono>
#include <filesystem>
#include <regex>
#include <set>

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

// Decodes the (unverified) payload of a compact JWS.
json jwt_payload(const std::string& jwt) {
    auto first = jwt.find('.');
    auto second = jwt.find('.', first + 1);
    auto bytes = bsfchat::base64url_decode(jwt.substr(first + 1, second - first - 1));
    return json::parse(std::string(bytes.begin(), bytes.end()));
}

class SecurityAudit : public ::testing::Test {
protected:
    void SetUp() override {
        keys_dir = bsfchat::test::unique_temp_dir("bsfchat_id_audit_keys");

        config.issuer_url = "https://id.example";
        config.password_hash_iterations = kMinPbkdf2Iterations;
        config.totp_max_attempts = 3;
        config.login_max_failures = 4;
        config.login_rate_limit = 1000; // keep the request limiter out of the way
        config.cookie_secure = true;

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

    std::string new_browser_session(const std::string& account_id) {
        static int n = 0;
        auto id = "browser-session-" + std::to_string(++n);
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

    httplib::Request cookie_request(const std::string& session) {
        httplib::Request req;
        req.method = "GET";
        req.remote_addr = "10.0.0.1";
        req.set_header("Cookie", "session=" + session);
        return req;
    }

    // GET /authorize; returns the response (200 = consent page rendered).
    httplib::Response authorize(const std::string& session,
                                const std::map<std::string, std::string>& extra = {}) {
        auto req = cookie_request(session);
        req.params.emplace("client_id", "bsfchat-desktop");
        req.params.emplace("redirect_uri", kRedirect);
        req.params.emplace("response_type", "code");
        req.params.emplace("scope", "openid profile"); // what the desktop client asks for
        req.params.emplace("state", "xyz");
        req.params.emplace("code_challenge", s256_challenge(kVerifier));
        req.params.emplace("code_challenge_method", "S256");
        for (const auto& [k, v] : extra) req.params.emplace(k, v);
        httplib::Response res;
        oidc->handle_authorize(req, res);
        return res;
    }

    // Full desktop flow: authorize, consent, token. Returns the token response.
    json desktop_login(const std::string& session,
                       const std::map<std::string, std::string>& extra = {}) {
        auto res = authorize(session, extra);
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
        EXPECT_FALSE(code.empty());

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

    std::filesystem::path keys_dir;
    Config config;
    std::unique_ptr<IdentityStore> store;
    std::unique_ptr<KeyManager> key_manager;
    std::unique_ptr<AccountHandler> accounts;
    std::unique_ptr<OidcHandler> oidc;
    std::string browser_session;
};

} // namespace

// ---------------------------------------------------------------------------
// C1 — one id_token is a sign-in credential on EVERY chat server.
//
// The audience is always the desktop client_id, never the chat server the
// user is signing in to, and there is no way for the client to ask for
// anything narrower (RFC 8707 `resource` is ignored). So an id_token handed to
// a hostile server verifies at every other server with the default
// `identity.client_id = "bsfchat-desktop"`.
// ---------------------------------------------------------------------------
TEST_F(SecurityAudit, C1_IdTokenAudienceIsBoundToTheChatServer) {
    auto tokens = desktop_login(browser_session, {{"resource", "https://evil-chat.example"}});
    auto id_token = tokens["id_token"].get<std::string>();

    // What chat.bsfchat.com runs on every m.login.token and link_identity:
    auto at_victim_server = bsfchat::jwt_verify(id_token, key_manager->get_public_key(),
                                                config.issuer_url, "bsfchat-desktop");
    EXPECT_FALSE(at_victim_server.has_value())
        << "an id_token requested for https://evil-chat.example verifies at a different "
           "chat server; aud=" << jwt_payload(id_token)["aud"];
}

// ---------------------------------------------------------------------------
// M4 — the id_token discloses the email address without the email scope.
// ---------------------------------------------------------------------------
TEST_F(SecurityAudit, M4_IdTokenOmitsEmailWithoutEmailScope) {
    auto tokens = desktop_login(browser_session); // scope = "openid profile"
    auto claims = jwt_payload(tokens["id_token"].get<std::string>());
    EXPECT_FALSE(claims.contains("email"))
        << "email released to every relying party: " << claims["email"];
}

// ---------------------------------------------------------------------------
// L-nonce — `nonce` is silently dropped (OIDC Core 3.1.2.1 / 3.1.3.7).
// ---------------------------------------------------------------------------
TEST_F(SecurityAudit, Lnonce_NonceIsEchoedIntoIdToken) {
    auto tokens = desktop_login(browser_session, {{"nonce", "n-0S6_WzA2Mj"}});
    auto claims = jwt_payload(tokens["id_token"].get<std::string>());
    EXPECT_EQ(claims.value("nonce", ""), "n-0S6_WzA2Mj");
}

// ---------------------------------------------------------------------------
// H1 — "disable user" does not disable anything that is already signed in.
// store->disable_account() is exactly what POST /api/admin/users/{id}/disable
// calls (AdminHandler.cpp:89).
// ---------------------------------------------------------------------------
TEST_F(SecurityAudit, H1_DisabledAccountCannotKeepMintingIdTokens) {
    auto tokens = desktop_login(browser_session);
    auto refresh_token = tokens["refresh_token"].get<std::string>();

    ASSERT_TRUE(store->disable_account("acct-1"));

    auto rres = refresh(refresh_token);
    EXPECT_NE(status_of(rres), 200)
        << "refresh grant still mints a fresh id_token for a disabled account: " << rres.body;

    httplib::Response pres;
    accounts->handle_get_profile(cookie_request(browser_session), pres);
    EXPECT_EQ(status_of(pres), 401) << "browser session of a disabled account still valid";

    auto ares = authorize(browser_session);
    EXPECT_NE(status_of(ares), 200) << "disabled account can still start a new authorization";
}

// ---------------------------------------------------------------------------
// H2b — changing the password leaves every other credential alive.
// ---------------------------------------------------------------------------
TEST_F(SecurityAudit, H2b_PasswordChangeRevokesOtherSessionsAndRefreshTokens) {
    auto stolen_session = new_browser_session("acct-1");
    auto tokens = desktop_login(stolen_session);
    auto stolen_refresh = tokens["refresh_token"].get<std::string>();

    auto req = json_request(json{{"old_password", kPassword}, {"new_password", "a brand new password"}});
    req.method = "PUT";
    req.set_header("Cookie", "session=" + browser_session);
    httplib::Response res;
    accounts->handle_update_profile(req, res);
    ASSERT_EQ(status_of(res), 200) << res.body;

    httplib::Response pres;
    accounts->handle_get_profile(cookie_request(stolen_session), pres);
    EXPECT_EQ(status_of(pres), 401) << "another browser session survived a password change";

    EXPECT_NE(status_of(refresh(stolen_refresh)), 200)
        << "a refresh token survived a password change";
}

// ---------------------------------------------------------------------------
// M3 — the session list cannot be used to revoke a session: it returns an
// 8-character prefix, and DELETE requires the full id.
// ---------------------------------------------------------------------------
TEST_F(SecurityAudit, M3_SessionsCanBeRevokedFromTheList) {
    auto other = new_browser_session("acct-1");
    (void)other;

    httplib::Response lres;
    accounts->handle_list_sessions(cookie_request(browser_session), lres);
    ASSERT_EQ(status_of(lres), 200);
    std::string listed;
    for (const auto& s : json::parse(lres.body)) {
        if (!s["is_current"].get<bool>()) listed = s["session_id"].get<std::string>();
    }
    ASSERT_FALSE(listed.empty());

    auto req = cookie_request(browser_session);
    req.method = "DELETE";
    // The handler reads req.matches[1]; the matched string must outlive it.
    static std::string path;
    path = "/api/user/sessions/" + listed;
    static const std::regex re(R"(/api/user/sessions/(.+))");
    ASSERT_TRUE(std::regex_match(path, req.matches, re));
    httplib::Response res;
    accounts->handle_revoke_session(req, res);
    EXPECT_EQ(status_of(res), 200) << "revoking the id the list returned (" << listed
                                   << ") fails: " << res.body;
}

// ---------------------------------------------------------------------------
// H3 — login CSRF. /api/login parses any body as JSON regardless of
// Content-Type, so a cross-site <form enctype="text/plain"> can submit it
// without a preflight and the response's Set-Cookie signs the victim's browser
// in to the attacker's account.
//   <input name='{"username":"mallory","password":"xxxxxxxx","x":"' value='"}'>
// serialises to  {"username":"mallory","password":"xxxxxxxx","x":"="}\r\n
// ---------------------------------------------------------------------------
TEST_F(SecurityAudit, H3_LoginRejectsNonJsonContentType) {
    httplib::Request req;
    req.method = "POST";
    req.remote_addr = "10.0.0.1";
    req.set_header("Content-Type", "text/plain");
    req.set_header("Origin", "https://attacker.example");
    req.body = std::string(R"({"username":"alice","password":")") + kPassword + R"(","x":"="})" "\r\n";
    httplib::Response res;
    accounts->handle_login(req, res);
    EXPECT_NE(status_of(res), 200) << "text/plain cross-site login accepted";
    EXPECT_TRUE(header_of(res, "Set-Cookie").empty())
        << "session cookie set from a cross-site form: " << header_of(res, "Set-Cookie");
}

// ---------------------------------------------------------------------------
// H3b — usernames are not normalised: case variants and homoglyphs are
// distinct accounts, which is what makes H3's consent page ("sign you in as
// alice") and the chat-side display name unreliable.
// ---------------------------------------------------------------------------
TEST_F(SecurityAudit, H3b_ConfusableUsernamesAreRefused) {
    for (const std::string name : {"Alice", "\xD0\xB0lice" /* Cyrillic a */, "alice​"}) {
        auto req = json_request(json{{"username", name}, {"password", "another password"}}, "10.9.9.9");
        httplib::Response res;
        accounts->handle_register(req, res);
        EXPECT_NE(status_of(res), 201) << "registered a username confusable with 'alice'";
    }
}

// ---------------------------------------------------------------------------
// H2 — rate limits and lockouts are keyed on the TCP peer. Behind the shipped
// nginx (deploy/nginx/bsfchat.conf.template) every request arrives from the
// same docker gateway address, and X-Forwarded-For is ignored. So a stranger's
// failures lock out everybody's login.
// ---------------------------------------------------------------------------
TEST_F(SecurityAudit, H2_OneClientsFailuresDoNotLockOutEveryone) {
    const std::string proxy = "172.18.0.1"; // what the container sees for every request
    for (int i = 0; i < config.login_max_failures; ++i) {
        auto req = json_request(json{{"username", "nobody-" + std::to_string(i)}, {"password", "x"}}, proxy);
        req.set_header("X-Forwarded-For", "203.0.113.66");
        httplib::Response res;
        accounts->handle_login(req, res);
    }

    auto req = json_request(json{{"username", "alice"}, {"password", kPassword}}, proxy);
    req.set_header("X-Forwarded-For", "198.51.100.7");
    httplib::Response res;
    accounts->handle_login(req, res);
    EXPECT_EQ(status_of(res), 200) << "alice is locked out by someone else's failures: " << res.body;
}

// ---------------------------------------------------------------------------
// M1 — stored XSS in the account portal. server_url validation allows `'`,
// and profile.html interpolates it into an inline onclick="removeServer('...')"
// after escapeHtml(), which does not escape quotes. Any "openid" access token
// (i.e. any relying party the user ever signed in to) can write it.
// ---------------------------------------------------------------------------
TEST_F(SecurityAudit, M1_ServerUrlCannotCarryScript) {
    auto tokens = desktop_login(browser_session);
    auto req = json_request(json{{"server_url", "https://x.example/');alert(document.domain);//"},
                                 {"server_name", "Click remove"}});
    req.set_header("Authorization", "Bearer " + tokens["access_token"].get<std::string>());
    httplib::Response res;
    accounts->handle_add_server(req, res);
    EXPECT_EQ(status_of(res), 400) << "script-bearing server_url stored: " << res.body;
}

// ---------------------------------------------------------------------------
// M2 — a TOTP code can be replayed. Nothing records the last accepted step,
// so the same six digits sign in again for up to ~90 seconds.
// ---------------------------------------------------------------------------
TEST_F(SecurityAudit, M2_TotpCodeCannotBeReplayed) {
    auto secret = bsfchat::generate_totp_secret();
    store->set_totp_secret("acct-1", secret, {"BACKUPAA"});
    store->enable_totp("acct-1");
    auto code = bsfchat::compute_totp(secret, static_cast<uint64_t>(now_seconds()) / 30);

    auto login_with = [&](const std::string& ip) {
        httplib::Response lres;
        accounts->handle_login(json_request(json{{"username", "alice"}, {"password", kPassword}}, ip), lres);
        auto token = json::parse(lres.body).value("login_token", "");
        httplib::Response res;
        accounts->handle_login_2fa(json_request(json{{"login_token", token}, {"code", code}}, ip), res);
        return status_of(res);
    };

    ASSERT_EQ(login_with("10.0.0.2"), 200);
    EXPECT_NE(login_with("10.0.0.3"), 200) << "the same TOTP code was accepted twice";
}

// ---------------------------------------------------------------------------
// M2b — no per-account limit on second-factor guesses. The login token burns
// after totp_max_attempts, but a password holder just asks for another one
// from another address. After many wrong codes the account should be locked.
// ---------------------------------------------------------------------------
TEST_F(SecurityAudit, M2b_SecondFactorGuessingIsLimitedPerAccount) {
    auto secret = bsfchat::generate_totp_secret();
    store->set_totp_secret("acct-1", secret, {"BACKUPAA"});
    store->enable_totp("acct-1");

    std::set<std::string> live;
    auto step = static_cast<uint64_t>(now_seconds()) / 30;
    for (int d = -2; d <= 2; ++d) live.insert(bsfchat::compute_totp(secret, step + d));
    std::string wrong = "000000";
    while (live.count(wrong)) wrong[5]++;

    int wrong_guesses = 0;
    for (int ip = 1; ip <= 4; ++ip) {
        auto addr = "192.0.2." + std::to_string(ip);
        httplib::Response lres;
        accounts->handle_login(json_request(json{{"username", "alice"}, {"password", kPassword}}, addr), lres);
        auto token = json::parse(lres.body).value("login_token", "");
        for (int i = 0; i < config.totp_max_attempts; ++i) {
            httplib::Response r;
            accounts->handle_login_2fa(json_request(json{{"login_token", token}, {"code", wrong}}, addr), r);
            ++wrong_guesses;
        }
    }
    ASSERT_EQ(wrong_guesses, 12);

    auto addr = "192.0.2.99";
    httplib::Response lres;
    accounts->handle_login(json_request(json{{"username", "alice"}, {"password", kPassword}}, addr), lres);
    EXPECT_NE(status_of(lres), 200)
        << "after " << wrong_guesses << " wrong second-factor codes from rotating addresses the "
           "account still hands out fresh login tokens";
}

// ---------------------------------------------------------------------------
// L-enum — registering with an email that is already in use returns a 500,
// distinct from success, which enumerates email addresses.
// ---------------------------------------------------------------------------
TEST_F(SecurityAudit, Lenum_TakenEmailIsNotDistinguishableAsServerError) {
    auto req = json_request(json{{"username", "bob"}, {"password", "bob password"},
                                 {"email", "alice@example.com"}}, "10.7.7.7");
    httplib::Response res;
    accounts->handle_register(req, res);
    EXPECT_NE(status_of(res), 500) << res.body;
}
