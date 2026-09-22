// The id_token is bound to ONE chat server.
//
// Identity audit 2026-09 (docs/security-audit-2026-09.md on the audit branch),
// finding C1: every id_token carried aud=bsfchat-desktop — the desktop
// client's id — never the chat server being signed in to, and every chat
// server checked for that same value. So any chat server using this provider,
// a hostile one included, received each user's id_token at sign-in and could
// replay it against chat.bsfchat.com as that user. Through the chat server's
// link_identity endpoint the replay became permanent: the victim's identity
// linked to the ATTACKER's account, insert-only, no unlink.
//
// The fix spans three repositories. Here: the client names the server it is
// signing in to as an RFC 8707 `resource`; we validate it, carry it through
// the consent request and the code, name it on the consent page, and put it
// — and only it — in `aud`, with the client in `azp`. The chat server then
// accepts only its own URL.
//
// The first three tests are the audit's proof tests (C1, M4, L-nonce),
// unchanged in what they assert; each failed on a6b6f6b. The rest pin the
// edges of the new contract, and M5 (the server-list API), which fed C1 a
// list of servers to auto-connect to.
//
// Like test_auth_flows.cpp these drive the handlers directly with synthetic
// httplib::Request objects. No socket is opened.

#include <gtest/gtest.h>

#include "api/AccountHandler.h"
#include "api/OidcHandler.h"
#include "core/Config.h"
#include "core/ClientRegistration.h"
#include "core/WebUtil.h"
#include "crypto/PasswordHash.h"
#include "store/IdentityStore.h"
#include "TempPaths.h"

#include <bsfchat/JwtUtils.h>
#include <nlohmann/json.hpp>
#include <openssl/sha.h>
#include <sqlite3.h>

#include <chrono>
#include <filesystem>
#include <map>

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
const std::string kChat = "https://chat.example";

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

int status_of(const httplib::Response& res) { return res.status < 0 ? 200 : res.status; }

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

json jwt_payload(const std::string& jwt) {
    auto first = jwt.find('.');
    auto second = jwt.find('.', first + 1);
    auto bytes = bsfchat::base64url_decode(jwt.substr(first + 1, second - first - 1));
    return json::parse(std::string(bytes.begin(), bytes.end()));
}

using Params = std::multimap<std::string, std::string>;

class TokenAudienceTest : public ::testing::Test {
protected:
    void SetUp() override {
        keys_dir = bsfchat::test::unique_temp_dir("bsfchat_id_audience_keys");

        config.issuer_url = "https://id.example";
        config.password_hash_iterations = kMinPbkdf2Iterations;
        config.login_rate_limit = 1000;
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
        account.password_hash = hash_password("correct horse battery", config.password_hash_iterations);
        account.created_at = now;
        account.updated_at = now;
        ASSERT_TRUE(store->create_account(account));

        OAuthClient desktop;
        desktop.client_id = "bsfchat-desktop";
        desktop.name = "BSFChat Desktop";
        // Exactly what IdentityServer seeds, so the iOS private-use callback
        // is registered here the same way it is in production.
        desktop.redirect_uris = first_party_redirect_uris();
        desktop.created_at = now;
        ASSERT_TRUE(store->create_oauth_client(desktop));

        // Some other relying party an admin registered: a bot dashboard, a
        // web app. Confidential, so no PKCE needed.
        OAuthClient other;
        other.client_id = "web-app";
        other.client_secret = "s3cr3t-value";
        other.name = "Web App";
        other.redirect_uris = R"(["https://app.example.com/cb"])";
        other.created_at = now;
        ASSERT_TRUE(store->create_oauth_client(other));

        Session s;
        s.session_id = browser_session;
        s.account_id = "acct-1";
        s.created_at = now;
        s.expires_at = now + 86400;
        s.token_type = token_type::kBrowserSession;
        ASSERT_TRUE(store->create_session(s));
    }

    void TearDown() override { std::filesystem::remove_all(keys_dir); }

    httplib::Request cookie_request() {
        httplib::Request req;
        req.method = "GET";
        req.remote_addr = "10.0.0.1";
        req.set_header("Cookie", "session=" + browser_session);
        return req;
    }

    // GET /authorize as the desktop client; `extra` may repeat a key.
    httplib::Response authorize(const Params& extra = {}, bool signed_in = true,
                                const std::string& scope = "openid profile") {
        httplib::Request req = signed_in ? cookie_request() : httplib::Request{};
        req.params.emplace("client_id", "bsfchat-desktop");
        req.params.emplace("redirect_uri", kRedirect);
        req.params.emplace("response_type", "code");
        req.params.emplace("scope", scope);
        req.params.emplace("state", "xyz");
        req.params.emplace("code_challenge", s256_challenge(kVerifier));
        req.params.emplace("code_challenge_method", "S256");
        for (const auto& [k, v] : extra) req.params.emplace(k, v);
        httplib::Response res;
        oidc->handle_authorize(req, res);
        return res;
    }

    std::string approve(const httplib::Response& consent_page) {
        const std::string marker = "name=\"consent_token\" value=\"";
        auto pos = consent_page.body.find(marker);
        EXPECT_NE(pos, std::string::npos) << consent_page.body;
        if (pos == std::string::npos) return "";
        auto start = pos + marker.size();
        auto consent = consent_page.body.substr(start, consent_page.body.find('"', start) - start);

        auto decision = form_request({{"consent_token", consent}, {"approve", "true"}});
        decision.set_header("Cookie", "session=" + browser_session);
        httplib::Response dres;
        oidc->handle_authorize_decision(decision, dres);
        return query_param(header_of(dres, "Location"), "code");
    }

    httplib::Response redeem(const std::string& code, const std::map<std::string, std::string>& extra = {}) {
        std::map<std::string, std::string> params{{"grant_type", "authorization_code"},
                                                  {"code", code},
                                                  {"redirect_uri", kRedirect},
                                                  {"client_id", "bsfchat-desktop"},
                                                  {"code_verifier", kVerifier}};
        for (const auto& [k, v] : extra) params[k] = v;
        auto treq = form_request(params);
        httplib::Response tres;
        oidc->handle_token(treq, tres);
        return tres;
    }

    json desktop_login(const Params& extra = {}, const std::string& scope = "openid profile") {
        auto res = authorize(extra, true, scope);
        EXPECT_EQ(status_of(res), 200) << res.body;
        auto code = approve(res);
        EXPECT_FALSE(code.empty());
        auto tres = redeem(code);
        EXPECT_EQ(status_of(tres), 200) << tres.body;
        return json::parse(tres.body, nullptr, false);
    }

    std::filesystem::path keys_dir;
    Config config;
    std::unique_ptr<IdentityStore> store;
    std::unique_ptr<KeyManager> key_manager;
    std::unique_ptr<AccountHandler> accounts;
    std::unique_ptr<OidcHandler> oidc;
    const std::string browser_session = "browser-session-1";
};

} // namespace

// ---------------------------------------------------------------------------
// The audit's proof tests.
// ---------------------------------------------------------------------------

// C1. A token requested for evil-chat.example must not verify at a different
// chat server — neither at one checking the legacy client_id audience (what
// every server did), nor at one checking its own URL (what they do now).
TEST_F(TokenAudienceTest, C1_IdTokenAudienceIsBoundToTheChatServer) {
    auto tokens = desktop_login({{"resource", "https://evil-chat.example"}});
    auto id_token = tokens["id_token"].get<std::string>();
    const auto key = key_manager->get_public_key();

    EXPECT_FALSE(bsfchat::jwt_verify(id_token, key, config.issuer_url, "bsfchat-desktop"))
        << "an id_token requested for https://evil-chat.example verifies at a different "
           "chat server; aud=" << jwt_payload(id_token)["aud"];
    EXPECT_FALSE(bsfchat::jwt_verify(id_token, key, config.issuer_url, kChat));

    // ...and it is good exactly where it was asked for.
    auto at_evil = bsfchat::jwt_verify(id_token, key, config.issuer_url, "https://evil-chat.example");
    ASSERT_TRUE(at_evil.has_value());
    EXPECT_EQ(at_evil->aud, "https://evil-chat.example");
}

// M4. With scope "openid profile" — what the desktop client asks for — the
// email address is not released.
TEST_F(TokenAudienceTest, M4_IdTokenOmitsEmailWithoutEmailScope) {
    auto claims = jwt_payload(desktop_login({{"resource", kChat}})["id_token"].get<std::string>());
    EXPECT_FALSE(claims.contains("email")) << "email released to every relying party: " << claims["email"];
    EXPECT_EQ(claims.value("name", ""), "Alice");  // profile still granted
}

// L-nonce. The nonce is echoed (OIDC Core 3.1.3.7).
TEST_F(TokenAudienceTest, Lnonce_NonceIsEchoedIntoIdToken) {
    auto claims = jwt_payload(
        desktop_login({{"resource", kChat}, {"nonce", "n-0S6_WzA2Mj"}})["id_token"].get<std::string>());
    EXPECT_EQ(claims.value("nonce", ""), "n-0S6_WzA2Mj");
}

// ---------------------------------------------------------------------------
// The contract around `resource`.
// ---------------------------------------------------------------------------

// The audience is written in the one canonical spelling the chat server also
// derives from its own configuration; otherwise a correctly configured
// deployment fails closed on a trailing slash.
TEST_F(TokenAudienceTest, ResourceIsCanonicalisedIntoAudAndClientIsInAzp) {
    auto claims = jwt_payload(
        desktop_login({{"resource", "HTTPS://Chat.Example:443/"}})["id_token"].get<std::string>());
    EXPECT_EQ(claims["aud"], kChat);  // a single string, not [resource, client_id]
    EXPECT_EQ(claims.value("azp", ""), "bsfchat-desktop");
}

TEST_F(TokenAudienceTest, IdTokenLivesFiveMinutes) {
    auto claims = jwt_payload(desktop_login({{"resource", kChat}})["id_token"].get<std::string>());
    EXPECT_LE(claims["exp"].get<int64_t>() - claims["iat"].get<int64_t>(), 300);
}

// Each of these is refused with invalid_target on the client's own redirect —
// never a consent page, so never a code.
TEST_F(TokenAudienceTest, UnacceptableResourceIsRefusedBeforeConsent) {
    const std::vector<Params> bad = {
        {{"resource", "http://chat.example"}},                     // clear text off loopback
        {{"resource", "https://real.example@evil.example"}},       // userinfo
        {{"resource", "https://chat.example#x"}},                  // fragment
        {{"resource", "chat.example"}},                            // not absolute
        {{"resource", ""}},                                        // names nothing
        {{"resource", kChat}, {"resource", "https://other.example"}},  // a token good at two servers
    };
    for (const auto& extra : bad) {
        auto res = authorize(extra);
        EXPECT_EQ(res.body.find("consent_token"), std::string::npos)
            << "consent offered for resource=" << extra.begin()->second;
        EXPECT_EQ(query_param(header_of(res, "Location"), "error"), "invalid_target")
            << "resource=" << extra.begin()->second;
    }

    // Development: http to loopback is fine.
    auto dev = authorize({{"resource", "http://localhost:8448"}});
    EXPECT_EQ(status_of(dev), 200) << dev.body;
}

TEST_F(TokenAudienceTest, UnacceptableNonceIsRefused) {
    for (const std::string nonce : {std::string("has space"), std::string("ctl\x01"),
                                    std::string(257, 'a')}) {
        auto res = authorize({{"resource", kChat}, {"nonce", nonce}});
        EXPECT_EQ(query_param(header_of(res, "Location"), "error"), "invalid_request");
    }
}

// The person approving the sign-in sees which server it is for.
TEST_F(TokenAudienceTest, ConsentPageNamesTheChatServer) {
    auto res = authorize({{"resource", "https://chat.example:8448"}});
    ASSERT_EQ(status_of(res), 200);
    EXPECT_NE(res.body.find("sign you in to <strong>chat.example:8448</strong>"), std::string::npos)
        << res.body;
    EXPECT_NE(res.body.find("Chat server: https://chat.example:8448"), std::string::npos);
}

// Signing in to the identity provider mid-flow goes through login.html and
// back to /authorize. Dropping `resource` there would silently downgrade the
// sign-in to the legacy audience.
TEST_F(TokenAudienceTest, LoginRedirectCarriesResourceAndNonce) {
    auto res = authorize({{"resource", kChat}, {"nonce", "abc"}}, /*signed_in=*/false);
    auto location = header_of(res, "Location");
    ASSERT_EQ(location.rfind("/login.html", 0), 0u) << location;
    EXPECT_EQ(query_param(location, "resource"), kChat);
    EXPECT_EQ(query_param(location, "nonce"), "abc");
}

// RFC 8707 at the token endpoint: repeating the resource is allowed, naming a
// different one is refused, and the audience always comes from the code.
TEST_F(TokenAudienceTest, TokenEndpointResourceMustMatchTheGrant) {
    auto code = approve(authorize({{"resource", kChat}}));
    auto mismatch = redeem(code, {{"resource", "https://evil.example"}});
    EXPECT_EQ(status_of(mismatch), 400);
    EXPECT_EQ(json::parse(mismatch.body).value("error", ""), "invalid_target");

    // A grant that named no server cannot be widened into one that does.
    auto legacy_code = approve(authorize());
    EXPECT_EQ(status_of(redeem(legacy_code, {{"resource", kChat}})), 400);

    auto code2 = approve(authorize({{"resource", kChat}}));
    auto ok = redeem(code2, {{"resource", "https://CHAT.example/"}});
    ASSERT_EQ(status_of(ok), 200) << ok.body;
    EXPECT_EQ(jwt_payload(json::parse(ok.body)["id_token"].get<std::string>())["aud"], kChat);
}

// The transition: an old client names no server and still gets the legacy
// audience, so it keeps signing in to servers that have not been upgraded.
// Upgraded servers refuse this token (server/tests/test_account_linking.cpp).
TEST_F(TokenAudienceTest, WithoutResourceTheLegacyAudienceIsKept) {
    auto claims = jwt_payload(desktop_login()["id_token"].get<std::string>());
    EXPECT_EQ(claims["aud"], "bsfchat-desktop");
    EXPECT_FALSE(claims.contains("nonce"));
}

// A refresh token is not bound to a server, so what it mints must not be a
// sign-in anywhere upgraded: the legacy audience, no nonce.
TEST_F(TokenAudienceTest, RefreshedIdTokenIsNotAudiencedToAServer) {
    auto tokens = desktop_login({{"resource", kChat}, {"nonce", "n1"}});
    auto req = form_request({{"grant_type", "refresh_token"},
                             {"refresh_token", tokens["refresh_token"].get<std::string>()},
                             {"client_id", "bsfchat-desktop"}});
    httplib::Response res;
    oidc->handle_token(req, res);
    ASSERT_EQ(status_of(res), 200) << res.body;
    auto claims = jwt_payload(json::parse(res.body)["id_token"].get<std::string>());
    EXPECT_EQ(claims["aud"], "bsfchat-desktop");
    EXPECT_FALSE(claims.contains("nonce"));
    EXPECT_FALSE(claims.contains("email"));
}

TEST_F(TokenAudienceTest, EmailIsReleasedOnlyUnderTheEmailScope) {
    auto with_email = jwt_payload(
        desktop_login({{"resource", kChat}}, "openid email")["id_token"].get<std::string>());
    EXPECT_EQ(with_email.value("email", ""), "alice@example.com");
    EXPECT_FALSE(with_email.contains("name"));  // no profile scope, no profile claims
}

// A database from before this change has neither column; the upgrade adds
// them and a grant then carries its resource through.
TEST_F(TokenAudienceTest, SchemaV1DatabaseGainsResourceAndNonceColumns) {
    auto dir = bsfchat::test::unique_temp_dir("bsfchat_id_audience_db");
    std::filesystem::create_directories(dir);
    auto path = (dir / "identity.db").string();
    {
        sqlite3* db = nullptr;
        ASSERT_EQ(sqlite3_open(path.c_str(), &db), SQLITE_OK);
        const char* v1 =
            "CREATE TABLE auth_codes (code TEXT PRIMARY KEY, client_id TEXT NOT NULL, "
            "account_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, scope TEXT, "
            "code_challenge TEXT, expires_at INTEGER NOT NULL);"
            "CREATE TABLE consent_requests (token TEXT PRIMARY KEY, session_id TEXT NOT NULL, "
            "account_id TEXT NOT NULL, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, "
            "scope TEXT NOT NULL DEFAULT '', state TEXT NOT NULL DEFAULT '', "
            "code_challenge TEXT NOT NULL DEFAULT '', expires_at INTEGER NOT NULL);"
            "PRAGMA user_version = 1;";
        ASSERT_EQ(sqlite3_exec(db, v1, nullptr, nullptr, nullptr), SQLITE_OK);
        sqlite3_close(db);
    }
    {
        IdentityStore upgraded(path);
        upgraded.initialize();
        AuthCode code;
        code.code = "c1";
        code.client_id = "bsfchat-desktop";
        code.account_id = "acct-1";
        code.redirect_uri = kRedirect;
        code.expires_at = now_seconds() + 300;
        code.resource = kChat;
        code.nonce = "n1";
        ASSERT_TRUE(upgraded.store_auth_code(code));
        auto back = upgraded.consume_auth_code("c1");
        ASSERT_TRUE(back.has_value());
        EXPECT_EQ(back->resource, kChat);
        EXPECT_EQ(back->nonce, "n1");
    }
    std::filesystem::remove_all(dir);
}

// ---------------------------------------------------------------------------
// M5 — only the desktop client (or the portal itself) may touch the list of
// servers the desktop client auto-connects to.
// ---------------------------------------------------------------------------
TEST_F(TokenAudienceTest, M5_OtherClientsCannotRewriteTheServerList) {
    // An access token for "web-app", with the openid scope every RP holds.
    httplib::Request areq = cookie_request();
    areq.params.emplace("client_id", "web-app");
    areq.params.emplace("redirect_uri", "https://app.example.com/cb");
    areq.params.emplace("response_type", "code");
    areq.params.emplace("scope", "openid");
    httplib::Response ares;
    oidc->handle_authorize(areq, ares);
    auto code = approve(ares);
    ASSERT_FALSE(code.empty());
    auto treq = form_request({{"grant_type", "authorization_code"},
                              {"code", code},
                              {"redirect_uri", "https://app.example.com/cb"},
                              {"client_id", "web-app"},
                              {"client_secret", "s3cr3t-value"}});
    httplib::Response tres;
    oidc->handle_token(treq, tres);
    ASSERT_EQ(status_of(tres), 200) << tres.body;
    auto other_token = json::parse(tres.body)["access_token"].get<std::string>();

    auto desktop_token = desktop_login({}, "openid profile")["access_token"].get<std::string>();

    auto add = [&](const std::string& bearer, const std::string& url) {
        httplib::Request req;
        req.method = "POST";
        req.remote_addr = "10.0.0.1";
        req.set_header("Content-Type", "application/json");
        if (!bearer.empty()) req.set_header("Authorization", "Bearer " + bearer);
        else req.set_header("Cookie", "session=" + browser_session);
        req.body = json{{"server_url", url}, {"server_name", "x"}}.dump();
        httplib::Response res;
        accounts->handle_add_server(req, res);
        return status_of(res);
    };

    EXPECT_EQ(add(other_token, "https://evil.example"), 403)
        << "a third-party client planted a server for the desktop app to auto-connect to";
    EXPECT_EQ(add(desktop_token, "https://chat.example"), 200);
    EXPECT_EQ(add("", "https://chat2.example"), 200);  // the portal's own profile page

    httplib::Request list;
    list.method = "GET";
    list.set_header("Authorization", "Bearer " + other_token);
    httplib::Response lres;
    accounts->handle_list_servers(list, lres);
    EXPECT_EQ(status_of(lres), 403);

    for (const auto& s : store->list_server_memberships("acct-1")) {
        EXPECT_NE(s.server_url, "https://evil.example");
    }
}

// ---------------------------------------------------------------------------
// M5 + H3, once both were on one branch: the writes on /api/servers take the
// same JSON/cross-site check as every other state-changing endpoint. A cookie
// is the credential a third-party page can make the browser attach, so the
// browser-session half of M5's rule needs it; the desktop client (bearer,
// JSON, no Origin, no Sec-Fetch-Site) is unaffected.
// ---------------------------------------------------------------------------
TEST_F(TokenAudienceTest, ServerListWritesRefuseCrossSiteBrowserRequests) {
    auto post = [&](const std::string& content_type, const Params& headers,
                    bool remove = false, const std::string& bearer = "") {
        httplib::Request req;
        req.method = "POST";
        req.remote_addr = "10.0.0.1";
        if (bearer.empty()) req.set_header("Cookie", "session=" + browser_session);
        else req.set_header("Authorization", "Bearer " + bearer);
        req.set_header("Content-Type", content_type);
        for (const auto& [k, v] : headers) req.set_header(k, v);
        req.body = json{{"server_url", "https://planted.example"}}.dump();
        httplib::Response res;
        if (remove) accounts->handle_remove_server(req, res);
        else accounts->handle_add_server(req, res);
        return status_of(res);
    };

    EXPECT_EQ(post("application/json", {{"Sec-Fetch-Site", "cross-site"}}), 403);
    EXPECT_EQ(post("application/json", {{"Origin", "https://evil.example"}}), 403);
    EXPECT_EQ(post("text/plain", {}), 415);  // a simple-request form post
    EXPECT_TRUE(store->list_server_memberships("acct-1").empty());

    // The portal itself, same-origin.
    EXPECT_EQ(post("application/json", {{"Sec-Fetch-Site", "same-origin"}}), 200);
    EXPECT_EQ(post("application/json", {{"Origin", "https://id.example"}, {"Sec-Fetch-Site", "cross-site"}},
                   /*remove=*/true), 403);
    ASSERT_EQ(store->list_server_memberships("acct-1").size(), 1u);

    // The desktop client, exactly as IdentityApiClient sends it.
    auto desktop_token = desktop_login()["access_token"].get<std::string>();
    EXPECT_EQ(post("application/json", {}, /*remove=*/true, desktop_token), 200);
    EXPECT_TRUE(store->list_server_memberships("acct-1").empty());
}


// ---------------------------------------------------------------------------
// The iOS transport does not touch any of this.
//
// iOS signs in through ASWebAuthenticationSession with a private-use URI
// scheme callback, because the desktop loopback redirect cannot work there —
// the browser hand-off suspends the app and the callback is never accepted.
// What changed is where the redirect lands. What must NOT change is the
// audience binding C1 exists for, the nonce, azp, or the token's lifetime.
// ---------------------------------------------------------------------------

TEST_F(TokenAudienceTest, TheNativeCallbackKeepsTheAudienceBinding) {
    const std::string kNative = "bsfchat://oauth/callback";

    auto req = cookie_request();
    req.params.emplace("client_id", "bsfchat-desktop");
    req.params.emplace("redirect_uri", kNative);
    req.params.emplace("response_type", "code");
    req.params.emplace("scope", "openid profile");
    req.params.emplace("state", "xyz");
    req.params.emplace("nonce", "n-from-ios");
    req.params.emplace("resource", kChat);
    req.params.emplace("code_challenge", s256_challenge(kVerifier));
    req.params.emplace("code_challenge_method", "S256");

    httplib::Response res;
    oidc->handle_authorize(req, res);
    ASSERT_EQ(status_of(res), 200) << res.body;

    auto code = approve(res);
    ASSERT_FALSE(code.empty());

    auto tres = redeem(code, {{"redirect_uri", kNative}, {"resource", kChat}});
    ASSERT_EQ(status_of(tres), 200) << tres.body;

    auto claims = jwt_payload(json::parse(tres.body)["id_token"].get<std::string>());
    EXPECT_EQ(claims["aud"], kChat);              // C1: the chat server, not the client
    EXPECT_EQ(claims.value("azp", ""), "bsfchat-desktop");
    EXPECT_EQ(claims.value("nonce", ""), "n-from-ios");
    EXPECT_LE(claims["exp"].get<int64_t>() - claims["iat"].get<int64_t>(), 300);
}

TEST_F(TokenAudienceTest, TheNativeCallbackCannotBorrowAnotherServersToken) {
    // The C1 proof, over the iOS transport: a code issued for one chat server
    // cannot be redeemed naming another.
    const std::string kNative = "bsfchat://oauth/callback";

    auto req = cookie_request();
    req.params.emplace("client_id", "bsfchat-desktop");
    req.params.emplace("redirect_uri", kNative);
    req.params.emplace("response_type", "code");
    req.params.emplace("scope", "openid profile");
    req.params.emplace("state", "xyz");
    req.params.emplace("resource", kChat);
    req.params.emplace("code_challenge", s256_challenge(kVerifier));
    req.params.emplace("code_challenge_method", "S256");

    httplib::Response res;
    oidc->handle_authorize(req, res);
    ASSERT_EQ(status_of(res), 200) << res.body;
    auto code = approve(res);
    ASSERT_FALSE(code.empty());

    auto tres = redeem(code, {{"redirect_uri", kNative},
                              {"resource", "https://evil.example"}});
    EXPECT_NE(status_of(tres), 200) << tres.body;
}
