// Regression tests for the /authorize + /token flows, credential separation
// and 2FA lockout. These drive the handlers directly with synthetic
// httplib::Request objects, which is enough to cover the authorization
// decisions without standing up a socket.

#include <gtest/gtest.h>

#include "api/AccountHandler.h"
#include "api/OidcHandler.h"
#include "core/Config.h"
#include "core/ClientRegistration.h"
#include "core/WebUtil.h"
#include "crypto/PasswordHash.h"
#include "crypto/Secrets.h"
#include "crypto/Totp.h"
#include "store/IdentityStore.h"
#include "TempPaths.h"

#include <nlohmann/json.hpp>
#include <openssl/sha.h>

#include <chrono>
#include <filesystem>

using namespace bsfchat::id;
using json = nlohmann::json;

namespace {

int64_t now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// Base64url without padding, matching the server's PKCE encoding.
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

// A 43-character verifier, the RFC 7636 minimum.
const std::string kVerifier = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

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

httplib::Request json_request(const json& body) {
    httplib::Request req;
    req.method = "POST";
    req.set_header("Content-Type", "application/json");
    req.body = body.dump();
    req.remote_addr = "10.0.0.1";
    return req;
}

// cpp-httplib leaves Response::status at -1 until the server serializes the
// response, at which point an unset status becomes 200. Handlers here are
// called directly, so normalize the same way.
int status_of(const httplib::Response& res) {
    return res.status < 0 ? 200 : res.status;
}

std::string extract_location(const httplib::Response& res) {
    auto it = res.headers.find("Location");
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

class AuthFlowTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Unique per process+fixture — see TempPaths.h. A shared key dir
        // made AuthFlowTest/TokenSeparationTest/TwoFactorTest fail under
        // ctest -j4.
        keys_dir = bsfchat::test::unique_temp_dir("bsfchat_id_authflow_keys");

        config.password_hash_iterations = kMinPbkdf2Iterations;
        config.totp_max_attempts = 3;
        config.login_max_failures = 4;
        config.login_rate_limit = 1000; // do not trip the request limiter in tests
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

        // Public client (no secret) — must use PKCE. Registered with exactly
        // what IdentityServer seeds in production (first_party_redirect_uris),
        // so the loopback redirect desktop uses and the private-use scheme
        // iOS uses are both exercised against the real list rather than a
        // convenient one.
        OAuthClient publicc;
        publicc.client_id = "bsfchat-desktop";
        publicc.client_secret = "";
        publicc.name = "BSFChat Desktop";
        publicc.redirect_uris = first_party_redirect_uris();
        publicc.created_at = now;
        ASSERT_TRUE(store->create_oauth_client(publicc));

        // Confidential client (has a secret) — must authenticate.
        OAuthClient confidential;
        confidential.client_id = "web-app";
        confidential.client_secret = "s3cr3t-value";
        confidential.name = "Web App";
        confidential.redirect_uris = R"(["https://app.example.com/cb"])";
        confidential.created_at = now;
        ASSERT_TRUE(store->create_oauth_client(confidential));

        browser_session = "browser-session-token";
        Session s;
        s.session_id = browser_session;
        s.account_id = "acct-1";
        s.created_at = now;
        s.expires_at = now + 3600;
        s.token_type = token_type::kBrowserSession;
        ASSERT_TRUE(store->create_session(s));
    }

    void TearDown() override {
        std::filesystem::remove_all(keys_dir);
    }

    // Runs GET /authorize followed by the consent POST, returning the final
    // redirect Location.
    std::string authorize_and_consent(const std::string& client_id,
                                      const std::string& redirect_uri,
                                      const std::string& challenge,
                                      const std::string& state = "xyz") {
        httplib::Request req;
        req.method = "GET";
        req.remote_addr = "10.0.0.1";
        req.set_header("Cookie", "session=" + browser_session);
        req.params.emplace("client_id", client_id);
        req.params.emplace("redirect_uri", redirect_uri);
        req.params.emplace("response_type", "code");
        req.params.emplace("scope", "openid profile");
        req.params.emplace("state", state);
        if (!challenge.empty()) {
            req.params.emplace("code_challenge", challenge);
            req.params.emplace("code_challenge_method", "S256");
        }

        httplib::Response res;
        oidc->handle_authorize(req, res);
        if (status_of(res) != 200) return "";

        auto token = consent_token_from(res.body);
        if (token.empty()) return "";

        auto decision = form_request({{"consent_token", token}, {"approve", "true"}});
        decision.set_header("Cookie", "session=" + browser_session);
        httplib::Response dres;
        oidc->handle_authorize_decision(decision, dres);
        return extract_location(dres);
    }

    static std::string consent_token_from(const std::string& html) {
        const std::string marker = "name=\"consent_token\" value=\"";
        auto pos = html.find(marker);
        if (pos == std::string::npos) return "";
        auto start = pos + marker.size();
        auto end = html.find('"', start);
        return html.substr(start, end - start);
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
// I1 — /token must actually authenticate the client
// ---------------------------------------------------------------------------

TEST_F(AuthFlowTest, ConfidentialClientWrongSecretIsRejected) {
    auto location = authorize_and_consent("web-app", "https://app.example.com/cb", "");
    auto code = query_param(location, "code");
    ASSERT_FALSE(code.empty());

    auto req = form_request({
        {"grant_type", "authorization_code"},
        {"code", code},
        {"redirect_uri", "https://app.example.com/cb"},
        {"client_id", "web-app"},
        {"client_secret", "wrong-secret"},
    });
    httplib::Response res;
    oidc->handle_token(req, res);

    EXPECT_EQ(status_of(res), 401);
    EXPECT_EQ(json::parse(res.body)["error"], "invalid_client");
}

TEST_F(AuthFlowTest, ConfidentialClientMissingSecretIsRejected) {
    auto location = authorize_and_consent("web-app", "https://app.example.com/cb", "");
    auto code = query_param(location, "code");
    ASSERT_FALSE(code.empty());

    auto req = form_request({
        {"grant_type", "authorization_code"},
        {"code", code},
        {"redirect_uri", "https://app.example.com/cb"},
        {"client_id", "web-app"},
    });
    httplib::Response res;
    oidc->handle_token(req, res);

    EXPECT_EQ(status_of(res), 401);
    EXPECT_EQ(json::parse(res.body)["error"], "invalid_client");
}

TEST_F(AuthFlowTest, ConfidentialClientCorrectSecretSucceeds) {
    auto location = authorize_and_consent("web-app", "https://app.example.com/cb", "");
    auto code = query_param(location, "code");
    ASSERT_FALSE(code.empty());

    auto req = form_request({
        {"grant_type", "authorization_code"},
        {"code", code},
        {"redirect_uri", "https://app.example.com/cb"},
        {"client_id", "web-app"},
        {"client_secret", "s3cr3t-value"},
    });
    httplib::Response res;
    oidc->handle_token(req, res);

    ASSERT_EQ(status_of(res), 200) << res.body;
    auto body = json::parse(res.body);
    EXPECT_FALSE(body["access_token"].get<std::string>().empty());
    EXPECT_FALSE(body["id_token"].get<std::string>().empty());
}

TEST_F(AuthFlowTest, ConfidentialClientAuthenticatesViaHttpBasic) {
    auto location = authorize_and_consent("web-app", "https://app.example.com/cb", "");
    auto code = query_param(location, "code");
    ASSERT_FALSE(code.empty());

    auto req = form_request({
        {"grant_type", "authorization_code"},
        {"code", code},
        {"redirect_uri", "https://app.example.com/cb"},
    });
    // base64("web-app:s3cr3t-value")
    req.set_header("Authorization", "Basic d2ViLWFwcDpzM2NyM3QtdmFsdWU=");

    httplib::Response res;
    oidc->handle_token(req, res);
    EXPECT_EQ(status_of(res), 200) << res.body;
}

TEST_F(AuthFlowTest, PublicClientPresentingASecretIsRejected) {
    auto challenge = s256_challenge(kVerifier);
    auto location = authorize_and_consent("bsfchat-desktop", "http://localhost:41234/oauth/callback", challenge);
    auto code = query_param(location, "code");
    ASSERT_FALSE(code.empty());

    auto req = form_request({
        {"grant_type", "authorization_code"},
        {"code", code},
        {"redirect_uri", "http://localhost:41234/oauth/callback"},
        {"client_id", "bsfchat-desktop"},
        {"client_secret", "anything"},
        {"code_verifier", kVerifier},
    });
    httplib::Response res;
    oidc->handle_token(req, res);

    EXPECT_EQ(status_of(res), 401);
    EXPECT_EQ(json::parse(res.body)["error"], "invalid_client");
}

// ---------------------------------------------------------------------------
// I2 — PKCE is mandatory for public clients, redirect matching is strict,
//      codes are single use, and /authorize does not grant silently
// ---------------------------------------------------------------------------

TEST_F(AuthFlowTest, PublicClientWithoutPkceIsRejectedAtAuthorize) {
    httplib::Request req;
    req.method = "GET";
    req.set_header("Cookie", "session=" + browser_session);
    req.params.emplace("client_id", "bsfchat-desktop");
    req.params.emplace("redirect_uri", "http://localhost:41234/oauth/callback");
    req.params.emplace("response_type", "code");
    req.params.emplace("scope", "openid");
    req.params.emplace("state", "st");

    httplib::Response res;
    oidc->handle_authorize(req, res);

    EXPECT_EQ(status_of(res), 302);
    EXPECT_EQ(query_param(extract_location(res), "error"), "invalid_request");
    EXPECT_TRUE(query_param(extract_location(res), "code").empty());
}

TEST_F(AuthFlowTest, PlainPkceMethodIsRejected) {
    httplib::Request req;
    req.method = "GET";
    req.set_header("Cookie", "session=" + browser_session);
    req.params.emplace("client_id", "bsfchat-desktop");
    req.params.emplace("redirect_uri", "http://localhost:41234/oauth/callback");
    req.params.emplace("response_type", "code");
    req.params.emplace("scope", "openid");
    req.params.emplace("code_challenge", kVerifier);
    req.params.emplace("code_challenge_method", "plain");

    httplib::Response res;
    oidc->handle_authorize(req, res);

    EXPECT_EQ(status_of(res), 302);
    EXPECT_EQ(query_param(extract_location(res), "error"), "invalid_request");
}

TEST_F(AuthFlowTest, AuthorizeDoesNotIssueCodeWithoutConsent) {
    auto challenge = s256_challenge(kVerifier);
    httplib::Request req;
    req.method = "GET";
    req.set_header("Cookie", "session=" + browser_session);
    req.params.emplace("client_id", "bsfchat-desktop");
    req.params.emplace("redirect_uri", "http://localhost:41234/oauth/callback");
    req.params.emplace("response_type", "code");
    req.params.emplace("scope", "openid profile");
    req.params.emplace("code_challenge", challenge);
    req.params.emplace("code_challenge_method", "S256");

    httplib::Response res;
    oidc->handle_authorize(req, res);

    // A GET must render a consent page, never a 302 carrying a code.
    EXPECT_EQ(status_of(res), 200);
    EXPECT_TRUE(extract_location(res).empty());
    EXPECT_NE(res.body.find("consent_token"), std::string::npos);
}

TEST_F(AuthFlowTest, ConsentDecisionFromAnotherSessionIsRejected) {
    auto challenge = s256_challenge(kVerifier);
    httplib::Request req;
    req.method = "GET";
    req.set_header("Cookie", "session=" + browser_session);
    req.params.emplace("client_id", "bsfchat-desktop");
    req.params.emplace("redirect_uri", "http://localhost:41234/oauth/callback");
    req.params.emplace("response_type", "code");
    req.params.emplace("scope", "openid");
    req.params.emplace("code_challenge", challenge);
    req.params.emplace("code_challenge_method", "S256");

    httplib::Response res;
    oidc->handle_authorize(req, res);
    auto token = consent_token_from(res.body);
    ASSERT_FALSE(token.empty());

    // (a) No credential at all — the cross-site POST case.
    auto anonymous = form_request({{"consent_token", token}, {"approve", "true"}});
    httplib::Response ares;
    oidc->handle_authorize_decision(anonymous, ares);
    EXPECT_EQ(status_of(ares), 401);
    EXPECT_TRUE(extract_location(ares).empty());

    // (b) A different, perfectly valid browser session must not be able to
    // approve a prompt it was never shown. This one belongs to the SAME
    // account — the shape a re-login produces, and the one the mobile 403 of
    // 2026-09-24 turned out to be — so it is answered by putting the
    // authorization request again rather than by a dead end. No code either
    // way: that is the property, and it is unchanged.
    auto now = now_seconds();
    Session other;
    other.session_id = "another-browser-session";
    other.account_id = "acct-1";
    other.created_at = now;
    other.expires_at = now + 3600;
    other.token_type = token_type::kBrowserSession;
    ASSERT_TRUE(store->create_session(other));

    auto foreign = form_request({{"consent_token", token}, {"approve", "true"}});
    foreign.set_header("Cookie", "session=another-browser-session");
    httplib::Response fres;
    oidc->handle_authorize_decision(foreign, fres);
    EXPECT_EQ(status_of(fres), 302);
    EXPECT_EQ(extract_location(fres).rfind("/authorize?", 0), 0u) << extract_location(fres);
    EXPECT_TRUE(query_param(extract_location(fres), "code").empty());

    // (b2) A STRANGER's session is the actual CSRF case, and gets the opaque
    // refusal: no code, no redirect, and nothing said about the prompt — not
    // the client, not the redirect_uri it names.
    Account stranger;
    stranger.id = "acct-2";
    stranger.username = "mallory";
    stranger.email = "mallory@example.com";
    stranger.password_hash = hash_password("hunter2hunter2", config.password_hash_iterations);
    stranger.created_at = now;
    stranger.updated_at = now;
    ASSERT_TRUE(store->create_account(stranger));
    Session theirs;
    theirs.session_id = "a-strangers-session";
    theirs.account_id = "acct-2";
    theirs.created_at = now;
    theirs.expires_at = now + 3600;
    theirs.token_type = token_type::kBrowserSession;
    ASSERT_TRUE(store->create_session(theirs));

    auto stranger_post = form_request({{"consent_token", token}, {"approve", "true"}});
    stranger_post.set_header("Cookie", "session=a-strangers-session");
    httplib::Response sres;
    oidc->handle_authorize_decision(stranger_post, sres);
    EXPECT_EQ(status_of(sres), 403);
    EXPECT_TRUE(extract_location(sres).empty());
    EXPECT_EQ(sres.body.find("localhost:41234"), std::string::npos);

    // (c) The rejected attempts must not have burned the pending request — the
    // rightful session can still complete it.
    auto owner = form_request({{"consent_token", token}, {"approve", "true"}});
    owner.set_header("Cookie", "session=" + browser_session);
    httplib::Response ores;
    oidc->handle_authorize_decision(owner, ores);
    EXPECT_EQ(status_of(ores), 302);
    EXPECT_FALSE(query_param(extract_location(ores), "code").empty());
}

TEST_F(AuthFlowTest, ConsentTokenIsSingleUse) {
    auto challenge = s256_challenge(kVerifier);
    httplib::Request req;
    req.method = "GET";
    req.set_header("Cookie", "session=" + browser_session);
    req.params.emplace("client_id", "bsfchat-desktop");
    req.params.emplace("redirect_uri", "http://localhost:41234/oauth/callback");
    req.params.emplace("response_type", "code");
    req.params.emplace("scope", "openid");
    req.params.emplace("code_challenge", challenge);
    req.params.emplace("code_challenge_method", "S256");

    httplib::Response res;
    oidc->handle_authorize(req, res);
    auto token = consent_token_from(res.body);
    ASSERT_FALSE(token.empty());

    auto first = form_request({{"consent_token", token}, {"approve", "true"}});
    first.set_header("Cookie", "session=" + browser_session);
    httplib::Response fres;
    oidc->handle_authorize_decision(first, fres);
    EXPECT_EQ(status_of(fres), 302);

    // Resubmitting the same form — the browser's back button, a double tap, a
    // tab Android restored — issues NO second code and steers the browser
    // nowhere. It is reported as what it is rather than as a CSRF attempt:
    // this exact response used to be the 403 "does not belong to this session"
    // that made a failed mobile sign-in unreadable and unrecoverable.
    auto second = form_request({{"consent_token", token}, {"approve", "true"}});
    second.set_header("Cookie", "session=" + browser_session);
    httplib::Response sres;
    oidc->handle_authorize_decision(second, sres);
    EXPECT_EQ(status_of(sres), 409);
    EXPECT_TRUE(extract_location(sres).empty());
    EXPECT_EQ(sres.body.find("code="), std::string::npos);
    EXPECT_NE(sres.body.find("Already approved"), std::string::npos);
}

TEST_F(AuthFlowTest, DenyingConsentReturnsAccessDenied) {
    auto challenge = s256_challenge(kVerifier);
    httplib::Request req;
    req.method = "GET";
    req.set_header("Cookie", "session=" + browser_session);
    req.params.emplace("client_id", "bsfchat-desktop");
    req.params.emplace("redirect_uri", "http://localhost:41234/oauth/callback");
    req.params.emplace("response_type", "code");
    req.params.emplace("scope", "openid");
    req.params.emplace("code_challenge", challenge);
    req.params.emplace("code_challenge_method", "S256");
    req.params.emplace("state", "the-state");

    httplib::Response res;
    oidc->handle_authorize(req, res);
    auto token = consent_token_from(res.body);
    ASSERT_FALSE(token.empty());

    auto decision = form_request({{"consent_token", token}, {"approve", "false"}});
    decision.set_header("Cookie", "session=" + browser_session);
    httplib::Response dres;
    oidc->handle_authorize_decision(decision, dres);

    auto location = extract_location(dres);
    EXPECT_EQ(query_param(location, "error"), "access_denied");
    EXPECT_EQ(query_param(location, "state"), "the-state");
    EXPECT_TRUE(query_param(location, "code").empty());
}

TEST_F(AuthFlowTest, WrongCodeVerifierIsRejected) {
    auto challenge = s256_challenge(kVerifier);
    auto location = authorize_and_consent("bsfchat-desktop", "http://localhost:41234/oauth/callback", challenge);
    auto code = query_param(location, "code");
    ASSERT_FALSE(code.empty());

    auto req = form_request({
        {"grant_type", "authorization_code"},
        {"code", code},
        {"redirect_uri", "http://localhost:41234/oauth/callback"},
        {"client_id", "bsfchat-desktop"},
        {"code_verifier", "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"},
    });
    httplib::Response res;
    oidc->handle_token(req, res);

    EXPECT_EQ(status_of(res), 400);
    EXPECT_EQ(json::parse(res.body)["error"], "invalid_grant");
}

TEST_F(AuthFlowTest, AuthorizationCodeIsSingleUse) {
    auto challenge = s256_challenge(kVerifier);
    auto location = authorize_and_consent("bsfchat-desktop", "http://localhost:41234/oauth/callback", challenge);
    auto code = query_param(location, "code");
    ASSERT_FALSE(code.empty());

    std::map<std::string, std::string> params = {
        {"grant_type", "authorization_code"},
        {"code", code},
        {"redirect_uri", "http://localhost:41234/oauth/callback"},
        {"client_id", "bsfchat-desktop"},
        {"code_verifier", kVerifier},
    };

    auto first = form_request(params);
    httplib::Response fres;
    oidc->handle_token(first, fres);
    ASSERT_EQ(status_of(fres), 200) << fres.body;

    auto second = form_request(params);
    httplib::Response sres;
    oidc->handle_token(second, sres);
    EXPECT_EQ(status_of(sres), 400);
    EXPECT_EQ(json::parse(sres.body)["error"], "invalid_grant");
}

TEST_F(AuthFlowTest, RedirectUriWithUserinfoSmugglingIsRejected) {
    httplib::Request req;
    req.method = "GET";
    req.set_header("Cookie", "session=" + browser_session);
    req.params.emplace("client_id", "bsfchat-desktop");
    // Authority is "localhost:8080@attacker.example" — the real host is
    // attacker.example. The old prefix check accepted this.
    req.params.emplace("redirect_uri", "http://localhost:8080@attacker.example/oauth/callback");
    req.params.emplace("response_type", "code");
    req.params.emplace("scope", "openid");
    req.params.emplace("code_challenge", s256_challenge(kVerifier));
    req.params.emplace("code_challenge_method", "S256");

    httplib::Response res;
    oidc->handle_authorize(req, res);
    EXPECT_EQ(status_of(res), 400);
}

TEST_F(AuthFlowTest, RedirectUriWithDifferentPathIsRejected) {
    httplib::Request req;
    req.method = "GET";
    req.set_header("Cookie", "session=" + browser_session);
    req.params.emplace("client_id", "bsfchat-desktop");
    req.params.emplace("redirect_uri", "http://localhost:41234/evil");
    req.params.emplace("response_type", "code");
    req.params.emplace("scope", "openid");
    req.params.emplace("code_challenge", s256_challenge(kVerifier));
    req.params.emplace("code_challenge_method", "S256");

    httplib::Response res;
    oidc->handle_authorize(req, res);
    EXPECT_EQ(status_of(res), 400);
}

TEST_F(AuthFlowTest, LoginRedirectPercentEncodesParameters) {
    httplib::Request req;
    req.method = "GET";
    // No cookie: unauthenticated, so we get the login redirect.
    req.params.emplace("client_id", "bsfchat-desktop");
    req.params.emplace("redirect_uri", "http://localhost:41234/oauth/callback");
    req.params.emplace("response_type", "code");
    req.params.emplace("scope", "openid profile");
    req.params.emplace("state", "a&b=c?d");
    req.params.emplace("code_challenge", s256_challenge(kVerifier));
    req.params.emplace("code_challenge_method", "S256");

    httplib::Response res;
    oidc->handle_authorize(req, res);

    ASSERT_EQ(status_of(res), 302);
    auto location = extract_location(res);
    // The raw '&' must not survive into the query string as a separator.
    EXPECT_EQ(query_param(location, "state"), "a&b=c?d");
    EXPECT_EQ(query_param(location, "redirect"), "http://localhost:41234/oauth/callback");
}

// ---------------------------------------------------------------------------
// I3 — an OIDC access token must not be an account-portal credential
// ---------------------------------------------------------------------------

class TokenSeparationTest : public AuthFlowTest {
protected:
    // Completes the public-client flow and returns the access token.
    std::string mint_access_token() {
        auto challenge = s256_challenge(kVerifier);
        auto location = authorize_and_consent("bsfchat-desktop", "http://localhost:41234/oauth/callback", challenge);
        auto code = query_param(location, "code");
        EXPECT_FALSE(code.empty());

        auto req = form_request({
            {"grant_type", "authorization_code"},
            {"code", code},
            {"redirect_uri", "http://localhost:41234/oauth/callback"},
            {"client_id", "bsfchat-desktop"},
            {"code_verifier", kVerifier},
        });
        httplib::Response res;
        oidc->handle_token(req, res);
        EXPECT_EQ(status_of(res), 200) << res.body;
        return json::parse(res.body)["access_token"].get<std::string>();
    }

    static httplib::Request bearer_request(const std::string& token) {
        httplib::Request req;
        req.method = "GET";
        req.remote_addr = "10.0.0.1";
        req.set_header("Authorization", "Bearer " + token);
        return req;
    }
};

TEST_F(TokenSeparationTest, AccessTokenCannotReadProfile) {
    auto token = mint_access_token();
    auto req = bearer_request(token);
    httplib::Response res;
    accounts->handle_get_profile(req, res);
    EXPECT_EQ(status_of(res), 401);
}

TEST_F(TokenSeparationTest, AccessTokenCannotListSessions) {
    auto token = mint_access_token();
    auto req = bearer_request(token);
    httplib::Response res;
    accounts->handle_list_sessions(req, res);
    EXPECT_EQ(status_of(res), 401);
}

TEST_F(TokenSeparationTest, AccessTokenCannotDisable2fa) {
    auto token = mint_access_token();
    auto req = json_request(json{{"password", "correct horse battery"}});
    req.set_header("Authorization", "Bearer " + token);
    httplib::Response res;
    accounts->handle_2fa_disable(req, res);
    EXPECT_EQ(status_of(res), 401);
}

TEST_F(TokenSeparationTest, AccessTokenCanStillReachUserinfo) {
    auto token = mint_access_token();
    auto req = bearer_request(token);
    httplib::Response res;
    oidc->handle_userinfo(req, res);

    ASSERT_EQ(status_of(res), 200) << res.body;
    auto body = json::parse(res.body);
    EXPECT_EQ(body["sub"], "acct-1");
    EXPECT_EQ(body["preferred_username"], "alice"); // profile scope granted
    EXPECT_FALSE(body.contains("email"));           // email scope was not
}

TEST_F(TokenSeparationTest, AccessTokenCanStillSyncServerList) {
    // The shipped desktop client depends on this; it must keep working.
    auto token = mint_access_token();
    auto req = bearer_request(token);
    httplib::Response res;
    accounts->handle_list_servers(req, res);
    EXPECT_EQ(status_of(res), 200) << res.body;
}

// The server list is the one thing an OIDC access token may write, and the
// desktop client connects to every entry on login. Anything a relying party
// with the ubiquitous "openid" scope can put here ends up in somebody's
// client, so the values have to be homeserver-shaped.
TEST_F(TokenSeparationTest, ServerUrlMustBeAbsoluteHttp) {
    auto token = mint_access_token();

    auto add = [&](const json& body) {
        auto req = json_request(body);
        req.set_header("Authorization", "Bearer " + token);
        httplib::Response res;
        accounts->handle_add_server(req, res);
        return status_of(res);
    };

    EXPECT_EQ(add(json{{"server_url", "file:///etc/passwd"}}), 400);
    EXPECT_EQ(add(json{{"server_url", "javascript:alert(1)"}}), 400);
    EXPECT_EQ(add(json{{"server_url", "not a url"}}), 400);
    EXPECT_EQ(add(json{{"server_url", "/relative"}}), 400);
    EXPECT_EQ(add(json{{"server_url", ""}}), 400);
    // Userinfo smuggling: a naive reader of this list sees "real.example".
    EXPECT_EQ(add(json{{"server_url", "https://real.example@evil.example/"}}), 400);
    // Fragments and control characters never belong in a homeserver URL.
    EXPECT_EQ(add(json{{"server_url", "https://ok.example/#x"}}), 400);
    EXPECT_EQ(add(json{{"server_url", "https://ok.example/\r\nX-Injected: 1"}}), 400);
    EXPECT_EQ(add(json{{"server_url", std::string("https://x.example/")
                                          + std::string(600, 'a')}}), 400);

    // Real homeserver URLs still work.
    EXPECT_EQ(add(json{{"server_url", "https://bsfchat.com"}}), 200);
    EXPECT_EQ(add(json{{"server_url", "http://192.168.1.10:8448"}}), 200);
}

// body["server_url"].get<std::string>() on a non-string threw json::type_error,
// which httplib turns into a 500. A malformed request is the client's fault
// and must say so.
TEST_F(TokenSeparationTest, NonStringServerUrlIsARequestError) {
    auto token = mint_access_token();
    auto req = json_request(json{{"server_url", 1}});
    req.set_header("Authorization", "Bearer " + token);
    httplib::Response res;
    accounts->handle_add_server(req, res);
    EXPECT_EQ(status_of(res), 400);

    auto remove_req = json_request(json{{"server_url", json::object()}});
    remove_req.set_header("Authorization", "Bearer " + token);
    httplib::Response remove_res;
    accounts->handle_remove_server(remove_req, remove_res);
    EXPECT_EQ(status_of(remove_res), 400);
}

TEST_F(TokenSeparationTest, ServerListIsBounded) {
    auto token = mint_access_token();
    for (int i = 0; i < 100; ++i) {
        auto req = json_request(json{
            {"server_url", "https://s" + std::to_string(i) + ".example"}});
        req.set_header("Authorization", "Bearer " + token);
        httplib::Response res;
        accounts->handle_add_server(req, res);
        ASSERT_EQ(status_of(res), 200) << "row " << i << ": " << res.body;
    }
    auto req = json_request(json{{"server_url", "https://one-too-many.example"}});
    req.set_header("Authorization", "Bearer " + token);
    httplib::Response res;
    accounts->handle_add_server(req, res);
    EXPECT_EQ(status_of(res), 409);
}

TEST_F(TokenSeparationTest, BrowserSessionCannotBeUsedAsAccessToken) {
    auto req = bearer_request(browser_session);
    httplib::Response res;
    oidc->handle_userinfo(req, res);
    EXPECT_EQ(status_of(res), 401);
}

TEST_F(TokenSeparationTest, AccessTokensAreNotListedAsBrowserSessions) {
    mint_access_token();
    auto sessions = store->list_sessions_for_account("acct-1");
    ASSERT_EQ(sessions.size(), 1u);
    // Rows carry the stored digest, not the bearer value (security audit L5).
    EXPECT_EQ(sessions[0].session_id, hash_token(browser_session));
}

TEST_F(AuthFlowTest, CookieParsingIsAnchoredToTheName) {
    httplib::Request req;
    req.method = "GET";
    // "mysession=" must not be read as "session=".
    req.set_header("Cookie", "mysession=" + browser_session);
    EXPECT_TRUE(accounts->get_session_account(req).empty());

    httplib::Request ok;
    ok.method = "GET";
    ok.set_header("Cookie", "theme=dark; session=" + browser_session + "; other=1");
    EXPECT_EQ(accounts->get_session_account(ok), "acct-1");
}

TEST_F(AuthFlowTest, SessionCookieCarriesSecureAndHttpOnly) {
    auto cookie = accounts->session_cookie("abc", 604800);
    EXPECT_NE(cookie.find("Secure"), std::string::npos);
    EXPECT_NE(cookie.find("HttpOnly"), std::string::npos);
    EXPECT_NE(cookie.find("SameSite=Lax"), std::string::npos);
}

// ---------------------------------------------------------------------------
// I4 — 2FA brute force
// ---------------------------------------------------------------------------

class TwoFactorTest : public AuthFlowTest {
protected:
    void SetUp() override {
        AuthFlowTest::SetUp();
        secret = bsfchat::generate_totp_secret();
        store->set_totp_secret("acct-1", secret, {"BACKUPAA", "BACKUPBB"});
        store->enable_totp("acct-1");
    }

    std::string start_login() {
        auto req = json_request(json{{"username", "alice"}, {"password", "correct horse battery"}});
        httplib::Response res;
        accounts->handle_login(req, res);
        EXPECT_EQ(status_of(res), 200) << res.body;
        auto body = json::parse(res.body);
        EXPECT_TRUE(body.value("requires_2fa", false));
        return body.value("login_token", "");
    }

    std::string secret;
};

// /2fa/setup does INSERT OR REPLACE with enabled = 0, so re-running it on an
// enrolled account silently turned 2FA OFF. It needs only a session cookie,
// while /2fa/disable deliberately demands the password — so the no-password
// endpoint was the cheap route to single-factor for anyone holding a stolen
// cookie.
TEST_F(TwoFactorTest, SetupCannotSilentlyDisableEnrolled2fa) {
    ASSERT_TRUE(store->get_totp("acct-1")->enabled);

    httplib::Request req;
    req.method = "POST";
    req.remote_addr = "10.0.0.1";
    req.set_header("Cookie", "session=" + browser_session);
    httplib::Response res;
    accounts->handle_2fa_setup(req, res);

    EXPECT_EQ(status_of(res), 409) << res.body;
    auto totp = store->get_totp("acct-1");
    ASSERT_TRUE(totp.has_value());
    EXPECT_TRUE(totp->enabled) << "setup turned 2FA off";
    EXPECT_EQ(totp->secret, secret) << "setup replaced the enrolled secret";
}

// Enrolling for the first time must still work.
TEST_F(AuthFlowTest, SetupWorksWhenNo2faIsEnrolled) {
    httplib::Request req;
    req.method = "POST";
    req.remote_addr = "10.0.0.1";
    req.set_header("Cookie", "session=" + browser_session);
    httplib::Response res;
    accounts->handle_2fa_setup(req, res);

    ASSERT_EQ(status_of(res), 200) << res.body;
    auto body = json::parse(res.body);
    EXPECT_FALSE(body.value("secret", "").empty());
    EXPECT_EQ(body["backup_codes"].size(), 8u);
}

TEST_F(TwoFactorTest, LoginTokenIsBurnedAfterRepeatedWrongCodes) {
    auto login_token = start_login();
    ASSERT_FALSE(login_token.empty());

    // config.totp_max_attempts is 3 in this fixture.
    for (int i = 0; i < 2; ++i) {
        auto req = json_request(json{{"login_token", login_token}, {"code", "000000"}});
        httplib::Response res;
        accounts->handle_login_2fa(req, res);
        EXPECT_EQ(status_of(res), 401);
        // Still alive, so the user can correct a typo.
        EXPECT_TRUE(store->validate_login_token(login_token).has_value());
    }

    auto req = json_request(json{{"login_token", login_token}, {"code", "000000"}});
    httplib::Response res;
    accounts->handle_login_2fa(req, res);
    EXPECT_EQ(status_of(res), 401);

    // The token must now be gone rather than surviving until its 5 minute expiry.
    EXPECT_FALSE(store->validate_login_token(login_token).has_value());

    // And even the correct code cannot revive it.
    auto now = now_seconds();
    auto valid_code = bsfchat::compute_totp(secret, static_cast<uint64_t>(now) / 30);
    auto retry = json_request(json{{"login_token", login_token}, {"code", valid_code}});
    httplib::Response rres;
    accounts->handle_login_2fa(retry, rres);
    EXPECT_EQ(status_of(rres), 401);
}

TEST_F(TwoFactorTest, CorrectTotpCodeCompletesLogin) {
    auto login_token = start_login();
    ASSERT_FALSE(login_token.empty());

    auto now = now_seconds();
    auto code = bsfchat::compute_totp(secret, static_cast<uint64_t>(now) / 30);

    auto req = json_request(json{{"login_token", login_token}, {"code", code}});
    httplib::Response res;
    accounts->handle_login_2fa(req, res);

    ASSERT_EQ(status_of(res), 200) << res.body;
    EXPECT_FALSE(json::parse(res.body)["session_id"].get<std::string>().empty());
    // Login token consumed on success.
    EXPECT_FALSE(store->validate_login_token(login_token).has_value());
}

TEST_F(TwoFactorTest, BackupCodesAreHashedAtRestAndSingleUse) {
    auto totp = store->get_totp("acct-1");
    ASSERT_TRUE(totp.has_value());
    // Plaintext must not be recoverable from the stored blob.
    EXPECT_EQ(totp->backup_codes_json.find("BACKUPAA"), std::string::npos);
    EXPECT_NE(totp->backup_codes_json.find("$pbkdf2"), std::string::npos);

    EXPECT_TRUE(store->consume_backup_code("acct-1", "BACKUPAA"));
    EXPECT_FALSE(store->consume_backup_code("acct-1", "BACKUPAA"));
    EXPECT_TRUE(store->consume_backup_code("acct-1", "BACKUPBB"));
}

TEST_F(AuthFlowTest, RepeatedPasswordFailuresLockOut) {
    // config.login_max_failures is 4 in this fixture.
    for (int i = 0; i < 4; ++i) {
        auto req = json_request(json{{"username", "alice"}, {"password", "nope"}});
        httplib::Response res;
        accounts->handle_login(req, res);
        EXPECT_EQ(status_of(res), 401);
    }

    // Even the correct password is refused while locked out.
    auto req = json_request(json{{"username", "alice"}, {"password", "correct horse battery"}});
    httplib::Response res;
    accounts->handle_login(req, res);
    EXPECT_EQ(status_of(res), 429);
}

// ---------------------------------------------------------------------------
// I5 — password hashing
// ---------------------------------------------------------------------------

TEST(PasswordUpgradeTest, LegacyHashesStillVerify) {
    // Format written by the old implementation: "$pbkdf2$<cost>$salt$hash",
    // produced here through the same PBKDF2 parameters it used.
    auto legacy = hash_password("hunter22", 4096);
    // Rewrite it into the legacy shape to prove the parser accepts it.
    auto first = legacy.find('$', 1);
    auto second = legacy.find('$', first + 1);
    auto tail = legacy.substr(second); // "$salt$hash"
    std::string legacy_form = "$pbkdf2$12" + tail;

    EXPECT_TRUE(verify_password("hunter22", legacy_form));
    EXPECT_FALSE(verify_password("wrong", legacy_form));
}

TEST(PasswordUpgradeTest, LegacyHashesAreFlaggedForRehash) {
    auto modern = hash_password("hunter22", kMinPbkdf2Iterations);
    EXPECT_FALSE(password_needs_rehash(modern, kMinPbkdf2Iterations));
    EXPECT_TRUE(password_needs_rehash(modern, kMinPbkdf2Iterations * 2));

    auto first = modern.find('$', 1);
    auto second = modern.find('$', first + 1);
    std::string legacy_form = "$pbkdf2$12" + modern.substr(second);
    EXPECT_TRUE(password_needs_rehash(legacy_form, kMinPbkdf2Iterations));
}

TEST(PasswordUpgradeTest, HashRecordsItsOwnIterationCount) {
    auto hash = hash_password("hunter22", 150000);
    EXPECT_TRUE(hash.starts_with("$pbkdf2-sha256$150000$"));
    EXPECT_TRUE(verify_password("hunter22", hash));
}

// ---------------------------------------------------------------------------
// Redirect URI matching
// ---------------------------------------------------------------------------

TEST(RedirectUriTest, LoopbackPortIsFlexibleButHostIsNot) {
    const std::string reg = "http://127.0.0.1/oauth/callback";
    EXPECT_TRUE(redirect_uri_matches(reg, "http://127.0.0.1:1234/oauth/callback"));
    EXPECT_TRUE(redirect_uri_matches(reg, "http://localhost:9999/oauth/callback"));
    EXPECT_FALSE(redirect_uri_matches(reg, "http://evil.example:1234/oauth/callback"));
    EXPECT_FALSE(redirect_uri_matches(reg, "http://localhost.evil.example/oauth/callback"));
    EXPECT_FALSE(redirect_uri_matches(reg, "http://127.0.0.1:1234@evil.example/oauth/callback"));
    EXPECT_FALSE(redirect_uri_matches(reg, "http://127.0.0.1:1234/other"));
    EXPECT_FALSE(redirect_uri_matches(reg, "https://127.0.0.1:1234/oauth/callback"));
    EXPECT_FALSE(redirect_uri_matches(reg, "http://127.0.0.1:1234/oauth/callback#frag"));
}

TEST(RedirectUriTest, NonLoopbackRequiresExactMatch) {
    const std::string reg = "https://app.example.com/cb";
    EXPECT_TRUE(redirect_uri_matches(reg, "https://app.example.com/cb"));
    EXPECT_FALSE(redirect_uri_matches(reg, "https://app.example.com/cb2"));
    EXPECT_FALSE(redirect_uri_matches(reg, "https://app.example.com:8443/cb"));
}

// ---------------------------------------------------------------------------
// The native (private-use URI scheme) callback — RFC 8252 section 7.1
//
// iOS cannot use the loopback redirect: handing off to the system browser
// suspends the app, so nothing ever accepts the callback connection and
// sign-in hangs. It presents ASWebAuthenticationSession in-process and
// redirects to bsfchat://oauth/callback instead.
// ---------------------------------------------------------------------------

TEST(RedirectUriTest, PrivateUseSchemeRequiresExactMatch) {
    // The port-flexible rule is for loopback http only. A custom scheme must
    // not inherit it — if it did, "bsfchat://oauth/callback" would start
    // matching things that merely look like it.
    const std::string reg = "bsfchat://oauth/callback";
    EXPECT_TRUE(redirect_uri_matches(reg, "bsfchat://oauth/callback"));
    EXPECT_FALSE(redirect_uri_matches(reg, "bsfchat://oauth/callback2"));
    EXPECT_FALSE(redirect_uri_matches(reg, "bsfchat://evil/oauth/callback"));
    EXPECT_FALSE(redirect_uri_matches(reg, "bsfchat://oauth/callback#frag"));
    EXPECT_FALSE(redirect_uri_matches(reg, "bsfchatx://oauth/callback"));
    EXPECT_FALSE(redirect_uri_matches(reg, "http://oauth/callback"));
    EXPECT_FALSE(redirect_uri_matches(reg, "bsfchat://oauth/callback/"));
}

TEST(FirstPartyClientTest, RegistrationCarriesBothCallbackShapes) {
    // What the client actually sends, byte for byte. The iOS client builds
    // this string from oidc::kNativeRedirectUri; /token compares it to the
    // stored value exactly, so a difference here is an iOS-only failure that
    // no desktop test would catch.
    const std::string uris = first_party_redirect_uris();
    EXPECT_NE(uris.find("\"bsfchat://oauth/callback\""), std::string::npos) << uris;
    EXPECT_NE(uris.find("\"http://localhost/oauth/callback\""), std::string::npos) << uris;
    EXPECT_NE(uris.find("\"http://127.0.0.1/oauth/callback\""), std::string::npos) << uris;
}

TEST(FirstPartyClientTest, SeedsAPublicClientSoPkceStaysMandatory) {
    IdentityStore store(":memory:");
    store.initialize();
    ensure_first_party_client(store);

    auto client = store.get_oauth_client("bsfchat-desktop");
    ASSERT_TRUE(client.has_value());
    // The whole safety argument for registering a scheme any app on the
    // device can claim rests on this being empty: no secret means public
    // means PKCE is enforced at /authorize and /token, so a stolen code is
    // worthless without the verifier.
    EXPECT_TRUE(client->client_secret.empty());
    EXPECT_EQ(client->redirect_uris, std::string(first_party_redirect_uris()));
}

TEST(FirstPartyClientTest, AnExistingLoopbackOnlyRegistrationIsWidened) {
    // Every deployment that predates the iOS client is sitting on this exact
    // value. Left alone, it refuses every iOS sign-in with "Invalid
    // redirect_uri for this client" and the fix looks like a client bug.
    IdentityStore store(":memory:");
    store.initialize();

    OAuthClient existing;
    existing.client_id = "bsfchat-desktop";
    existing.client_secret = "";
    existing.name = "BSFChat Desktop";
    existing.redirect_uris =
        R"(["http://127.0.0.1/oauth/callback","http://localhost/oauth/callback"])";
    existing.created_at = now_seconds();
    ASSERT_TRUE(store.create_oauth_client(existing));

    ensure_first_party_client(store);

    auto client = store.get_oauth_client("bsfchat-desktop");
    ASSERT_TRUE(client.has_value());
    EXPECT_EQ(client->redirect_uris, std::string(first_party_redirect_uris()));
}

TEST(FirstPartyClientTest, ACustomisedRegistrationIsLeftAlone) {
    // Only the exact values this project shipped are upgraded. An operator
    // who narrowed or extended the list keeps what they wrote.
    IdentityStore store(":memory:");
    store.initialize();

    const std::string custom = R"(["http://127.0.0.1/oauth/callback"])";
    OAuthClient existing;
    existing.client_id = "bsfchat-desktop";
    existing.client_secret = "";
    existing.name = "BSFChat Desktop";
    existing.redirect_uris = custom;
    existing.created_at = now_seconds();
    ASSERT_TRUE(store.create_oauth_client(existing));

    ensure_first_party_client(store);

    auto client = store.get_oauth_client("bsfchat-desktop");
    ASSERT_TRUE(client.has_value());
    EXPECT_EQ(client->redirect_uris, custom);
}

TEST_F(AuthFlowTest, NativeCallbackCompletesTheAuthorizationCodeFlow) {
    // The iOS sign-in, end to end through the handlers: authorize with the
    // private-use redirect, consent, then redeem the code with the verifier.
    auto location = authorize_and_consent(
        "bsfchat-desktop", "bsfchat://oauth/callback", s256_challenge(kVerifier));
    ASSERT_FALSE(location.empty());
    // The provider must redirect to the scheme itself — this is the URL
    // ASWebAuthenticationSession watches for, and anything else leaves the
    // sheet open.
    EXPECT_TRUE(location.starts_with("bsfchat://oauth/callback?")) << location;

    auto code = query_param(location, "code");
    ASSERT_FALSE(code.empty()) << location;
    EXPECT_EQ(query_param(location, "state"), "xyz");

    auto req = form_request({
        {"grant_type", "authorization_code"},
        {"code", code},
        {"redirect_uri", "bsfchat://oauth/callback"},
        {"client_id", "bsfchat-desktop"},
        {"code_verifier", kVerifier},
    });
    httplib::Response res;
    oidc->handle_token(req, res);
    ASSERT_EQ(status_of(res), 200) << res.body;
    EXPECT_FALSE(json::parse(res.body)["id_token"].get<std::string>().empty());
}

TEST_F(AuthFlowTest, NativeCallbackWithoutPkceIsRejectedAtAuthorize) {
    // The load-bearing check for a scheme another app can claim. Without it,
    // a hijacked redirect would be a complete account takeover.
    httplib::Request req;
    req.method = "GET";
    req.set_header("Cookie", "session=" + browser_session);
    req.params.emplace("client_id", "bsfchat-desktop");
    req.params.emplace("redirect_uri", "bsfchat://oauth/callback");
    req.params.emplace("response_type", "code");
    req.params.emplace("scope", "openid");
    req.params.emplace("state", "st");

    httplib::Response res;
    oidc->handle_authorize(req, res);

    EXPECT_EQ(status_of(res), 302);
    EXPECT_EQ(query_param(extract_location(res), "error"), "invalid_request");
    EXPECT_TRUE(query_param(extract_location(res), "code").empty());
}

TEST_F(AuthFlowTest, NativeCallbackCodeIsUselessWithoutTheVerifier) {
    // The attack this defends against: another app registers bsfchat://,
    // wins the redirect, and presents the code it caught. It never saw the
    // verifier, so the grant fails.
    auto location = authorize_and_consent(
        "bsfchat-desktop", "bsfchat://oauth/callback", s256_challenge(kVerifier));
    auto code = query_param(location, "code");
    ASSERT_FALSE(code.empty());

    auto stolen = form_request({
        {"grant_type", "authorization_code"},
        {"code", code},
        {"redirect_uri", "bsfchat://oauth/callback"},
        {"client_id", "bsfchat-desktop"},
        {"code_verifier", "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"},
    });
    httplib::Response res;
    oidc->handle_token(stolen, res);
    EXPECT_EQ(status_of(res), 400);
    EXPECT_EQ(json::parse(res.body)["error"], "invalid_grant");

    // And with no verifier at all.
    auto none = form_request({
        {"grant_type", "authorization_code"},
        {"code", code},
        {"redirect_uri", "bsfchat://oauth/callback"},
        {"client_id", "bsfchat-desktop"},
    });
    httplib::Response nres;
    oidc->handle_token(none, nres);
    EXPECT_EQ(status_of(nres), 400);
    EXPECT_EQ(json::parse(nres.body)["error"], "invalid_grant");
}

TEST_F(AuthFlowTest, NativeCallbackCannotBeSwappedForLoopbackAtToken) {
    // RFC 6749 4.1.3: /token's redirect_uri must be identical to the one the
    // code was issued against. Both of these are registered for this client,
    // which is exactly why the check has to be equality and not membership.
    auto location = authorize_and_consent(
        "bsfchat-desktop", "bsfchat://oauth/callback", s256_challenge(kVerifier));
    auto code = query_param(location, "code");
    ASSERT_FALSE(code.empty());

    auto req = form_request({
        {"grant_type", "authorization_code"},
        {"code", code},
        {"redirect_uri", "http://localhost:41234/oauth/callback"},
        {"client_id", "bsfchat-desktop"},
        {"code_verifier", kVerifier},
    });
    httplib::Response res;
    oidc->handle_token(req, res);
    EXPECT_EQ(status_of(res), 400);
    EXPECT_EQ(json::parse(res.body)["error"], "invalid_grant");
}

TEST_F(AuthFlowTest, AnUnregisteredNativeSchemeIsRejected) {
    // Adding one private-use scheme must not open the door to any other.
    for (const char* uri : {"bsfchatx://oauth/callback",
                            "bsfchat://oauth/callback2",
                            "bsfchat://evil/oauth/callback"}) {
        httplib::Request req;
        req.method = "GET";
        req.set_header("Cookie", "session=" + browser_session);
        req.params.emplace("client_id", "bsfchat-desktop");
        req.params.emplace("redirect_uri", uri);
        req.params.emplace("response_type", "code");
        req.params.emplace("scope", "openid");
        req.params.emplace("code_challenge", s256_challenge(kVerifier));
        req.params.emplace("code_challenge_method", "S256");

        httplib::Response res;
        oidc->handle_authorize(req, res);
        // In-band 400, never a redirect: the URI was never validated, so it
        // is not somewhere an error may be sent.
        EXPECT_EQ(status_of(res), 400) << uri;
    }
}


TEST(WebUtilTest, PercentEncodingRoundTrips) {
    const std::string raw = "a&b=c?d #e/f";
    EXPECT_EQ(percent_decode(percent_encode(raw)), raw);
    EXPECT_EQ(percent_encode("a&b"), "a%26b");
}

TEST(WebUtilTest, CookieParsingMatchesWholeNames) {
    EXPECT_EQ(get_cookie("session=abc", "session").value_or(""), "abc");
    EXPECT_EQ(get_cookie("theme=x; session=abc; z=1", "session").value_or(""), "abc");
    EXPECT_FALSE(get_cookie("mysession=abc", "session").has_value());
    EXPECT_FALSE(get_cookie("sessionx=abc", "session").has_value());
}

// ---------------------------------------------------------------------------
// Schema migration — an existing database must not be bricked or emptied
// ---------------------------------------------------------------------------

TEST(SchemaMigrationTest, UpgradesAPreExistingDatabaseInPlace) {
    auto db_path = bsfchat::test::unique_temp_file("bsfchat_id_migration_test", ".db");
    std::filesystem::remove(db_path);
    std::filesystem::remove(db_path.string() + "-wal");
    std::filesystem::remove(db_path.string() + "-shm");

    auto now = now_seconds();

    // Build a database with the ORIGINAL schema (no token_type/scope/client_id
    // on sessions, no attempts on login_tokens, plaintext backup codes).
    {
        sqlite3* raw = nullptr;
        ASSERT_EQ(sqlite3_open(db_path.c_str(), &raw), SQLITE_OK);
        auto run = [&](const std::string& sql) {
            char* err = nullptr;
            ASSERT_EQ(sqlite3_exec(raw, sql.c_str(), nullptr, nullptr, &err), SQLITE_OK)
                << (err ? err : "");
        };
        run("CREATE TABLE accounts (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE,"
            " password_hash TEXT, display_name TEXT, avatar_url TEXT, is_admin BOOLEAN DEFAULT FALSE,"
            " created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)");
        run("CREATE TABLE sessions (session_id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id),"
            " created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)");
        run("CREATE TABLE user_totp (account_id TEXT PRIMARY KEY REFERENCES accounts(id), secret TEXT NOT NULL,"
            " enabled INTEGER NOT NULL DEFAULT 0, backup_codes TEXT,"
            " created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')))");
        run("CREATE TABLE login_tokens (token TEXT PRIMARY KEY, account_id TEXT NOT NULL, expires_at INTEGER NOT NULL)");

        run("INSERT INTO accounts (id, username, password_hash, created_at, updated_at) VALUES"
            " ('old-1', 'bob', '$pbkdf2$12$aabb$ccdd', " + std::to_string(now) + ", " + std::to_string(now) + ")");
        // A browser session (7 day TTL) and an OIDC access token (1 hour TTL).
        run("INSERT INTO sessions VALUES ('old-browser', 'old-1', " + std::to_string(now) +
            ", " + std::to_string(now + 604800) + ")");
        run("INSERT INTO sessions VALUES ('old-access', 'old-1', " + std::to_string(now) +
            ", " + std::to_string(now + 3600) + ")");
        run("INSERT INTO user_totp (account_id, secret, enabled, backup_codes) VALUES"
            " ('old-1', 'JBSWY3DPEHPK3PXP', 1, '[\"PLAINAAA\",\"PLAINBBB\"]')");
        sqlite3_close(raw);
    }

    // Opening with the new code must migrate rather than throw.
    {
        IdentityStore store(db_path.string());
        ASSERT_NO_THROW(store.initialize());

        // Existing accounts survive.
        auto account = store.get_account_by_username("bob");
        ASSERT_TRUE(account.has_value());

        // The long-lived row stays a browser session; the 1 hour one is
        // reclassified as an OIDC access token and loses portal authority.
        EXPECT_TRUE(store.get_browser_session("old-browser").has_value());
        EXPECT_FALSE(store.get_browser_session("old-access").has_value());
        EXPECT_TRUE(store.get_oidc_access_token("old-access").has_value());

        // Only the browser session is listed to the user.
        auto sessions = store.list_sessions_for_account("old-1");
        ASSERT_EQ(sessions.size(), 1u);
        EXPECT_EQ(sessions[0].session_id, hash_token("old-browser"));

        // Backup codes were hashed in place but still redeem.
        auto totp = store.get_totp("old-1");
        ASSERT_TRUE(totp.has_value());
        EXPECT_EQ(totp->backup_codes_json.find("PLAINAAA"), std::string::npos);
        EXPECT_TRUE(store.consume_backup_code("old-1", "PLAINAAA"));
        EXPECT_FALSE(store.consume_backup_code("old-1", "PLAINAAA"));

        // New columns are usable.
        store.create_login_token("lt-1", "old-1", now + 300);
        EXPECT_FALSE(store.record_login_token_failure("lt-1", 3));
    }

    // Re-opening an already-migrated database must be a no-op, not an error.
    {
        IdentityStore store(db_path.string());
        ASSERT_NO_THROW(store.initialize());
        EXPECT_TRUE(store.get_account_by_username("bob").has_value());
    }

    std::filesystem::remove(db_path);
    std::filesystem::remove(db_path.string() + "-wal");
    std::filesystem::remove(db_path.string() + "-shm");
}

TEST(WebUtilTest, ScopeMatchingIsTokenwise) {
    EXPECT_TRUE(scope_contains("openid profile", "openid"));
    EXPECT_TRUE(scope_contains("openid profile", "profile"));
    EXPECT_FALSE(scope_contains("openid profile", "email"));
    EXPECT_FALSE(scope_contains("openidx", "openid"));
}
