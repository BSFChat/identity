// The mobile reviewer path, end to end, as two authorizations in one browser
// session.
//
// A phone signing in with a BSFChat ID runs the provider twice:
//
//   1. /authorize with NO `resource` — the account-level sign-in whose access
//      token is used to read /api/servers, i.e. "which servers am I in?".
//   2. /authorize WITH `resource=<the server found in that list>` — the
//      sign-in that produces the id_token actually posted to the chat server.
//
// Step 2 was failing in production at the consent POST with
// "Authorization request does not belong to this session" (403). These tests
// pin the provider's half of that path so the answer cannot drift.

#include <gtest/gtest.h>

#include "api/AccountHandler.h"
#include "api/OidcHandler.h"
#include "core/Config.h"
#include "core/ClientRegistration.h"
#include "core/WebUtil.h"
#include "crypto/PasswordHash.h"
#include "store/IdentityStore.h"
#include "TempPaths.h"

#include <nlohmann/json.hpp>
#include <openssl/sha.h>

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
// What the phone actually asks for (oidc::kNativeRedirectUri).
const std::string kNativeRedirect = "bsfchat://oauth/callback";
const std::string kUat = "https://uat.bsfchat.com";

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

class MobileSecondSignInTest : public ::testing::Test {
protected:
    void SetUp() override {
        keys_dir = bsfchat::test::unique_temp_dir("bsfchat_id_mobile2_keys");

        config.password_hash_iterations = kMinPbkdf2Iterations;
        config.login_rate_limit = 1000;
        config.cookie_secure = true;
        config.issuer_url = "https://id.bsfchat.com";

        store = std::make_unique<IdentityStore>(":memory:");
        store->initialize();
        key_manager = std::make_unique<KeyManager>(keys_dir.string());
        accounts = std::make_unique<AccountHandler>(*store, config);
        oidc = std::make_unique<OidcHandler>(*store, *key_manager, *accounts, config);

        auto now = now_seconds();

        Account account;
        account.id = "acct-review";
        account.username = "appreview";
        account.email = "appreview@example.com";
        account.display_name = "App Review";
        account.password_hash =
            hash_password("correct horse battery", config.password_hash_iterations);
        account.created_at = now;
        account.updated_at = now;
        ASSERT_TRUE(store->create_account(account));

        OAuthClient desktop;
        desktop.client_id = "bsfchat-desktop";
        desktop.client_secret = "";
        desktop.name = "BSFChat";
        desktop.redirect_uris = first_party_redirect_uris();
        desktop.created_at = now;
        ASSERT_TRUE(store->create_oauth_client(desktop));

        // The one server this account belongs to — the reviewer's shape.
        store->add_server_membership("acct-review", kUat, "BSFChat UAT");

        // Sign in exactly as login.html does, and keep the cookie the browser
        // would keep.
        httplib::Request login;
        login.method = "POST";
        login.remote_addr = "10.0.0.1";
        login.set_header("Content-Type", "application/json");
        login.body = json{{"username", "appreview"},
                          {"password", "correct horse battery"}}.dump();
        httplib::Response lres;
        accounts->handle_login(login, lres);
        ASSERT_EQ(status_of(lres), 200) << lres.body;

        auto set_cookie = header_of(lres, "Set-Cookie");
        auto eq = set_cookie.find('=');
        auto semi = set_cookie.find(';');
        ASSERT_NE(eq, std::string::npos);
        cookie = set_cookie.substr(0, semi);          // "session=<id>"
        session_id = set_cookie.substr(eq + 1, semi - eq - 1);
        ASSERT_FALSE(session_id.empty());
    }

    void TearDown() override { std::filesystem::remove_all(keys_dir); }

    // GET /authorize as the browser would, with the live session cookie.
    httplib::Response authorize(const std::string& challenge, const std::string& state,
                                const std::string& nonce, const std::string& resource) {
        httplib::Request req;
        req.method = "GET";
        req.remote_addr = "10.0.0.1";
        req.set_header("Cookie", cookie);
        req.params.emplace("client_id", "bsfchat-desktop");
        req.params.emplace("redirect_uri", kNativeRedirect);
        req.params.emplace("response_type", "code");
        req.params.emplace("scope", "openid profile");
        req.params.emplace("code_challenge", challenge);
        req.params.emplace("code_challenge_method", "S256");
        req.params.emplace("state", state);
        req.params.emplace("nonce", nonce);
        if (!resource.empty()) req.params.emplace("resource", resource);

        httplib::Response res;
        oidc->handle_authorize(req, res);
        return res;
    }

    httplib::Response decide(const std::string& token, const std::string& approve = "true") {
        auto req = form_request({{"consent_token", token}, {"approve", approve}});
        req.set_header("Cookie", cookie);
        httplib::Response res;
        oidc->handle_authorize_decision(req, res);
        return res;
    }

    httplib::Response redeem(const std::string& code, const std::string& resource) {
        std::map<std::string, std::string> body{
            {"grant_type", "authorization_code"},
            {"code", code},
            {"redirect_uri", kNativeRedirect},
            {"client_id", "bsfchat-desktop"},
            {"code_verifier", kVerifier},
        };
        if (!resource.empty()) body["resource"] = resource;
        auto req = form_request(body);
        httplib::Response res;
        oidc->handle_token(req, res);
        return res;
    }

    static std::string consent_token_from(const std::string& html) {
        const std::string marker = "name=\"consent_token\" value=\"";
        auto pos = html.find(marker);
        if (pos == std::string::npos) return "";
        auto start = pos + marker.size();
        return html.substr(start, html.find('"', start) - start);
    }

    std::filesystem::path keys_dir;
    Config config;
    std::unique_ptr<IdentityStore> store;
    std::unique_ptr<KeyManager> key_manager;
    std::unique_ptr<AccountHandler> accounts;
    std::unique_ptr<OidcHandler> oidc;
    std::string cookie;
    std::string session_id;
};

} // namespace

// The whole reviewer path: account sign-in, server list, server sign-in.
TEST_F(MobileSecondSignInTest, SecondAuthorizationInTheSameSessionSucceeds) {
    const auto challenge = s256_challenge(kVerifier);

    // --- 1. account-level authorization, no resource ------------------------
    auto first = authorize(challenge, "state-1", "nonce-1", "");
    ASSERT_EQ(status_of(first), 200) << first.body;
    auto first_token = consent_token_from(first.body);
    ASSERT_FALSE(first_token.empty());

    auto first_decision = decide(first_token);
    ASSERT_EQ(status_of(first_decision), 302) << first_decision.body;
    auto first_code = query_param(header_of(first_decision, "Location"), "code");
    ASSERT_FALSE(first_code.empty());

    auto first_tokens = redeem(first_code, "");
    ASSERT_EQ(status_of(first_tokens), 200) << first_tokens.body;
    auto access_token = json::parse(first_tokens.body).value("access_token", "");
    ASSERT_FALSE(access_token.empty());

    // --- 2. GET /api/servers with that access token -------------------------
    httplib::Request servers;
    servers.method = "GET";
    servers.remote_addr = "10.0.0.1";
    servers.set_header("Authorization", "Bearer " + access_token);
    httplib::Response sres;
    accounts->handle_list_servers(servers, sres);
    ASSERT_EQ(status_of(sres), 200) << sres.body;
    auto list = json::parse(sres.body);
    ASSERT_TRUE(list.is_array());
    ASSERT_EQ(list.size(), 1u);
    EXPECT_EQ(list[0].value("server_url", ""), kUat);

    // --- 3. the server-bound authorization, same browser session ------------
    auto second = authorize(challenge, "state-2", "nonce-2", kUat);
    ASSERT_EQ(status_of(second), 200) << second.body;
    auto second_token = consent_token_from(second.body);
    ASSERT_FALSE(second_token.empty());
    EXPECT_NE(second_token, first_token);

    auto second_decision = decide(second_token);
    EXPECT_EQ(status_of(second_decision), 302) << second_decision.body;
    auto second_code = query_param(header_of(second_decision, "Location"), "code");
    EXPECT_FALSE(second_code.empty());
}

// The same, but with the first authorization's consent never decided — which
// is what happens whenever the app opens a second /authorize before the first
// prompt was answered.
TEST_F(MobileSecondSignInTest, AnUndecidedPromptDoesNotInvalidateTheNextOne) {
    const auto challenge = s256_challenge(kVerifier);

    auto first = authorize(challenge, "state-1", "nonce-1", "");
    ASSERT_EQ(status_of(first), 200);
    auto stale = consent_token_from(first.body);
    ASSERT_FALSE(stale.empty());

    auto second = authorize(challenge, "state-2", "nonce-2", kUat);
    ASSERT_EQ(status_of(second), 200);
    auto live = consent_token_from(second.body);
    ASSERT_FALSE(live.empty());

    auto decision = decide(live);
    EXPECT_EQ(status_of(decision), 302) << decision.body;
}

// The failure the phone actually hit: the browser is showing a prompt from an
// authorization the app has since superseded with another one. Approving the
// page on screen must still work — a later /authorize does not invalidate an
// earlier prompt — and approving a prompt twice must not mint a second code.
TEST_F(MobileSecondSignInTest, AStalePromptIsStillTheUsersToApproveOnce) {
    const auto challenge = s256_challenge(kVerifier);

    auto shown = authorize(challenge, "state-a", "nonce-a", kUat);
    ASSERT_EQ(status_of(shown), 200);
    const auto shown_token = consent_token_from(shown.body);
    ASSERT_FALSE(shown_token.empty());

    // The client fans out and asks again before the user has tapped anything.
    auto superseding = authorize(challenge, "state-b", "nonce-b", kUat);
    ASSERT_EQ(status_of(superseding), 200);
    ASSERT_NE(consent_token_from(superseding.body), shown_token);

    // The user taps Allow on the page in front of them, which is the first.
    auto granted = decide(shown_token);
    EXPECT_EQ(status_of(granted), 302) << granted.body;
    EXPECT_FALSE(query_param(header_of(granted, "Location"), "code").empty());

    // ...and a resubmission of it is named for what it is, with no second
    // code and no redirect that could disturb whatever sign-in is live now.
    auto again = decide(shown_token);
    EXPECT_EQ(status_of(again), 409) << again.body;
    EXPECT_TRUE(header_of(again, "Location").empty());
    EXPECT_NE(again.body.find("Already approved"), std::string::npos);
}

// A prompt left unanswered past its five minutes hands the app a real answer
// rather than letting it sit until its own timeout. The `state` must come
// back so the client can tell this is the attempt it is waiting on.
TEST_F(MobileSecondSignInTest, AnExpiredPromptSendsTheUserBackToTheApp) {
    ConsentRequest stale;
    stale.token = "stale-consent-token";
    stale.session_id = session_id;       // hashed by the store
    stale.account_id = "acct-review";
    stale.client_id = "bsfchat-desktop";
    stale.redirect_uri = kNativeRedirect;
    stale.scope = "openid profile";
    stale.state = "state-waiting";
    stale.code_challenge = s256_challenge(kVerifier);
    stale.expires_at = now_seconds() - 1;
    stale.resource = kUat;
    stale.nonce = "nonce-waiting";
    ASSERT_TRUE(store->store_consent_request(stale));

    auto res = decide("stale-consent-token");
    ASSERT_EQ(status_of(res), 302) << res.body;
    const auto location = header_of(res, "Location");
    EXPECT_EQ(location.rfind(kNativeRedirect, 0), 0u) << location;
    EXPECT_EQ(query_param(location, "error"), "access_denied");
    EXPECT_EQ(query_param(location, "state"), "state-waiting");
    EXPECT_TRUE(query_param(location, "code").empty());
}

// The CSRF guard is unchanged, and must stay unchanged: a decision posted from
// any other session is refused, tells the poster nothing about the prompt, and
// leaves it pending for the session it belongs to.
TEST_F(MobileSecondSignInTest, AForeignSessionLearnsNothingAndBurnsNothing) {
    const auto challenge = s256_challenge(kVerifier);
    auto shown = authorize(challenge, "state-2", "nonce-2", kUat);
    ASSERT_EQ(status_of(shown), 200);
    const auto token = consent_token_from(shown.body);
    ASSERT_FALSE(token.empty());

    auto now = now_seconds();
    Session other;
    other.session_id = "someone-elses-session";
    other.account_id = "acct-review";
    other.created_at = now;
    other.expires_at = now + 3600;
    other.token_type = token_type::kBrowserSession;
    ASSERT_TRUE(store->create_session(other));

    auto foreign = form_request({{"consent_token", token}, {"approve", "true"}});
    foreign.set_header("Cookie", "session=someone-elses-session");
    httplib::Response fres;
    oidc->handle_authorize_decision(foreign, fres);

    EXPECT_EQ(status_of(fres), 403);
    EXPECT_TRUE(header_of(fres, "Location").empty());
    // Nothing about the prompt leaks — not the client, not where it points.
    EXPECT_EQ(fres.body.find(kNativeRedirect), std::string::npos);
    EXPECT_EQ(fres.body.find(kUat), std::string::npos);

    // ...and the rightful session can still complete it.
    auto owner = decide(token);
    EXPECT_EQ(status_of(owner), 302) << owner.body;
    EXPECT_FALSE(query_param(header_of(owner, "Location"), "code").empty());
}

// Three identical /authorize hits (what production's nginx log shows) each
// mint their own prompt; approving the one the user is actually looking at
// must work.
TEST_F(MobileSecondSignInTest, RepeatedAuthorizeHitsDoNotInvalidateEachOther) {
    const auto challenge = s256_challenge(kVerifier);

    std::string last;
    for (int i = 0; i < 3; ++i) {
        auto res = authorize(challenge, "state-2", "nonce-2", kUat);
        ASSERT_EQ(status_of(res), 200);
        last = consent_token_from(res.body);
        ASSERT_FALSE(last.empty());
    }

    auto decision = decide(last);
    EXPECT_EQ(status_of(decision), 302) << decision.body;
}
