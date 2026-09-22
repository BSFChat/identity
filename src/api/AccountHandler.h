#pragma once

#include "store/IdentityStore.h"
#include "core/Config.h"
#include "core/RateLimiter.h"

#include <httplib.h>

namespace bsfchat::id {

// Resolved credential for a request. `token_type` distinguishes a browser
// session cookie (full account authority) from an OIDC access token (scoped,
// and never sufficient for account management).
struct AuthContext {
    std::string account_id;
    std::string credential_id;
    std::string token_type;
    std::string scope;
    std::string client_id;    // OAuth client an access token was issued to; empty for a browser session

    bool authenticated() const { return !account_id.empty(); }
    bool is_browser_session() const { return token_type == token_type::kBrowserSession; }
};

class AccountHandler {
public:
    AccountHandler(IdentityStore& store, const Config& config);

    void handle_register(const httplib::Request& req, httplib::Response& res);
    void handle_login(const httplib::Request& req, httplib::Response& res);
    void handle_logout(const httplib::Request& req, httplib::Response& res);
    void handle_get_profile(const httplib::Request& req, httplib::Response& res);
    void handle_update_profile(const httplib::Request& req, httplib::Response& res);

    // Session management
    void handle_list_sessions(const httplib::Request& req, httplib::Response& res);
    void handle_revoke_session(const httplib::Request& req, httplib::Response& res);

    // 2FA / TOTP
    void handle_2fa_status(const httplib::Request& req, httplib::Response& res);
    void handle_2fa_setup(const httplib::Request& req, httplib::Response& res);
    void handle_2fa_verify(const httplib::Request& req, httplib::Response& res);
    void handle_2fa_disable(const httplib::Request& req, httplib::Response& res);
    void handle_login_2fa(const httplib::Request& req, httplib::Response& res);

    // Server memberships
    void handle_list_servers(const httplib::Request& req, httplib::Response& res);
    void handle_add_server(const httplib::Request& req, httplib::Response& res);
    void handle_remove_server(const httplib::Request& req, httplib::Response& res);

    // Returns the account behind a *browser session* credential, or "" if the
    // request does not carry one. An OIDC access token is deliberately NOT
    // accepted here: it must not be able to manage the account it was minted
    // from (list/revoke sessions, disable 2FA, reach admin endpoints).
    std::string get_session_account(const httplib::Request& req);

    // Resolves either credential kind. An OIDC access token is accepted only
    // when its granted scope contains `required_scope`.
    AuthContext authenticate(const httplib::Request& req, const std::string& required_scope);

    // Builds the Set-Cookie value for a browser session, honouring
    // config.cookie_secure.
    std::string session_cookie(const std::string& session_id, int max_age_seconds) const;

    // Periodic housekeeping for the in-memory limiter maps.
    void prune_limiters();

private:
    // Extracts the caller's remote address for rate-limit keying.
    static std::string client_key(const httplib::Request& req);

    IdentityStore& store_;
    const Config& config_;

    RateLimiter login_limiter_;
    FailureTracker login_failures_;
    FailureTracker totp_failures_;
};

} // namespace bsfchat::id
