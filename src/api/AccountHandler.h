#pragma once

#include "store/IdentityStore.h"
#include "core/ClientAddress.h"
#include "core/Config.h"
#include "core/RateLimiter.h"

#include <httplib.h>

#include <atomic>
#include <mutex>

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
    // Apps signed in with OAuth refresh tokens (one entry per grant), which
    // users could previously neither see nor revoke (security audit H4).
    void handle_list_apps(const httplib::Request& req, httplib::Response& res);
    void handle_revoke_app(const httplib::Request& req, httplib::Response& res);

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

    // Login-CSRF defence for state-changing endpoints (security audit H3).
    // Writes a 4xx and returns false when the request must be refused:
    //   * a body that is not application/json. A cross-site <form> can only
    //     send text/plain, urlencoded or multipart without a CORS preflight,
    //     and the preflight cannot succeed with credentials against our
    //     wildcard CORS policy — so requiring JSON is what actually stops a
    //     foreign page from posting a login and collecting the Set-Cookie;
    //   * a browser saying the request is cross-site (Sec-Fetch-Site), or,
    //     from browsers that do not send that, an Origin that is not the
    //     issuer's. Non-browser callers send neither and are unaffected.
    // `body_required` false lets a body-less request (DELETE, a bare logout)
    // through the Content-Type check; the origin check always applies.
    bool reject_unsafe_request(const httplib::Request& req, httplib::Response& res,
                               bool body_required = true);

    // The address per-client limits are keyed on, resolved through
    // config.trusted_proxies (core/ClientAddress.h). Empty when the client
    // cannot be told apart from others, which callers treat as "skip the
    // per-address limit", never as one shared bucket.
    std::string client_key(const httplib::Request& req);

private:
    // Creates a browser session, sets the cookie, and writes the login reply.
    void start_session(const Account& account, httplib::Response& res, int status = 200);
    // A PBKDF2 hash of nothing in particular, at the configured cost, so an
    // unknown username costs the same as a wrong password (security audit L2).
    const std::string& dummy_password_hash();

    IdentityStore& store_;
    const Config& config_;
    ClientAddressResolver client_address_;
    std::string issuer_origin_;

    RateLimiter login_limiter_;
    // Password failures per (client address, submitted username).
    FailureTracker login_failures_;
    // Password failures per submitted username alone, at a higher threshold.
    FailureTracker account_failures_;
    // Second-factor failures per account ("2fa-user:"), and enrolment.
    FailureTracker totp_failures_;

    std::once_flag dummy_hash_once_;
    std::string dummy_hash_;
    std::atomic<int64_t> last_proxy_warning_{0};
};

} // namespace bsfchat::id
