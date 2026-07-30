#pragma once

#include "store/IdentityStore.h"
#include "crypto/KeyManager.h"
#include "core/Config.h"
#include "api/AccountHandler.h"

#include <httplib.h>

namespace bsfchat::id {

class OidcHandler {
public:
    OidcHandler(IdentityStore& store, KeyManager& key_manager, AccountHandler& account_handler, const Config& config);

    void handle_discovery(const httplib::Request& req, httplib::Response& res);
    void handle_authorize(const httplib::Request& req, httplib::Response& res);
    // Consent decision POSTed back from the page rendered by handle_authorize.
    void handle_authorize_decision(const httplib::Request& req, httplib::Response& res);
    void handle_token(const httplib::Request& req, httplib::Response& res);
    void handle_userinfo(const httplib::Request& req, httplib::Response& res);
    void handle_jwks(const httplib::Request& req, httplib::Response& res);
    void handle_revoke(const httplib::Request& req, httplib::Response& res);

private:
    std::string create_id_token(const Account& account, const std::string& client_id);
    std::string create_access_token();

    // Outcome of authenticating the caller of /token.
    struct ClientAuthResult {
        bool ok = false;
        std::string error;             // OAuth error code
        std::string description;
        bool requires_pkce = false;    // true for public (secret-less) clients
    };

    // Verifies the presented client credentials against the registered client.
    // Confidential clients must present their secret; public clients must not,
    // and must instead prove possession via PKCE.
    ClientAuthResult authenticate_client(const std::string& client_id,
                                         const std::string& presented_secret,
                                         bool secret_was_presented);

    // Renders the consent page for a validated authorization request.
    void render_consent_page(httplib::Response& res, const OAuthClient& client,
                             const Account& account, const std::string& scope,
                             const std::string& consent_token, const std::string& redirect_uri);

    IdentityStore& store_;
    KeyManager& key_manager_;
    AccountHandler& account_handler_;
    const Config& config_;
};

} // namespace bsfchat::id
