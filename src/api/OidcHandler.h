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
    void handle_token(const httplib::Request& req, httplib::Response& res);
    void handle_userinfo(const httplib::Request& req, httplib::Response& res);
    void handle_jwks(const httplib::Request& req, httplib::Response& res);
    void handle_revoke(const httplib::Request& req, httplib::Response& res);

private:
    std::string create_id_token(const Account& account, const std::string& client_id);
    std::string create_access_token();

    IdentityStore& store_;
    KeyManager& key_manager_;
    AccountHandler& account_handler_;
    const Config& config_;
};

} // namespace bsfchat::id
