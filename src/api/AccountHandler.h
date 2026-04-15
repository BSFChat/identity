#pragma once

#include "store/IdentityStore.h"
#include "core/Config.h"

#include <httplib.h>

namespace bsfchat::id {

class AccountHandler {
public:
    AccountHandler(IdentityStore& store, const Config& config);

    void handle_register(const httplib::Request& req, httplib::Response& res);
    void handle_login(const httplib::Request& req, httplib::Response& res);
    void handle_logout(const httplib::Request& req, httplib::Response& res);
    void handle_get_profile(const httplib::Request& req, httplib::Response& res);
    void handle_update_profile(const httplib::Request& req, httplib::Response& res);

    // Helper to extract account_id from session cookie. Returns empty string if not authenticated.
    std::string get_session_account(const httplib::Request& req);

private:
    IdentityStore& store_;
    const Config& config_;
};

} // namespace bsfchat::id
