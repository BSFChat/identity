#pragma once

#include "store/IdentityStore.h"
#include "api/AccountHandler.h"
#include "core/Config.h"

#include <httplib.h>

namespace bsfchat::id {

class AdminHandler {
public:
    AdminHandler(IdentityStore& store, AccountHandler& account_handler, const Config& config);

    void handle_list_users(const httplib::Request& req, httplib::Response& res);
    void handle_disable_user(const httplib::Request& req, httplib::Response& res);
    void handle_list_clients(const httplib::Request& req, httplib::Response& res);
    void handle_create_client(const httplib::Request& req, httplib::Response& res);

private:
    bool require_admin(const httplib::Request& req, httplib::Response& res);

    IdentityStore& store_;
    AccountHandler& account_handler_;
    const Config& config_;
};

} // namespace bsfchat::id
