#pragma once

#include "store/IdentityStore.h"
#include "core/Config.h"

#include <httplib.h>

namespace bsfchat::id {

// TODO: Phase 1F — External SSO provider integration.
// This handler will support connecting external identity providers
// (Google, GitHub, etc.) for federated login.

class SsoHandler {
public:
    SsoHandler(IdentityStore& store, const Config& config);

    // TODO: Implement SSO callback endpoints
    // void handle_sso_redirect(const httplib::Request& req, httplib::Response& res);
    // void handle_sso_callback(const httplib::Request& req, httplib::Response& res);

private:
    IdentityStore& store_;
    const Config& config_;
};

} // namespace bsfchat::id
