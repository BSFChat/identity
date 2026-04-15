#include "api/SsoHandler.h"

namespace bsfchat::id {

SsoHandler::SsoHandler(IdentityStore& store, const Config& config)
    : store_(store), config_(config) {
    // TODO: Phase 1F — Initialize SSO provider configurations
}

} // namespace bsfchat::id
