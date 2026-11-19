#pragma once

#include "store/IdentityStore.h"

#include <string>

namespace bsfchat::id {

// Operator commands run from main.cpp against the service's database
// (audit 3, M3 and the 2FA recovery path). Like --reset-password, these are
// the parts with a seam for tests; main.cpp only prints the outcome.
struct OperatorResult {
    bool ok = false;        // something was changed, or it already was so
    std::string message;    // for the operator's terminal
};

// --grant-admin / --revoke-admin <username>. Revoking the last enabled
// administrator is refused. Granting to a deleted account is refused.
OperatorResult set_admin_by_username(IdentityStore& store, const std::string& username,
                                     bool admin);

// --disable-2fa <username>: the recovery path for a user who lost both
// their authenticator and their backup codes. Removes the second factor and
// signs the account out everywhere, as turning 2FA off in the portal does.
OperatorResult disable_2fa_by_username(IdentityStore& store, const std::string& username);

// The text both the portal and the CLI give when the last administrator
// tries to leave (deletion, revocation).
inline constexpr const char* kGrantAdminHint =
    "Make another account an administrator first: on the server, run "
    "bsfchat-id --config <file> --grant-admin <username>";

} // namespace bsfchat::id
