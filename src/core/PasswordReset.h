#pragma once

#include "store/IdentityStore.h"

#include <string>

namespace bsfchat::id {

// Operator-driven password recovery (audit 2026-11-15, I-2).
//
// This service sends no email, so there is no self-service reset: a user who
// has forgotten their password asks whoever runs the service, who runs
//   bsfchat-id --config <file> --reset-password <username>
// (main.cpp). This is the part of that command with a seam for tests.
struct PasswordResetResult {
    enum class Status {
        Reset,          // new password stored, every credential revoked
        NoSuchAccount,
        PolicyRejected, // the new password fails password_policy_error()
        StoreFailed,
    };
    Status status = Status::StoreFailed;
    std::string message;     // human-readable, for the operator's terminal
    std::string account_id;  // set when the account was found
    bool account_disabled = false;
    int signed_out = 0;      // sessions and app grants ended
};

// Sets `new_password` on the account named `username` (exact match, as
// stored) under the same policy as registration and the password change, and
// then ends everything the account is signed in with — browser sessions,
// access tokens, refresh tokens, pending codes and consent prompts — exactly
// as a password change does, except that no session is kept: the operator's
// terminal has none, and whoever knew the old password must not stay in.
// 2FA is left as it is; a disabled account stays disabled.
PasswordResetResult reset_account_password(IdentityStore& store, const std::string& username,
                                           const std::string& new_password, int hash_iterations);

} // namespace bsfchat::id
