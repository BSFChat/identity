#include "core/PasswordReset.h"
#include "crypto/PasswordHash.h"


namespace bsfchat::id {

PasswordResetResult reset_account_password(IdentityStore& store, const std::string& username,
                                           const std::string& new_password, int hash_iterations) {
    PasswordResetResult result;

    auto account = store.get_account_by_username(username);
    if (!account) {
        result.status = PasswordResetResult::Status::NoSuchAccount;
        result.message = "No account is named '" + username + "'";
        return result;
    }
    result.account_id = account->id;
    result.account_disabled = account->disabled();

    if (auto err = password_policy_error(new_password)) {
        result.status = PasswordResetResult::Status::PolicyRejected;
        result.message = *err;
        return result;
    }

    if (!store.update_password_hash(account->id, hash_password(new_password, hash_iterations))) {
        result.status = PasswordResetResult::Status::StoreFailed;
        result.message = "The new password could not be saved";
        return result;
    }

    // The same revocation the password-change endpoint does, with nothing
    // kept (see the header).
    result.signed_out = store.revoke_account_credentials(account->id);
    result.status = PasswordResetResult::Status::Reset;
    result.message = "Password reset for '" + account->username + "' (" + account->id + "); " +
                     std::to_string(result.signed_out) + " session(s)/app(s) signed out";
    if (result.account_disabled) {
        result.message += ". Note: the account is DISABLED and still cannot sign in";
    }
    return result;
}

} // namespace bsfchat::id
