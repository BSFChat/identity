#include "core/OperatorCommands.h"

namespace bsfchat::id {

OperatorResult set_admin_by_username(IdentityStore& store, const std::string& username,
                                     bool admin) {
    OperatorResult result;
    auto account = store.get_account_by_username(username);
    if (!account) {
        result.message = "No account is named '" + username + "'";
        return result;
    }
    const auto who = "'" + account->username + "' (" + account->id + ")";
    switch (store.set_admin(account->id, admin)) {
        case IdentityStore::SetAdminResult::Changed:
            result.ok = true;
            result.message = admin ? who + " is now an administrator"
                                   : who + " is no longer an administrator";
            if (admin && account->disabled()) {
                result.message += ". Note: the account is DISABLED and cannot sign in";
            }
            return result;
        case IdentityStore::SetAdminResult::Unchanged:
            result.ok = true;
            result.message = admin ? who + " is already an administrator"
                                   : who + " is not an administrator";
            return result;
        case IdentityStore::SetAdminResult::NoSuchAccount:
            result.message = "No account is named '" + username + "'";
            return result;
        case IdentityStore::SetAdminResult::Deleted:
            result.message = "The account " + who + " was deleted and cannot be an administrator";
            return result;
        case IdentityStore::SetAdminResult::LastAdmin:
            result.message = who + " is the only administrator left; grant another account "
                             "first with --grant-admin";
            return result;
    }
    return result;
}

OperatorResult disable_2fa_by_username(IdentityStore& store, const std::string& username) {
    OperatorResult result;
    auto account = store.get_account_by_username(username);
    if (!account) {
        result.message = "No account is named '" + username + "'";
        return result;
    }
    const auto who = "'" + account->username + "' (" + account->id + ")";
    auto totp = store.get_totp(account->id);
    if (!totp) {
        result.ok = true;
        result.message = who + " has no two-factor authentication set up";
        return result;
    }
    store.disable_totp(account->id);
    const int ended = store.revoke_account_credentials(account->id);
    result.ok = true;
    result.message = "Two-factor authentication removed from " + who + "; " +
                     std::to_string(ended) + " session(s)/app(s) signed out. They can sign in "
                     "with their password and set it up again";
    return result;
}

} // namespace bsfchat::id
