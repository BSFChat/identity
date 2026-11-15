#include "core/AccountDeletion.h"

namespace bsfchat::id {

AccountDeletionResult delete_account_by_username(IdentityStore& store, const std::string& username) {
    AccountDeletionResult result;

    auto account = store.get_account_by_username(username);
    if (!account) {
        result.status = AccountDeletionResult::Status::NoSuchAccount;
        result.message = "No account is named '" + username + "'";
        return result;
    }
    result.account_id = account->id;
    if (account->deleted()) {
        result.status = AccountDeletionResult::Status::AlreadyDeleted;
        result.message = "The account '" + username + "' was already deleted";
        return result;
    }
    if (!store.delete_account(account->id)) {
        result.status = AccountDeletionResult::Status::StoreFailed;
        result.message = "The account could not be deleted";
        return result;
    }
    result.status = AccountDeletionResult::Status::Deleted;
    result.message = "Deleted account '" + account->username + "' (" + account->id +
                     "): its personal data, 2FA, sessions, app sign-ins and server list are gone; "
                     "the username stays reserved";
    return result;
}

} // namespace bsfchat::id
