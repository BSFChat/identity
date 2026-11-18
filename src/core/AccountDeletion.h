#pragma once

#include "store/IdentityStore.h"

#include <string>

namespace bsfchat::id {

// Operator-driven account deletion (audit 2026-11-15, I-12), for
//   bsfchat-id --config <file> --delete-account <username>
// (main.cpp), the counterpart of the self-service POST /api/account/delete.
// The account becomes a tombstone as IdentityStore::delete_account()
// describes: personal data and every credential gone, username reserved.
struct AccountDeletionResult {
    enum class Status {
        Deleted,
        NoSuchAccount,
        AlreadyDeleted,
        // The only administrator left: refused, nothing changed (audit I2-4).
        LastAdmin,
        StoreFailed,
    };
    Status status = Status::StoreFailed;
    std::string message;    // human-readable, for the operator's terminal
    std::string account_id; // set when the account was found
};

AccountDeletionResult delete_account_by_username(IdentityStore& store, const std::string& username);

} // namespace bsfchat::id
