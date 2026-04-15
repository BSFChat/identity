#pragma once

#include <string>

namespace bsfchat::id {

// PBKDF2-SHA256 password hashing (same approach as bsfchat server).
std::string hash_password(const std::string& password, int cost = 12);
bool verify_password(const std::string& password, const std::string& hash);

} // namespace bsfchat::id
