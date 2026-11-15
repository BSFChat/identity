#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace bsfchat::id {

// OWASP guidance (2023+) for PBKDF2-HMAC-SHA256 is 600,000 iterations.
inline constexpr int kDefaultPbkdf2Iterations = 600000;

// Anything below this in configuration is treated as a mistake and clamped up.
inline constexpr int kMinPbkdf2Iterations = 100000;

// PBKDF2-HMAC-SHA256 password hashing.
//
// Produces "$pbkdf2-sha256$<iterations>$<salt_hex>$<hash_hex>". The iteration
// count is recorded in the string, so raising the default never invalidates
// previously stored hashes.
//
// The legacy "$pbkdf2$<cost>$<salt_hex>$<hash_hex>" format (iterations =
// 1 << cost) is still accepted by verify_password so existing users can log in;
// callers should re-hash on successful login via password_needs_rehash().
std::string hash_password(const std::string& password, int iterations = kDefaultPbkdf2Iterations);

bool verify_password(const std::string& password, const std::string& stored_hash);

// True when the stored hash uses the legacy format or fewer iterations than the
// target, i.e. it should be upgraded next time the plaintext is available.
bool password_needs_rehash(const std::string& stored_hash, int target_iterations);

// The password policy, in one place: registration, the password change and
// the operator's --reset-password all apply it. nullopt when acceptable,
// otherwise a sentence fit to show the user.
inline constexpr size_t kMinPasswordLength = 8;
inline constexpr size_t kMaxPasswordLength = 1024;
std::optional<std::string> password_policy_error(std::string_view password);

} // namespace bsfchat::id
