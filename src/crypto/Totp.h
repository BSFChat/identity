#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace bsfchat {

// Generate a 20-byte random secret encoded as Base32 (RFC 4648, no padding).
std::string generate_totp_secret();

// Compute a 6-digit TOTP code for the given base32 secret and time step.
std::string compute_totp(const std::string& base32_secret, uint64_t time_step);

// Verify a TOTP code against the current time with a +/- window tolerance.
bool verify_totp(const std::string& base32_secret, const std::string& code, int window = 1);

// As verify_totp, but returns the time-step the code matched, so the caller
// can refuse a step it has already accepted (a code is otherwise replayable
// for as long as the window lasts, about 90 seconds).
std::optional<uint64_t> verify_totp_step(const std::string& base32_secret, const std::string& code,
                                         int window = 1);

// Build an otpauth:// provisioning URI for QR code generation.
std::string totp_provisioning_uri(const std::string& secret, const std::string& username, const std::string& issuer);

// Generate random backup codes: ten characters from an alphabet without
// lookalikes (no O/0, I/L/1), formatted XXXXX-XXXXX.
std::vector<std::string> generate_backup_codes(int count = 8);

// What a backup code is compared as: separators (dash, spaces) dropped and
// letters upper-cased, so "abcde fghjk" matches "ABCDE-FGHJK". Applies to
// codes issued since this rule; codes stored before it were compared exactly
// and still are (see IdentityStore::consume_backup_code).
std::string normalize_backup_code(const std::string& code);

} // namespace bsfchat
