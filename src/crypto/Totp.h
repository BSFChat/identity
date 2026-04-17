#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace bsfchat {

// Generate a 20-byte random secret encoded as Base32 (RFC 4648, no padding).
std::string generate_totp_secret();

// Compute a 6-digit TOTP code for the given base32 secret and time step.
std::string compute_totp(const std::string& base32_secret, uint64_t time_step);

// Verify a TOTP code against the current time with a +/- window tolerance.
bool verify_totp(const std::string& base32_secret, const std::string& code, int window = 1);

// Build an otpauth:// provisioning URI for QR code generation.
std::string totp_provisioning_uri(const std::string& secret, const std::string& username, const std::string& issuer);

// Generate random 8-character alphanumeric backup codes.
std::vector<std::string> generate_backup_codes(int count = 8);

} // namespace bsfchat
