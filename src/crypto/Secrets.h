#pragma once

#include <cstddef>
#include <string>

namespace bsfchat::id {

// Fills `out` with `len` bytes from OpenSSL's CSPRNG, or throws.
//
// Every credential this service mints (session ids, access/refresh tokens,
// auth codes, consent tokens, client secrets) comes through here. RAND_bytes
// reports failure through its return value and leaves the buffer as it found
// it, so the old unchecked call sites produced an ALL-ZERO token from a
// zero-initialised std::vector on failure — a forgeable credential that looked
// like a random one. Throwing turns that into a 500 from httplib: fail closed.
void secure_random_bytes(unsigned char* out, size_t len);

// `bytes` random bytes, lower-case hex encoded (so 2 * bytes characters).
std::string secure_random_hex(size_t bytes);

// Lower-case hex SHA-256 of `data`.
std::string sha256_hex(const std::string& data);

// How bearer credentials are stored at rest: SHA-256 of the presented value.
//
// Sessions, access tokens and refresh tokens are 256-bit random values, so an
// unsalted fast hash is the right tool — there is no dictionary to attack, and
// the lookup has to stay an indexed equality match. What it buys is that a
// copy of identity.db (a backup, say) is no longer a set of live credentials.
std::string hash_token(const std::string& token);

// OAuth client secrets are stored as "sha256$<hex>". The prefix makes the
// migration idempotent and lets a hand-inserted plaintext row be recognised.
inline constexpr const char* kClientSecretHashPrefix = "sha256$";
std::string hash_client_secret(const std::string& secret);

// Compares a presented secret against the stored form in constant time. An
// empty stored value never matches (that is a public client, not a secret).
bool client_secret_matches(const std::string& stored, const std::string& presented);

} // namespace bsfchat::id
