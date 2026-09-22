#include "crypto/Secrets.h"
#include "core/WebUtil.h"

#include <openssl/rand.h>
#include <openssl/sha.h>

#include <limits>
#include <stdexcept>
#include <vector>

namespace bsfchat::id {

namespace {

std::string to_hex(const unsigned char* data, size_t len) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(kHex[data[i] >> 4]);
        out.push_back(kHex[data[i] & 0x0f]);
    }
    return out;
}

} // namespace

void secure_random_bytes(unsigned char* out, size_t len) {
    if (len > static_cast<size_t>(std::numeric_limits<int>::max())) {
        throw std::invalid_argument("secure_random_bytes: length too large");
    }
    if (RAND_bytes(out, static_cast<int>(len)) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
}

std::string secure_random_hex(size_t bytes) {
    std::vector<unsigned char> buf(bytes);
    secure_random_bytes(buf.data(), buf.size());
    return to_hex(buf.data(), buf.size());
}

std::string sha256_hex(const std::string& data) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), digest);
    return to_hex(digest, sizeof(digest));
}

std::string hash_token(const std::string& token) {
    return sha256_hex(token);
}

std::string hash_client_secret(const std::string& secret) {
    return std::string(kClientSecretHashPrefix) + sha256_hex(secret);
}

bool client_secret_matches(const std::string& stored, const std::string& presented) {
    if (stored.empty()) return false;
    // Both sides are fixed-length digests once hashed, so constant_time_equals
    // leaks nothing about the secret even through its length check.
    return constant_time_equals(stored, hash_client_secret(presented));
}

} // namespace bsfchat::id
