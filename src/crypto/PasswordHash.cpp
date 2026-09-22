#include "crypto/PasswordHash.h"
#include "core/WebUtil.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace bsfchat::id {

namespace {

constexpr const char* kPrefix = "$pbkdf2-sha256$";
constexpr const char* kLegacyPrefix = "$pbkdf2$";

std::string bytes_to_hex(const unsigned char* data, size_t len) {
    std::ostringstream ss;
    for (size_t i = 0; i < len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    return ss.str();
}

std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    if (hex.size() % 2 != 0) return bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = nibble(hex[i]);
        int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) return {};
        bytes.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return bytes;
}

std::string pbkdf2_hash(const std::string& password, const unsigned char* salt, size_t salt_len, int iterations) {
    unsigned char hash[32]; // SHA-256 output
    if (PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.size()),
                            salt, static_cast<int>(salt_len),
                            iterations, EVP_sha256(), 32, hash) != 1) {
        throw std::runtime_error("PBKDF2 hash failed");
    }
    return bytes_to_hex(hash, 32);
}

// Decomposed representation of a stored hash string.
struct ParsedHash {
    bool valid = false;
    bool legacy = false;
    int iterations = 0;
    std::string salt_hex;
    std::string expected_hash;
};

ParsedHash parse_stored(const std::string& stored) {
    ParsedHash out;

    std::string body;
    if (stored.rfind(kPrefix, 0) == 0) {
        body = stored.substr(std::string(kPrefix).size());
    } else if (stored.rfind(kLegacyPrefix, 0) == 0) {
        out.legacy = true;
        body = stored.substr(std::string(kLegacyPrefix).size());
    } else {
        return out;
    }

    auto p1 = body.find('$');
    if (p1 == std::string::npos) return out;
    auto p2 = body.find('$', p1 + 1);
    if (p2 == std::string::npos) return out;

    auto number = body.substr(0, p1);
    if (number.empty()) return out;
    for (char c : number) {
        if (c < '0' || c > '9') return out;
    }

    long parsed = 0;
    try {
        parsed = std::stol(number);
    } catch (...) {
        return out;
    }

    if (out.legacy) {
        // Legacy field is a log2 cost; 2^cost iterations.
        //
        // Capped at 25, not 31, for two reasons. `1 << 31` on a signed int is
        // implementation-defined and yields a NEGATIVE iteration count on the
        // compilers we build with. And 2^30 is over a billion iterations -- the
        // very CPU burn the modern branch below refuses with its 50,000,000
        // cap, which a hostile or corrupt legacy row could otherwise demand.
        // 2^25 (33,554,432) is the largest power of two under that cap, and
        // real legacy costs sit far lower (the server writes 12 to 19).
        if (parsed < 1 || parsed > 25) return out;
        out.iterations = static_cast<int>(1u << static_cast<unsigned>(parsed));
    } else {
        // Guard against a hostile/corrupt row asking us to burn CPU forever.
        if (parsed < 1 || parsed > 50000000) return out;
        out.iterations = static_cast<int>(parsed);
    }

    out.salt_hex = body.substr(p1 + 1, p2 - p1 - 1);
    out.expected_hash = body.substr(p2 + 1);
    if (out.salt_hex.empty() || out.expected_hash.empty()) return out;

    out.valid = true;
    return out;
}

} // namespace

std::string hash_password(const std::string& password, int iterations) {
    if (iterations < 1) iterations = kDefaultPbkdf2Iterations;

    unsigned char salt[16];
    if (RAND_bytes(salt, sizeof(salt)) != 1) {
        throw std::runtime_error("Failed to generate random salt");
    }

    std::string salt_hex = bytes_to_hex(salt, sizeof(salt));
    std::string hash_hex = pbkdf2_hash(password, salt, sizeof(salt), iterations);

    return std::string(kPrefix) + std::to_string(iterations) + "$" + salt_hex + "$" + hash_hex;
}

bool verify_password(const std::string& password, const std::string& stored_hash) {
    auto parsed = parse_stored(stored_hash);
    if (!parsed.valid) return false;

    auto salt_bytes = hex_to_bytes(parsed.salt_hex);
    if (salt_bytes.empty()) return false;

    std::string computed;
    try {
        computed = pbkdf2_hash(password, salt_bytes.data(), salt_bytes.size(), parsed.iterations);
    } catch (...) {
        return false;
    }

    return constant_time_equals(computed, parsed.expected_hash);
}

bool password_needs_rehash(const std::string& stored_hash, int target_iterations) {
    auto parsed = parse_stored(stored_hash);
    if (!parsed.valid) return false; // nothing usable to upgrade
    if (parsed.legacy) return true;
    return parsed.iterations < target_iterations;
}

} // namespace bsfchat::id
