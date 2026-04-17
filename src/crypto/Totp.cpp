#include "crypto/Totp.h"

#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace bsfchat {

namespace {

// Base32 alphabet (RFC 4648)
constexpr char BASE32_ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

std::string base32_encode(const unsigned char* data, size_t len) {
    std::string result;
    result.reserve((len * 8 + 4) / 5);

    int buffer = 0;
    int bits_left = 0;

    for (size_t i = 0; i < len; ++i) {
        buffer = (buffer << 8) | data[i];
        bits_left += 8;
        while (bits_left >= 5) {
            bits_left -= 5;
            result += BASE32_ALPHABET[(buffer >> bits_left) & 0x1f];
        }
    }
    if (bits_left > 0) {
        result += BASE32_ALPHABET[(buffer << (5 - bits_left)) & 0x1f];
    }
    // No padding per spec
    return result;
}

std::vector<unsigned char> base32_decode(const std::string& encoded) {
    std::vector<unsigned char> result;
    result.reserve(encoded.size() * 5 / 8);

    int buffer = 0;
    int bits_left = 0;

    for (char c : encoded) {
        int val;
        if (c >= 'A' && c <= 'Z') {
            val = c - 'A';
        } else if (c >= 'a' && c <= 'z') {
            val = c - 'a';
        } else if (c >= '2' && c <= '7') {
            val = c - '2' + 26;
        } else if (c == '=') {
            break; // padding
        } else {
            continue; // skip invalid
        }

        buffer = (buffer << 5) | val;
        bits_left += 5;
        if (bits_left >= 8) {
            bits_left -= 8;
            result.push_back(static_cast<unsigned char>((buffer >> bits_left) & 0xff));
        }
    }
    return result;
}

std::string url_encode(const std::string& s) {
    std::ostringstream out;
    out << std::hex << std::uppercase << std::setfill('0');
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            out << c;
        } else {
            out << '%' << std::setw(2) << static_cast<int>(c);
        }
    }
    return out.str();
}

} // namespace

std::string generate_totp_secret() {
    unsigned char bytes[20];
    if (RAND_bytes(bytes, sizeof(bytes)) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
    return base32_encode(bytes, sizeof(bytes));
}

std::string compute_totp(const std::string& base32_secret, uint64_t time_step) {
    auto key = base32_decode(base32_secret);
    if (key.empty()) {
        throw std::runtime_error("Invalid TOTP secret");
    }

    // Encode time_step as 8-byte big-endian
    unsigned char msg[8];
    for (int i = 7; i >= 0; --i) {
        msg[i] = static_cast<unsigned char>(time_step & 0xff);
        time_step >>= 8;
    }

    // HMAC-SHA1
    unsigned char hmac_result[20];
    unsigned int hmac_len = 0;
    HMAC(EVP_sha1(), key.data(), static_cast<int>(key.size()),
         msg, sizeof(msg), hmac_result, &hmac_len);

    // Dynamic truncation (RFC 4226)
    int offset = hmac_result[19] & 0x0f;
    uint32_t code = (static_cast<uint32_t>(hmac_result[offset] & 0x7f) << 24)
                  | (static_cast<uint32_t>(hmac_result[offset + 1]) << 16)
                  | (static_cast<uint32_t>(hmac_result[offset + 2]) << 8)
                  | (static_cast<uint32_t>(hmac_result[offset + 3]));
    code %= 1000000;

    std::ostringstream ss;
    ss << std::setfill('0') << std::setw(6) << code;
    return ss.str();
}

bool verify_totp(const std::string& base32_secret, const std::string& code, int window) {
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    uint64_t current_step = static_cast<uint64_t>(now) / 30;

    for (int i = -window; i <= window; ++i) {
        uint64_t step = current_step + static_cast<uint64_t>(i);
        if (compute_totp(base32_secret, step) == code) {
            return true;
        }
    }
    return false;
}

std::string totp_provisioning_uri(const std::string& secret, const std::string& username, const std::string& issuer) {
    return "otpauth://totp/" + url_encode(issuer) + ":" + url_encode(username)
         + "?secret=" + secret
         + "&issuer=" + url_encode(issuer);
}

std::vector<std::string> generate_backup_codes(int count) {
    static constexpr char ALPHANUM[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    constexpr int CODE_LEN = 8;

    std::vector<std::string> codes;
    codes.reserve(count);

    for (int i = 0; i < count; ++i) {
        unsigned char bytes[CODE_LEN];
        if (RAND_bytes(bytes, sizeof(bytes)) != 1) {
            throw std::runtime_error("RAND_bytes failed");
        }
        std::string code(CODE_LEN, '\0');
        for (int j = 0; j < CODE_LEN; ++j) {
            code[j] = ALPHANUM[bytes[j] % 62];
        }
        codes.push_back(std::move(code));
    }
    return codes;
}

} // namespace bsfchat
