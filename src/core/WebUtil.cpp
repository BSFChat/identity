#include "core/WebUtil.h"

#include <openssl/crypto.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <sstream>

namespace bsfchat::id {

namespace {

bool is_unreserved(unsigned char c) {
    return std::isalnum(c) != 0 || c == '-' || c == '_' || c == '.' || c == '~';
}

int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string trim(const std::string& s) {
    auto begin = s.find_first_not_of(" \t");
    if (begin == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t");
    return s.substr(begin, end - begin + 1);
}

} // namespace

std::string percent_encode(const std::string& s) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        if (is_unreserved(c)) {
            out += static_cast<char>(c);
        } else {
            out += '%';
            out += kHex[(c >> 4) & 0x0F];
            out += kHex[c & 0x0F];
        }
    }
    return out;
}

std::string percent_decode(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '+') {
            out += ' ';
        } else if (s[i] == '%' && i + 2 < s.size()) {
            int hi = hex_value(s[i + 1]);
            int lo = hex_value(s[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out += static_cast<char>((hi << 4) | lo);
                i += 2;
            } else {
                out += s[i];
            }
        } else {
            out += s[i];
        }
    }
    return out;
}

std::string html_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&':  out += "&amp;";  break;
            case '<':  out += "&lt;";   break;
            case '>':  out += "&gt;";   break;
            case '"':  out += "&quot;"; break;
            case '\'': out += "&#39;";  break;
            default:   out += c;        break;
        }
    }
    return out;
}

bool constant_time_equals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    if (a.empty()) return true;
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

ParsedUri parse_uri(const std::string& uri) {
    ParsedUri out;

    auto scheme_end = uri.find("://");
    if (scheme_end == std::string::npos || scheme_end == 0) return out;

    out.scheme = to_lower(uri.substr(0, scheme_end));
    for (char c : out.scheme) {
        if (std::isalnum(static_cast<unsigned char>(c)) == 0 && c != '+' && c != '-' && c != '.') {
            return out;
        }
    }

    std::string rest = uri.substr(scheme_end + 3);
    auto authority_end = rest.find_first_of("/?#");
    std::string authority = (authority_end == std::string::npos) ? rest : rest.substr(0, authority_end);
    std::string remainder = (authority_end == std::string::npos) ? "" : rest.substr(authority_end);

    if (authority.empty()) return out;

    // Reject userinfo outright. "http://localhost:8080@evil.example/" has an
    // authority of "localhost:8080@evil.example" whose real host is evil.example,
    // and it is never a legitimate OAuth redirect target.
    if (authority.find('@') != std::string::npos) return out;

    if (authority.front() == '[') {
        auto close = authority.find(']');
        if (close == std::string::npos) return out;
        out.host = to_lower(authority.substr(1, close - 1));
        if (close + 1 < authority.size()) {
            if (authority[close + 1] != ':') return out;
            out.port = authority.substr(close + 2);
        }
    } else {
        auto colon = authority.rfind(':');
        if (colon == std::string::npos) {
            out.host = to_lower(authority);
        } else {
            out.host = to_lower(authority.substr(0, colon));
            out.port = authority.substr(colon + 1);
        }
    }

    if (out.host.empty()) return out;
    if (!out.port.empty()) {
        for (char c : out.port) {
            if (std::isdigit(static_cast<unsigned char>(c)) == 0) return out;
        }
    }

    auto hash = remainder.find('#');
    if (hash != std::string::npos) {
        out.has_fragment = true;
        remainder.resize(hash);
    }
    auto qmark = remainder.find('?');
    if (qmark != std::string::npos) {
        out.query = remainder.substr(qmark + 1);
        remainder.resize(qmark);
    }
    out.path = remainder;

    out.valid = true;
    return out;
}

bool is_loopback_host(const std::string& host) {
    return host == "127.0.0.1" || host == "::1" || host == "localhost";
}

bool redirect_uri_matches(const std::string& registered, const std::string& presented) {
    if (registered.empty() || presented.empty()) return false;

    // Exact match short-circuit — covers https web clients and any client that
    // registered a fully-specified loopback URI including its port.
    if (registered == presented) return true;

    auto reg = parse_uri(registered);
    auto got = parse_uri(presented);
    if (!reg.valid || !got.valid) return false;

    // The port-flexible rule exists only for RFC 8252 native-app loopback
    // redirects. Everything else must match exactly, which it already didn't.
    if (reg.scheme != "http" || got.scheme != "http") return false;
    if (!is_loopback_host(reg.host) || !is_loopback_host(got.host)) return false;

    // A fragment on the presented URI is forbidden by OAuth 2.0 and would let a
    // caller reshape where the browser actually lands.
    if (got.has_fragment) return false;

    auto normalize_path = [](const std::string& p) { return p.empty() ? std::string("/") : p; };
    if (normalize_path(reg.path) != normalize_path(got.path)) return false;
    if (reg.query != got.query) return false;

    // Port is intentionally free: native apps bind an ephemeral loopback port.
    return true;
}

std::string uri_origin(const ParsedUri& uri) {
    if (!uri.valid || uri.scheme.empty() || uri.host.empty()) return "";
    std::string origin = uri.scheme + "://";
    origin += uri.host.find(':') != std::string::npos ? "[" + uri.host + "]" : uri.host;
    const bool default_port = uri.port.empty() || (uri.scheme == "https" && uri.port == "443") ||
                              (uri.scheme == "http" && uri.port == "80");
    if (!default_port) origin += ":" + uri.port;
    return origin;
}

bool is_json_content_type(const std::string& content_type) {
    auto media = content_type.substr(0, content_type.find(';'));
    return to_lower(trim(media)) == "application/json";
}

const std::vector<std::pair<std::string, std::string>>& default_security_headers() {
    static const std::vector<std::pair<std::string, std::string>> headers = {
        {"Content-Security-Policy",
         "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
         "img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"},
        {"X-Frame-Options", "DENY"},
        {"X-Content-Type-Options", "nosniff"},
        {"Referrer-Policy", "no-referrer"},
    };
    return headers;
}

std::optional<std::string> get_cookie(const std::string& cookie_header, const std::string& name) {
    std::istringstream ss(cookie_header);
    std::string pair;
    while (std::getline(ss, pair, ';')) {
        auto eq = pair.find('=');
        if (eq == std::string::npos) continue;
        if (trim(pair.substr(0, eq)) == name) {
            return trim(pair.substr(eq + 1));
        }
    }
    return std::nullopt;
}

bool scope_contains(const std::string& scope_list, const std::string& scope) {
    if (scope.empty()) return true;
    std::istringstream ss(scope_list);
    std::string token;
    while (ss >> token) {
        if (token == scope) return true;
    }
    return false;
}

} // namespace bsfchat::id
