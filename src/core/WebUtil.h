#pragma once

#include <optional>
#include <string>

namespace bsfchat::id {

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

// RFC 3986 percent-encoding of everything outside the unreserved set.
std::string percent_encode(const std::string& s);

// Decodes percent escapes and '+' (form encoding). Malformed escapes are
// preserved literally rather than throwing.
std::string percent_decode(const std::string& s);

// Escapes text for safe interpolation into an HTML document body/attribute.
std::string html_escape(const std::string& s);

// ---------------------------------------------------------------------------
// Constant-time comparison
// ---------------------------------------------------------------------------

// Compares two strings without leaking their contents through timing.
// Length inequality is still observable (unavoidable, and not sensitive here).
bool constant_time_equals(const std::string& a, const std::string& b);

// ---------------------------------------------------------------------------
// URI parsing / redirect_uri matching
// ---------------------------------------------------------------------------

struct ParsedUri {
    bool valid = false;
    std::string scheme;       // lowercased
    std::string host;         // lowercased, IPv6 without brackets
    std::string port;         // empty when not specified
    std::string path;         // "" or starts with '/'
    std::string query;        // without leading '?'
    bool has_fragment = false;
};

// Strict-ish absolute URI parser. Rejects anything carrying userinfo
// ("http://localhost:1234@evil.example/") which is the classic way to smuggle
// a foreign host past a naive prefix check.
ParsedUri parse_uri(const std::string& uri);

// True for the loopback hosts RFC 8252 section 7.3 talks about.
bool is_loopback_host(const std::string& host);

// RFC 8252-flavoured redirect_uri comparison:
//   * exact string equality always matches;
//   * otherwise, a registered loopback http URI matches a presented URI with
//     the same scheme, a loopback host, the same path and query, and ANY port.
// Everything else is rejected. Fragments are never allowed on a presented URI.
bool redirect_uri_matches(const std::string& registered, const std::string& presented);

// ---------------------------------------------------------------------------
// Cookies
// ---------------------------------------------------------------------------

// Parses a Cookie header properly (splitting on ';' and matching whole names),
// so that "mysession=..." is not mistaken for "session=...".
std::optional<std::string> get_cookie(const std::string& cookie_header, const std::string& name);

// ---------------------------------------------------------------------------
// OAuth scopes
// ---------------------------------------------------------------------------

// True when the space-delimited scope list contains the exact scope token.
bool scope_contains(const std::string& scope_list, const std::string& scope);

} // namespace bsfchat::id
