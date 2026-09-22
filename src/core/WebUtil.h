#pragma once

#include <optional>
#include <string>
#include <utility>
#include <vector>

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

// "scheme://host[:port]" as a browser would send it in an Origin header:
// lowercased, IPv6 bracketed, and the port dropped when it is the scheme's
// default. Empty for an invalid URI.
std::string uri_origin(const ParsedUri& uri);

// ---------------------------------------------------------------------------
// Request hygiene
// ---------------------------------------------------------------------------

// True when a Content-Type header value names application/json (parameters
// such as charset are ignored, case is not significant).
bool is_json_content_type(const std::string& content_type);

// Headers every response carries (security audit L7), applied by the server's
// post-routing handler without overwriting anything a handler set itself —
// the consent page sets its own CSP.
//
// script-src is 'self' with no 'unsafe-inline': the pages no longer contain
// inline script or inline event handlers, so an injected <script> or
// onclick= (M1) does not run even if some future escaping mistake lets one
// through. style-src keeps 'unsafe-inline' because the pages use style=""
// attributes; injected CSS is a far smaller risk and not worth rewriting
// every page for. img-src allows data: for the 2FA QR code, which
// qrcode.min.js renders into a data: URL. form-action is deliberately NOT
// set: browsers apply it to the redirect after a form POST, which would break
// the consent page's redirect to the desktop client's loopback URI.
const std::vector<std::pair<std::string, std::string>>& default_security_headers();

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
