#include "api/OidcHandler.h"
#include "core/Version.h"
#include "core/Logger.h"
#include "core/WebUtil.h"
#include "crypto/Secrets.h"

#include <bsfchat/Identifiers.h>
#include <bsfchat/JwtUtils.h>
#include <nlohmann/json.hpp>
#include <openssl/sha.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <vector>

namespace bsfchat::id {

namespace {

using json = nlohmann::json;

int64_t now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// Checked CSPRNG (crypto/Secrets.h): an unchecked RAND_bytes failure used to
// leave the zero-initialised buffer as the token (security audit L3).
std::string random_hex(int bytes) {
    return secure_random_hex(static_cast<size_t>(bytes));
}

std::string base64url_encode_local(const unsigned char* data, size_t len) {
    static constexpr char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string result;
    result.reserve((len * 4 + 2) / 3);

    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) n |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < len) n |= static_cast<uint32_t>(data[i + 2]);

        result += table[(n >> 18) & 0x3F];
        result += table[(n >> 12) & 0x3F];
        if (i + 1 < len) result += table[(n >> 6) & 0x3F];
        if (i + 2 < len) result += table[n & 0x3F];
    }
    return result;
}

std::vector<unsigned char> base64_decode_local(const std::string& input) {
    static constexpr unsigned char decode_table[256] = {
        255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
        255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
        255,255,255,255,255,255,255,255,255,255,255, 62,255,255,255, 63,
         52, 53, 54, 55, 56, 57, 58, 59, 60, 61,255,255,255,  0,255,255,
        255,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
         15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,255,255,255,255,255,
        255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
         41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,255,255,255,255,255,
        255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
        255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
        255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
        255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
        255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
        255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
        255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
        255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    };

    std::vector<unsigned char> result;
    result.reserve(input.size() * 3 / 4);

    uint32_t buf = 0;
    int bits = 0;
    for (char c : input) {
        if (c == '=' || c == '\n' || c == '\r') continue;
        unsigned char val = decode_table[static_cast<unsigned char>(c)];
        if (val == 255) continue;
        buf = (buf << 6) | val;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            result.push_back(static_cast<unsigned char>((buf >> bits) & 0xFF));
        }
    }
    return result;
}

void json_error(httplib::Response& res, int status, const std::string& error) {
    res.status = status;
    res.set_content(json{{"error", error}}.dump(), "application/json");
}

// RFC 6749 error response for the token endpoint.
void oauth_error(httplib::Response& res, int status, const std::string& error,
                 const std::string& description = "") {
    res.status = status;
    json body = {{"error", error}};
    if (!description.empty()) body["error_description"] = description;
    res.set_header("Cache-Control", "no-store");
    if (status == 401) {
        res.set_header("WWW-Authenticate", "Basic realm=\"token\"");
    }
    res.set_content(body.dump(), "application/json");
}

// Parse URL-encoded form body
std::map<std::string, std::string> parse_form(const std::string& body) {
    std::map<std::string, std::string> params;
    std::istringstream ss(body);
    std::string pair;
    while (std::getline(ss, pair, '&')) {
        auto eq = pair.find('=');
        if (eq != std::string::npos) {
            params[percent_decode(pair.substr(0, eq))] = percent_decode(pair.substr(eq + 1));
        }
    }
    return params;
}

// Appends a query parameter to a URL, choosing '?' or '&' as appropriate and
// percent-encoding the value. Raw concatenation here is how an unencoded
// `state` containing '&' used to be able to inject extra parameters.
void append_query_param(std::string& url, const std::string& key, const std::string& value) {
    url += (url.find('?') == std::string::npos) ? '?' : '&';
    url += percent_encode(key);
    url += '=';
    url += percent_encode(value);
}

// Redirects the user agent back to the client with an OAuth error, per RFC 6749
// section 4.1.2.1. Only used once redirect_uri has been validated.
void redirect_with_error(httplib::Response& res, const std::string& redirect_uri,
                         const std::string& error, const std::string& state) {
    std::string location = redirect_uri;
    append_query_param(location, "error", error);
    if (!state.empty()) append_query_param(location, "state", state);
    res.set_redirect(location);
}

// id_token lifetime. The token is presented exactly once, to the chat server
// named in its `aud`, seconds after it is minted; an hour of validity was an
// hour in which a copy of it was a sign-in credential. Five minutes covers
// clock skew and a slow sign-in without leaving a long replay window.
constexpr int64_t kIdTokenLifetimeSeconds = 300;

// OIDC nonce bounds. It is opaque to us, but it is echoed into a signed token
// and round-tripped through the login page's query string, so it is held to
// printable ASCII and a length no honest client needs to exceed.
constexpr size_t kMaxNonceLength = 256;

bool nonce_acceptable(const std::string& nonce) {
    if (nonce.size() > kMaxNonceLength) return false;
    for (char c : nonce) {
        if (c < 0x21 || c > 0x7e) return false;
    }
    return true;
}

// The host (and port, if not the default) of a canonical audience URL, for
// the consent page. The full URL is shown underneath; this is the part a
// person can recognise at a glance.
std::string audience_display_host(const std::string& canonical) {
    auto start = canonical.find("://");
    if (start == std::string::npos) return canonical;
    start += 3;
    return canonical.substr(start, canonical.find('/', start) - start);
}

} // namespace

OidcHandler::OidcHandler(IdentityStore& store, KeyManager& key_manager,
                         AccountHandler& account_handler, const Config& config)
    : store_(store), key_manager_(key_manager), account_handler_(account_handler), config_(config) {}

void OidcHandler::handle_discovery(const httplib::Request&, httplib::Response& res) {
    auto issuer = config_.issuer_url;
    json discovery = {
        {"issuer", issuer},
        {"authorization_endpoint", issuer + "/authorize"},
        {"token_endpoint", issuer + "/token"},
        {"userinfo_endpoint", issuer + "/userinfo"},
        {"jwks_uri", issuer + "/jwks"},
        {"revocation_endpoint", issuer + "/token/revoke"},
        {"registration_endpoint", issuer + "/register"},
        {"scopes_supported", json::array({"openid", "profile", "email"})},
        {"response_types_supported", json::array({"code"})},
        {"grant_types_supported", json::array({"authorization_code", "refresh_token"})},
        {"subject_types_supported", json::array({"public"})},
        {"id_token_signing_alg_values_supported", json::array({"RS256"})},
        {"token_endpoint_auth_methods_supported",
            json::array({"client_secret_post", "client_secret_basic", "none"})},
        // "plain" was advertised but never implemented by the token endpoint,
        // and is rejected outright now.
        {"code_challenge_methods_supported", json::array({"S256"})}
    };

    // Additive, vendor-namespaced, and outside every field an OIDC client
    // reads. OpenID Connect Discovery 1.0 section 3 says a provider MAY
    // publish additional metadata and that clients MUST ignore what they
    // do not recognise, so this cannot change how any relying party
    // behaves — it just means an operator can ask a running identity
    // service what build it is without shell access to the container.
    discovery["bsfchat_version"] = build::version_string();
    discovery["bsfchat_revision"] = build::revision_string();
    discovery["bsfchat_channel"] = build::channel_of(build::kVersion);

    res.set_content(discovery.dump(), "application/json");
}

void OidcHandler::handle_authorize(const httplib::Request& req, httplib::Response& res) {
    auto client_id = req.get_param_value("client_id");
    auto redirect_uri = req.get_param_value("redirect_uri");
    auto response_type = req.get_param_value("response_type");
    auto scope = req.get_param_value("scope");
    auto state = req.get_param_value("state");
    auto code_challenge = req.get_param_value("code_challenge");
    auto code_challenge_method = req.get_param_value("code_challenge_method");
    auto nonce = req.get_param_value("nonce");

    if (client_id.empty() || redirect_uri.empty()) {
        json_error(res, 400, "client_id and redirect_uri are required");
        return;
    }

    if (response_type != "code") {
        json_error(res, 400, "Only response_type=code is supported");
        return;
    }

    // Verify client exists
    auto client = store_.get_oauth_client(client_id);
    if (!client) {
        json_error(res, 400, "Unknown client_id");
        return;
    }

    // Validate redirect_uri against client's registered URIs.
    //
    // The old check accepted anything starting with "http://localhost:", which
    // "http://localhost:1234@attacker.example/" satisfies while actually
    // pointing at attacker.example. redirect_uri_matches() parses both URIs and
    // only relaxes the *port* for genuine loopback registrations.
    {
        bool uri_valid = false;
        auto uris = json::parse(client->redirect_uris, nullptr, false);
        if (!uris.is_discarded() && uris.is_array()) {
            for (const auto& registered : uris) {
                if (!registered.is_string()) continue;
                if (redirect_uri_matches(registered.get<std::string>(), redirect_uri)) {
                    uri_valid = true;
                    break;
                }
            }
        }
        if (!uri_valid) {
            // Never redirect to an unvalidated URI — report in-band instead.
            json_error(res, 400, "Invalid redirect_uri for this client");
            return;
        }
    }

    // A client with no registered secret is a public client. Public clients get
    // no client authentication at the token endpoint, so PKCE is the only thing
    // binding the code to the requester — it is mandatory, not optional.
    const bool is_public_client = client->client_secret.empty();

    if (!code_challenge_method.empty() && code_challenge_method != "S256") {
        redirect_with_error(res, redirect_uri, "invalid_request", state);
        return;
    }
    if (code_challenge.empty()) {
        if (is_public_client) {
            redirect_with_error(res, redirect_uri, "invalid_request", state);
            return;
        }
    } else if (code_challenge.size() < 43 || code_challenge.size() > 128) {
        // RFC 7636: a S256 challenge is base64url of a 32-byte digest.
        redirect_with_error(res, redirect_uri, "invalid_request", state);
        return;
    }

    // RFC 8707 resource indicator: the chat server this sign-in is for.
    //
    // Identity audit 2026-09, finding C1. Every id_token used to carry
    // aud=<client_id>, and every chat server checked for that same value, so a
    // token handed to one server signed its holder in at all of them. A
    // hostile server received each user's token at sign-in and could replay
    // it against chat.bsfchat.com — and, through link_identity, attach the
    // victim's identity to the attacker's account there permanently.
    //
    // The client now names the server it is connecting to, we put exactly
    // that into `aud`, and each server accepts only its own URL. The CLIENT
    // decides this value from the address it will post the token to; nothing
    // a chat server says reaches it, so a hostile server cannot ask for a
    // token audienced to somebody else's.
    //
    // One resource, no more. RFC 8707 allows several, but a token good at two
    // servers is the bug this closes. Canonicalised with the same function
    // the chat server applies to its own URL, and held to https (or http on
    // loopback, for development): an http audience would be a credential
    // that crosses the network in clear text on every sign-in.
    //
    // Absent: the token gets the legacy client_id audience, as before. Old
    // clients keep working against old servers, and upgraded servers refuse
    // that audience, which is the point — see create_id_token.
    std::string resource;
    if (req.has_param("resource")) {
        auto canonical = req.get_param_value_count("resource") == 1
            ? bsfchat::canonical_audience_url(req.get_param_value("resource"))
            : std::nullopt;
        if (!canonical || !bsfchat::audience_url_is_secure(*canonical)) {
            redirect_with_error(res, redirect_uri, "invalid_target", state);
            return;
        }
        resource = *canonical;
    }

    if (!nonce_acceptable(nonce)) {
        redirect_with_error(res, redirect_uri, "invalid_request", state);
        return;
    }

    // Check if user is logged in (has session cookie)
    auto account_id = account_handler_.get_session_account(req);
    if (account_id.empty()) {
        // Redirect to the login page, preserving the request. Every value is
        // percent-encoded: previously a '&' or '?' inside redirect_uri or state
        // silently corrupted or injected parameters here.
        std::string login_url = "/login.html";
        append_query_param(login_url, "redirect", redirect_uri);
        append_query_param(login_url, "client_id", client_id);
        append_query_param(login_url, "response_type", response_type);
        append_query_param(login_url, "scope", scope);
        append_query_param(login_url, "state", state);
        if (!code_challenge.empty()) {
            append_query_param(login_url, "code_challenge", code_challenge);
            append_query_param(login_url, "code_challenge_method", "S256");
        }
        // Dropping either of these on the way through the login page would
        // quietly turn a server-bound sign-in back into a legacy one.
        if (!resource.empty()) append_query_param(login_url, "resource", resource);
        if (!nonce.empty()) append_query_param(login_url, "nonce", nonce);
        res.set_redirect(login_url);
        return;
    }

    auto account = store_.get_account_by_id(account_id);
    if (!account) {
        json_error(res, 500, "Account not found");
        return;
    }

    // Do NOT mint a code here. A GET to /authorize is reachable by any site
    // that navigates the browser to it, and the session cookie is SameSite=Lax
    // so it rides along. Issuing on GET meant a third-party page could silently
    // obtain a code on a redirect_uri of its choosing. Instead we render a
    // consent page whose approval token the attacker cannot read (same-origin
    // policy) and cannot guess.
    auto consent_token = random_hex(32);

    ConsentRequest consent;
    consent.token = consent_token;
    consent.session_id = account_handler_.authenticate(req, "").credential_id;
    consent.account_id = account_id;
    consent.client_id = client_id;
    consent.redirect_uri = redirect_uri;
    consent.scope = scope;
    consent.state = state;
    consent.code_challenge = code_challenge;
    consent.expires_at = now_seconds() + 300; // 5 minutes
    consent.resource = resource;
    consent.nonce = nonce;

    if (consent.session_id.empty() || !store_.store_consent_request(consent)) {
        json_error(res, 500, "Failed to start authorization");
        return;
    }

    render_consent_page(res, *client, *account, scope, consent_token, redirect_uri, resource);
}

void OidcHandler::render_consent_page(httplib::Response& res, const OAuthClient& client,
                                      const Account& account, const std::string& scope,
                                      const std::string& consent_token,
                                      const std::string& redirect_uri,
                                      const std::string& resource) {
    std::ostringstream scopes_html;
    std::istringstream scope_stream(scope);
    std::string token;
    while (scope_stream >> token) {
        std::string label = token;
        if (token == "openid") label = "Confirm your identity";
        else if (token == "profile") label = "Your display name and avatar";
        else if (token == "email") label = "Your email address";
        scopes_html << "<li>" << html_escape(label) << "</li>";
    }
    if (scopes_html.str().empty()) {
        scopes_html << "<li>Confirm your identity</li>";
    }

    // Name the chat server. Before C1 was fixed this page could not say which
    // server a sign-in was for, because nothing in the request said so; now
    // that the token is only good at one server, the person approving it
    // should see which. Host first, in bold, because that is what they will
    // recognise; the full URL underneath for anyone who wants to check.
    std::ostringstream target_html;
    if (!resource.empty()) {
        target_html << " to <strong>" << html_escape(audience_display_host(resource))
                    << "</strong>";
    }
    std::ostringstream server_html;
    if (!resource.empty()) {
        server_html << "<p style=\"color:var(--text-muted);font-size:13px;word-break:break-all;\">"
                    << "Chat server: " << html_escape(resource) << "</p>";
    }

    std::ostringstream html;
    html << "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\">"
         << "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
         << "<title>Authorize - BSFChat ID</title>"
         << "<link rel=\"stylesheet\" href=\"/css/style.css\"></head><body>"
         << "<div class=\"container\"><div class=\"card\">"
         << "<div class=\"logo\"><h1>BSFChat ID</h1>"
         << "<p class=\"subtitle\">Authorize application</p></div>"
         << "<p><strong>" << html_escape(client.name.empty() ? client.client_id : client.name)
         << "</strong> wants to sign you in" << target_html.str() << " as <strong>"
         << html_escape(account.username) << "</strong> and access:</p>"
         << "<ul>" << scopes_html.str() << "</ul>"
         << server_html.str()
         << "<p style=\"color:var(--text-muted);font-size:13px;word-break:break-all;\">"
         << "You will be returned to " << html_escape(redirect_uri) << "</p>"
         << "<form method=\"POST\" action=\"/authorize/decision\">"
         << "<input type=\"hidden\" name=\"consent_token\" value=\"" << html_escape(consent_token) << "\">"
         << "<button type=\"submit\" name=\"approve\" value=\"true\" class=\"btn btn-primary\">Allow</button>"
         << "<button type=\"submit\" name=\"approve\" value=\"false\" class=\"btn btn-secondary\">Deny</button>"
         << "</form></div></div></body></html>";

    res.set_header("Cache-Control", "no-store");
    // This page must never be framed: a clickjacked "Allow" is the same as a
    // silent grant.
    res.set_header("X-Frame-Options", "DENY");
    res.set_header("Content-Security-Policy", "frame-ancestors 'none'");
    res.set_content(html.str(), "text/html");
}

void OidcHandler::handle_authorize_decision(const httplib::Request& req, httplib::Response& res) {
    auto log = get_logger();

    auto params = parse_form(req.body);
    auto consent_token = params["consent_token"];
    auto approve = params["approve"];

    if (consent_token.empty()) {
        json_error(res, 400, "Missing consent token");
        return;
    }

    // The consent token is bound to the browser session that was shown the
    // prompt. This is the CSRF check: a cross-site POST cannot carry a token it
    // was never able to read, and a token lifted from another user's session
    // does not match here.
    auto ctx = account_handler_.authenticate(req, "");
    if (!ctx.authenticated() || !ctx.is_browser_session()) {
        json_error(res, 401, "Not authenticated");
        return;
    }

    // Consumption is conditional on that binding, so a rejected decision leaves
    // the pending request intact for its rightful owner.
    auto consent = store_.consume_consent_request(consent_token, ctx.credential_id);
    if (!consent) {
        log->warn("Rejected consent decision that did not match the issuing session");
        json_error(res, 403, "Authorization request does not belong to this session");
        return;
    }
    if (consent->expires_at < now_seconds() || ctx.account_id != consent->account_id) {
        json_error(res, 400, "Authorization request expired — please try again");
        return;
    }

    if (approve != "true") {
        redirect_with_error(res, consent->redirect_uri, "access_denied", consent->state);
        return;
    }

    auto code = random_hex(32);
    AuthCode auth_code;
    auth_code.code = code;
    auth_code.client_id = consent->client_id;
    auth_code.account_id = consent->account_id;
    auth_code.redirect_uri = consent->redirect_uri;
    auth_code.scope = consent->scope;
    auth_code.code_challenge = consent->code_challenge;
    auth_code.expires_at = now_seconds() + 300; // 5 minutes
    auth_code.resource = consent->resource;
    auth_code.nonce = consent->nonce;

    if (!store_.store_auth_code(auth_code)) {
        json_error(res, 500, "Failed to issue authorization code");
        return;
    }

    std::string location = consent->redirect_uri;
    append_query_param(location, "code", code);
    if (!consent->state.empty()) append_query_param(location, "state", consent->state);

    log->info("Authorization code issued to client {} for account {}",
              consent->client_id, consent->account_id);
    res.set_redirect(location);
}

OidcHandler::ClientAuthResult OidcHandler::authenticate_client(const std::string& client_id,
                                                               const std::string& presented_secret,
                                                               bool secret_was_presented) {
    ClientAuthResult result;

    if (client_id.empty()) {
        result.error = "invalid_client";
        result.description = "client_id is required";
        return result;
    }

    auto client = store_.get_oauth_client(client_id);
    if (!client) {
        result.error = "invalid_client";
        result.description = "Unknown client";
        return result;
    }

    if (client->client_secret.empty()) {
        // Public client: it has no secret to prove, so it must not present one
        // (that would mean the caller believes it is confidential), and it must
        // use PKCE instead.
        if (secret_was_presented && !presented_secret.empty()) {
            result.error = "invalid_client";
            result.description = "This client is public and must not present a client_secret";
            return result;
        }
        result.ok = true;
        result.requires_pkce = true;
        return result;
    }

    // Confidential client: the registered secret must actually be presented and
    // must match. Previously the secret was parsed from three places and then
    // never compared against anything at all.
    if (!secret_was_presented || presented_secret.empty()) {
        result.error = "invalid_client";
        result.description = "Client authentication required";
        return result;
    }
    // The store keeps only a digest of the secret (security audit L5).
    if (!client_secret_matches(client->client_secret, presented_secret)) {
        result.error = "invalid_client";
        result.description = "Client authentication failed";
        return result;
    }

    result.ok = true;
    return result;
}

void OidcHandler::handle_token(const httplib::Request& req, httplib::Response& res) {
    auto log = get_logger();

    // Parse either form-encoded or JSON body
    std::string grant_type, code, redirect_uri, client_id, client_secret, refresh_token_str, code_verifier;
    std::string resource;
    bool secret_presented = false;

    if (req.get_header_value("Content-Type").find("application/x-www-form-urlencoded") != std::string::npos) {
        auto params = parse_form(req.body);
        grant_type = params["grant_type"];
        code = params["code"];
        redirect_uri = params["redirect_uri"];
        client_id = params["client_id"];
        refresh_token_str = params["refresh_token"];
        code_verifier = params["code_verifier"];
        resource = params["resource"];
        if (params.count("client_secret")) {
            client_secret = params["client_secret"];
            secret_presented = true;
        }
    } else {
        auto body = json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.is_object()) {
            oauth_error(res, 400, "invalid_request", "Invalid request body");
            return;
        }
        grant_type = body.value("grant_type", "");
        code = body.value("code", "");
        redirect_uri = body.value("redirect_uri", "");
        client_id = body.value("client_id", "");
        refresh_token_str = body.value("refresh_token", "");
        code_verifier = body.value("code_verifier", "");
        if (body.contains("resource") && body["resource"].is_string()) {
            resource = body["resource"].get<std::string>();
        }
        if (body.contains("client_secret") && body["client_secret"].is_string()) {
            client_secret = body["client_secret"].get<std::string>();
            secret_presented = true;
        }
    }

    // HTTP Basic client authentication (RFC 6749 section 2.3.1) takes
    // precedence and must not be silently ignored when a client_id also
    // appeared in the body.
    if (req.has_header("Authorization")) {
        auto auth = req.get_header_value("Authorization");
        if (auth.starts_with("Basic ")) {
            auto decoded_bytes = base64_decode_local(auth.substr(6));
            std::string credentials(decoded_bytes.begin(), decoded_bytes.end());
            auto colon = credentials.find(':');
            if (colon == std::string::npos) {
                oauth_error(res, 401, "invalid_client", "Malformed Basic credentials");
                return;
            }
            auto basic_id = percent_decode(credentials.substr(0, colon));
            auto basic_secret = percent_decode(credentials.substr(colon + 1));
            if (!client_id.empty() && client_id != basic_id) {
                oauth_error(res, 400, "invalid_request",
                            "client_id in body does not match Basic credentials");
                return;
            }
            client_id = basic_id;
            client_secret = basic_secret;
            secret_presented = true;
        }
    }

    if (grant_type == "authorization_code") {
        if (code.empty()) {
            oauth_error(res, 400, "invalid_request", "code is required");
            return;
        }

        // Single fetch-and-delete inside one transaction. The old code did a
        // separate SELECT and DELETE, so two concurrent redemptions of the same
        // code could both pass the lookup and both get tokens.
        auto auth_code = store_.consume_auth_code(code);
        if (!auth_code) {
            oauth_error(res, 400, "invalid_grant", "Invalid authorization code");
            return;
        }

        if (auth_code->expires_at < now_seconds()) {
            oauth_error(res, 400, "invalid_grant", "Authorization code expired");
            return;
        }

        // The code identifies the client it was issued to; an explicitly
        // supplied client_id must agree with it.
        if (!client_id.empty() && auth_code->client_id != client_id) {
            oauth_error(res, 400, "invalid_grant", "client_id mismatch");
            return;
        }
        auto effective_client_id = client_id.empty() ? auth_code->client_id : client_id;

        auto auth = authenticate_client(effective_client_id, client_secret, secret_presented);
        if (!auth.ok) {
            log->warn("Token request rejected for client '{}': {}", effective_client_id, auth.description);
            oauth_error(res, 401, auth.error, auth.description);
            return;
        }

        // RFC 6749 4.1.3: redirect_uri is REQUIRED when it was present in the
        // authorization request, and must be identical.
        if (redirect_uri.empty() || auth_code->redirect_uri != redirect_uri) {
            oauth_error(res, 400, "invalid_grant", "redirect_uri mismatch");
            return;
        }

        // PKCE. Mandatory for public clients — an attacker can no longer simply
        // omit code_challenge to skip the check, because /authorize refuses to
        // issue a code without one.
        if (auth.requires_pkce && auth_code->code_challenge.empty()) {
            oauth_error(res, 400, "invalid_grant", "PKCE is required for public clients");
            return;
        }
        if (!auth_code->code_challenge.empty()) {
            if (code_verifier.empty()) {
                oauth_error(res, 400, "invalid_grant", "code_verifier is required");
                return;
            }
            if (code_verifier.size() < 43 || code_verifier.size() > 128) {
                oauth_error(res, 400, "invalid_grant", "Malformed code_verifier");
                return;
            }
            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256(reinterpret_cast<const unsigned char*>(code_verifier.c_str()),
                   code_verifier.size(), hash);
            auto computed_challenge = base64url_encode_local(hash, SHA256_DIGEST_LENGTH);
            if (!constant_time_equals(computed_challenge, auth_code->code_challenge)) {
                oauth_error(res, 400, "invalid_grant", "PKCE code_verifier mismatch");
                return;
            }
        }

        // RFC 8707 2.2: a resource repeated at the token endpoint must be one
        // the grant covers. Ours covers exactly the one named at /authorize,
        // so anything else — including naming a server when the grant named
        // none — is refused rather than silently ignored. The audience always
        // comes from the code, never from this parameter.
        if (!resource.empty()) {
            auto canonical = bsfchat::canonical_audience_url(resource);
            if (!canonical || *canonical != auth_code->resource) {
                oauth_error(res, 400, "invalid_target",
                            "resource does not match the authorization request");
                return;
            }
        }

        // Get account
        auto account = store_.get_account_by_id(auth_code->account_id);
        if (!account || account->disabled()) {
            oauth_error(res, 400, "invalid_grant", "Account no longer exists");
            return;
        }

        // Generate tokens
        auto access_token = create_access_token();
        auto id_token = create_id_token(*account, auth_code->client_id, auth_code->scope,
                                        auth_code->resource, auth_code->nonce);
        auto refresh_token = random_hex(32);

        auto now = now_seconds();

        // Access tokens live in the sessions table but are tagged as OIDC
        // credentials, so they cannot act as account-portal session cookies.
        Session access_session;
        access_session.session_id = access_token;
        access_session.account_id = account->id;
        access_session.created_at = now;
        access_session.expires_at = now + 3600; // 1 hour
        access_session.token_type = token_type::kOidcAccess;
        access_session.scope = auth_code->scope;
        access_session.client_id = auth_code->client_id;
        store_.create_session(access_session);

        // Store refresh token: the first of a new family, whose absolute
        // expiry no later rotation can move (security audit H4).
        RefreshToken rt;
        rt.token = refresh_token;
        rt.client_id = auth_code->client_id;
        rt.account_id = account->id;
        rt.scope = auth_code->scope;
        rt.family_id = random_hex(16);
        rt.family_expires_at = now + int64_t{86400} * config_.refresh_token_max_lifetime_days;
        rt.expires_at = std::min(now + int64_t{86400} * config_.refresh_token_idle_days,
                                 rt.family_expires_at);
        rt.created_at = now;
        store_.store_refresh_token(rt);

        json response = {
            {"access_token", access_token},
            {"token_type", "Bearer"},
            {"expires_in", 3600},
            {"scope", auth_code->scope},
            {"id_token", id_token},
            {"refresh_token", refresh_token}
        };

        res.set_header("Cache-Control", "no-store");
        res.set_content(response.dump(), "application/json");

    } else if (grant_type == "refresh_token") {
        if (refresh_token_str.empty()) {
            oauth_error(res, 400, "invalid_request", "refresh_token is required");
            return;
        }

        // A disabled account's tokens are filtered out by the store (H1).
        auto rt = store_.get_refresh_token(refresh_token_str);
        if (!rt) {
            oauth_error(res, 400, "invalid_grant", "Invalid refresh token");
            return;
        }

        if (!client_id.empty() && rt->client_id != client_id) {
            oauth_error(res, 400, "invalid_grant", "client_id mismatch");
            return;
        }
        auto effective_client_id = client_id.empty() ? rt->client_id : client_id;

        auto auth = authenticate_client(effective_client_id, client_secret, secret_presented);
        if (!auth.ok) {
            log->warn("Refresh rejected for client '{}': {}", effective_client_id, auth.description);
            oauth_error(res, 401, auth.error, auth.description);
            return;
        }

        auto account = store_.get_account_by_id(rt->account_id);
        if (!account || account->disabled()) {
            store_.delete_refresh_token(refresh_token_str);
            oauth_error(res, 400, "invalid_grant", "Account no longer exists");
            return;
        }

        // Rotate first, atomically (security audit L4): the old token is
        // retired and its successor stored in one transaction, and nothing is
        // minted unless that succeeded. Expiry (idle and absolute) and replay
        // of an already-rotated token are decided inside the same transaction.
        auto new_refresh_token = random_hex(32);
        auto now = now_seconds();
        RefreshToken new_rt;
        new_rt.token = new_refresh_token;
        new_rt.expires_at = now + int64_t{86400} * config_.refresh_token_idle_days;
        switch (store_.rotate_refresh_token(refresh_token_str, new_rt)) {
            case RotateResult::Rotated:
                break;
            case RotateResult::Reused:
                log->warn("Refresh token replayed for account {} (client {}); its grant was revoked",
                          rt->account_id, rt->client_id);
                oauth_error(res, 400, "invalid_grant", "Refresh token already used");
                return;
            case RotateResult::Invalid:
                oauth_error(res, 400, "invalid_grant", "Refresh token expired");
                return;
        }

        // Generate new tokens.
        //
        // The id_token minted here names no chat server: a refresh token is
        // not bound to one (the refresh token rows carry a family, not a
        // resource, and the desktop client never uses this path for a
        // sign-in — it runs a fresh authorization per server). So it gets the
        // legacy client_id audience, which no upgraded chat server accepts.
        // A refresh token therefore cannot be turned into a sign-in anywhere
        // that has the C1 fix, which is the safe direction to be wrong in.
        // Claims still follow the scope the grant was given (M4), and there
        // is no nonce: that belongs to an authorization request, and a
        // refresh is not one.
        auto access_token = create_access_token();
        auto id_token = create_id_token(*account, rt->client_id, rt->scope, "", "");

        Session access_session;
        access_session.session_id = access_token;
        access_session.account_id = account->id;
        access_session.created_at = now;
        access_session.expires_at = now + 3600;
        access_session.token_type = token_type::kOidcAccess;
        access_session.scope = rt->scope;
        access_session.client_id = rt->client_id;
        store_.create_session(access_session);

        json response = {
            {"access_token", access_token},
            {"token_type", "Bearer"},
            {"expires_in", 3600},
            {"scope", rt->scope},
            {"id_token", id_token},
            {"refresh_token", new_refresh_token}
        };

        res.set_header("Cache-Control", "no-store");
        res.set_content(response.dump(), "application/json");

    } else {
        oauth_error(res, 400, "unsupported_grant_type", "Unsupported grant_type");
    }
}

void OidcHandler::handle_userinfo(const httplib::Request& req, httplib::Response& res) {
    // Extract access token from Authorization header
    if (!req.has_header("Authorization")) {
        json_error(res, 401, "Missing Authorization header");
        return;
    }

    auto auth = req.get_header_value("Authorization");
    if (!auth.starts_with("Bearer ")) {
        json_error(res, 401, "Invalid Authorization header");
        return;
    }

    auto token = auth.substr(7);

    // Only an OIDC access token is accepted here — a browser session cookie
    // value is not an OAuth credential and must not be usable as one.
    auto session = store_.get_oidc_access_token(token);
    if (!session || session->expires_at < now_seconds()) {
        res.set_header("WWW-Authenticate", "Bearer error=\"invalid_token\"");
        json_error(res, 401, "Invalid or expired access token");
        return;
    }

    if (!scope_contains(session->scope, "openid")) {
        res.set_header("WWW-Authenticate", "Bearer error=\"insufficient_scope\", scope=\"openid\"");
        json_error(res, 403, "Token does not carry the openid scope");
        return;
    }

    auto account = store_.get_account_by_id(session->account_id);
    if (!account) {
        json_error(res, 404, "Account not found");
        return;
    }

    // Claims are released according to the granted scope rather than always
    // being dumped in full.
    json response = {{"sub", account->id}};
    if (scope_contains(session->scope, "profile")) {
        response["name"] = account->display_name;
        response["preferred_username"] = account->username;
        response["picture"] = account->avatar_url;
    }
    if (scope_contains(session->scope, "email")) {
        response["email"] = account->email;
    }

    res.set_header("Cache-Control", "no-store");
    res.set_content(response.dump(), "application/json");
}

void OidcHandler::handle_jwks(const httplib::Request&, httplib::Response& res) {
    res.set_content(key_manager_.get_jwks().dump(), "application/json");
}

void OidcHandler::handle_revoke(const httplib::Request& req, httplib::Response& res) {
    std::string token;

    if (req.get_header_value("Content-Type").find("application/x-www-form-urlencoded") != std::string::npos) {
        auto params = parse_form(req.body);
        token = params["token"];
    } else {
        try {
            auto body = json::parse(req.body);
            token = body.value("token", "");
        } catch (...) {
            json_error(res, 400, "Invalid request body");
            return;
        }
    }

    if (token.empty()) {
        json_error(res, 400, "token is required");
        return;
    }

    // Try to delete as refresh token — with every token rotated out of the
    // same grant, so revoking the current one cannot leave a sibling alive.
    store_.revoke_refresh_token_family(token);
    // Also try to delete as an OIDC access token. Restricted to that credential
    // kind so this unauthenticated endpoint cannot be used to destroy browser
    // sessions.
    if (store_.get_oidc_access_token(token)) {
        store_.delete_session(token);
    }

    res.set_header("Cache-Control", "no-store");
    res.set_content(json{{"success", true}}.dump(), "application/json");
}

std::string OidcHandler::create_id_token(const Account& account, const std::string& client_id,
                                         const std::string& scope, const std::string& resource,
                                         const std::string& nonce) {
    auto now = now_seconds();
    bsfchat::JwtClaims claims;
    claims.sub = account.id;
    claims.iss = config_.issuer_url;
    // C1. With a resource, the token is audienced to that one chat server and
    // to nothing else — deliberately NOT [resource, client_id]. OIDC Core
    // expects the client_id in `aud`, but every chat server that has not yet
    // been upgraded checks for exactly that value, so including it would keep
    // a token minted for a hostile server replayable against every
    // un-upgraded one, indefinitely. `azp` names the client instead.
    //
    // Without a resource (an old client, the desktop app's server-list sync,
    // a refresh), the legacy audience is kept so old clients still sign in to
    // old servers. Upgraded servers refuse it: it is the vulnerable one.
    claims.aud = resource.empty() ? client_id : resource;
    claims.azp = client_id;
    claims.iat = now;
    claims.exp = now + kIdTokenLifetimeSeconds;
    if (!nonce.empty()) claims.nonce = nonce;

    // M4: claims follow the granted scope, as /userinfo already did. The
    // id_token is what every chat server receives, so an email address in it
    // went to every chat server operator whatever the user had agreed to.
    if (scope_contains(scope, "profile")) {
        claims.name = account.display_name;
        claims.picture = account.avatar_url.empty() ? std::nullopt
                                                    : std::optional<std::string>(account.avatar_url);
    }
    if (scope_contains(scope, "email") && !account.email.empty()) {
        claims.email = account.email;
    }

    return key_manager_.sign_token(claims);
}

std::string OidcHandler::create_access_token() {
    return random_hex(32);
}

} // namespace bsfchat::id
