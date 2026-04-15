#include "api/OidcHandler.h"
#include "core/Logger.h"

#include <bsfchat/Identifiers.h>
#include <nlohmann/json.hpp>
#include <openssl/rand.h>
#include <openssl/sha.h>

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

std::string random_hex(int bytes) {
    std::vector<unsigned char> buf(bytes);
    RAND_bytes(buf.data(), bytes);
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (auto b : buf) ss << std::setw(2) << static_cast<int>(b);
    return ss.str();
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

// Parse URL-encoded form body
std::map<std::string, std::string> parse_form(const std::string& body) {
    std::map<std::string, std::string> params;
    std::istringstream ss(body);
    std::string pair;
    while (std::getline(ss, pair, '&')) {
        auto eq = pair.find('=');
        if (eq != std::string::npos) {
            auto key = pair.substr(0, eq);
            auto val = pair.substr(eq + 1);
            // Simple URL decode for common cases
            std::string decoded;
            for (size_t i = 0; i < val.size(); ++i) {
                if (val[i] == '%' && i + 2 < val.size()) {
                    decoded += static_cast<char>(std::stoi(val.substr(i + 1, 2), nullptr, 16));
                    i += 2;
                } else if (val[i] == '+') {
                    decoded += ' ';
                } else {
                    decoded += val[i];
                }
            }
            params[key] = decoded;
        }
    }
    return params;
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
        {"token_endpoint_auth_methods_supported", json::array({"client_secret_post", "client_secret_basic"})},
        {"code_challenge_methods_supported", json::array({"S256", "plain"})}
    };
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

    // Validate redirect_uri against client's registered URIs
    {
        bool uri_valid = false;
        try {
            auto uris = json::parse(client->redirect_uris);
            for (const auto& registered : uris) {
                auto reg_str = registered.get<std::string>();
                if (reg_str == redirect_uri) {
                    uri_valid = true;
                    break;
                }
                // RFC 8252: for native apps, "http://localhost" matches any port
                if (reg_str == "http://localhost" &&
                    redirect_uri.starts_with("http://localhost:")) {
                    uri_valid = true;
                    break;
                }
            }
        } catch (...) {
            // If redirect_uris isn't valid JSON, fall through to reject
        }
        if (!uri_valid) {
            json_error(res, 400, "Invalid redirect_uri for this client");
            return;
        }
    }

    // Check if user is logged in (has session cookie)
    auto account_id = account_handler_.get_session_account(req);
    if (account_id.empty()) {
        // Redirect to login page with return URL
        std::string login_url = "/login.html?redirect=" + redirect_uri
            + "&client_id=" + client_id
            + "&response_type=" + response_type
            + "&scope=" + scope
            + "&state=" + state;
        if (!code_challenge.empty()) {
            login_url += "&code_challenge=" + code_challenge;
            login_url += "&code_challenge_method=" + code_challenge_method;
        }
        res.set_redirect(login_url);
        return;
    }

    // Generate authorization code
    auto code = random_hex(32);
    auto now = now_seconds();

    AuthCode auth_code;
    auth_code.code = code;
    auth_code.client_id = client_id;
    auth_code.account_id = account_id;
    auth_code.redirect_uri = redirect_uri;
    auth_code.scope = scope;
    auth_code.code_challenge = code_challenge;
    auth_code.expires_at = now + 300; // 5 minutes

    store_.store_auth_code(auth_code);

    // Redirect back to client with code
    std::string location = redirect_uri + "?code=" + code;
    if (!state.empty()) location += "&state=" + state;

    res.set_redirect(location);
}

void OidcHandler::handle_token(const httplib::Request& req, httplib::Response& res) {
    auto log = get_logger();

    // Parse either form-encoded or JSON body
    std::string grant_type, code, redirect_uri, client_id, client_secret, refresh_token_str, code_verifier;

    if (req.get_header_value("Content-Type").find("application/x-www-form-urlencoded") != std::string::npos) {
        auto params = parse_form(req.body);
        grant_type = params["grant_type"];
        code = params["code"];
        redirect_uri = params["redirect_uri"];
        client_id = params["client_id"];
        client_secret = params["client_secret"];
        refresh_token_str = params["refresh_token"];
        code_verifier = params["code_verifier"];
    } else {
        try {
            auto body = json::parse(req.body);
            grant_type = body.value("grant_type", "");
            code = body.value("code", "");
            redirect_uri = body.value("redirect_uri", "");
            client_id = body.value("client_id", "");
            client_secret = body.value("client_secret", "");
            refresh_token_str = body.value("refresh_token", "");
            code_verifier = body.value("code_verifier", "");
        } catch (...) {
            json_error(res, 400, "Invalid request body");
            return;
        }
    }

    // Also check for HTTP Basic auth for client credentials
    if (client_id.empty() && req.has_header("Authorization")) {
        auto auth = req.get_header_value("Authorization");
        if (auth.starts_with("Basic ")) {
            auto decoded_bytes = base64_decode_local(auth.substr(6));
            std::string credentials(decoded_bytes.begin(), decoded_bytes.end());
            auto colon = credentials.find(':');
            if (colon != std::string::npos) {
                client_id = credentials.substr(0, colon);
                client_secret = credentials.substr(colon + 1);
            }
        }
    }

    if (grant_type == "authorization_code") {
        if (code.empty()) {
            json_error(res, 400, "code is required");
            return;
        }

        auto auth_code = store_.get_auth_code(code);
        if (!auth_code) {
            json_error(res, 400, "Invalid authorization code");
            return;
        }

        // Check expiry
        if (auth_code->expires_at < now_seconds()) {
            store_.delete_auth_code(code);
            json_error(res, 400, "Authorization code expired");
            return;
        }

        // Verify client
        if (!client_id.empty() && auth_code->client_id != client_id) {
            json_error(res, 400, "client_id mismatch");
            return;
        }

        // Verify redirect_uri
        if (!redirect_uri.empty() && auth_code->redirect_uri != redirect_uri) {
            json_error(res, 400, "redirect_uri mismatch");
            return;
        }

        // PKCE verification
        if (!auth_code->code_challenge.empty()) {
            if (code_verifier.empty()) {
                json_error(res, 400, "code_verifier is required");
                return;
            }
            // S256: SHA256(code_verifier), then base64url encode
            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256(reinterpret_cast<const unsigned char*>(code_verifier.c_str()),
                   code_verifier.size(), hash);
            // Base64url encode the hash
            auto computed_challenge = base64url_encode_local(hash, SHA256_DIGEST_LENGTH);
            if (computed_challenge != auth_code->code_challenge) {
                json_error(res, 400, "PKCE code_verifier mismatch");
                return;
            }
        }

        // Delete the code (single use)
        store_.delete_auth_code(code);

        // Get account
        auto account = store_.get_account_by_id(auth_code->account_id);
        if (!account) {
            json_error(res, 500, "Account not found");
            return;
        }

        // Generate tokens
        auto access_token = create_access_token();
        auto id_token = create_id_token(*account, auth_code->client_id);
        auto refresh_token = random_hex(32);

        auto now = now_seconds();

        // Store access token as a session so userinfo can look it up
        Session access_session;
        access_session.session_id = access_token;
        access_session.account_id = account->id;
        access_session.created_at = now;
        access_session.expires_at = now + 3600; // 1 hour
        store_.create_session(access_session);

        // Store refresh token
        RefreshToken rt;
        rt.token = refresh_token;
        rt.client_id = auth_code->client_id;
        rt.account_id = account->id;
        rt.scope = auth_code->scope;
        rt.expires_at = now + 86400 * 30; // 30 days
        store_.store_refresh_token(rt);

        json response = {
            {"access_token", access_token},
            {"token_type", "Bearer"},
            {"expires_in", 3600},
            {"id_token", id_token},
            {"refresh_token", refresh_token}
        };

        res.set_header("Cache-Control", "no-store");
        res.set_content(response.dump(), "application/json");

    } else if (grant_type == "refresh_token") {
        if (refresh_token_str.empty()) {
            json_error(res, 400, "refresh_token is required");
            return;
        }

        auto rt = store_.get_refresh_token(refresh_token_str);
        if (!rt) {
            json_error(res, 400, "Invalid refresh token");
            return;
        }

        if (rt->expires_at < now_seconds()) {
            store_.delete_refresh_token(refresh_token_str);
            json_error(res, 400, "Refresh token expired");
            return;
        }

        auto account = store_.get_account_by_id(rt->account_id);
        if (!account) {
            json_error(res, 500, "Account not found");
            return;
        }

        // Generate new tokens
        auto access_token = create_access_token();
        auto id_token = create_id_token(*account, rt->client_id);
        auto new_refresh_token = random_hex(32);

        auto now = now_seconds();

        // Store new access token session
        Session access_session;
        access_session.session_id = access_token;
        access_session.account_id = account->id;
        access_session.created_at = now;
        access_session.expires_at = now + 3600;
        store_.create_session(access_session);

        // Rotate refresh token
        store_.delete_refresh_token(refresh_token_str);
        RefreshToken new_rt;
        new_rt.token = new_refresh_token;
        new_rt.client_id = rt->client_id;
        new_rt.account_id = rt->account_id;
        new_rt.scope = rt->scope;
        new_rt.expires_at = now + 86400 * 30;
        store_.store_refresh_token(new_rt);

        json response = {
            {"access_token", access_token},
            {"token_type", "Bearer"},
            {"expires_in", 3600},
            {"id_token", id_token},
            {"refresh_token", new_refresh_token}
        };

        res.set_header("Cache-Control", "no-store");
        res.set_content(response.dump(), "application/json");

    } else {
        json_error(res, 400, "Unsupported grant_type");
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
    auto session = store_.get_session(token);
    if (!session || session->expires_at < now_seconds()) {
        json_error(res, 401, "Invalid or expired access token");
        return;
    }

    auto account = store_.get_account_by_id(session->account_id);
    if (!account) {
        json_error(res, 404, "Account not found");
        return;
    }

    json response = {
        {"sub", account->id},
        {"name", account->display_name},
        {"preferred_username", account->username},
        {"email", account->email},
        {"picture", account->avatar_url}
    };

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

    // Try to delete as refresh token
    store_.delete_refresh_token(token);
    // Also try to delete as session/access token
    store_.delete_session(token);

    res.set_content(json{{"success", true}}.dump(), "application/json");
}

std::string OidcHandler::create_id_token(const Account& account, const std::string& client_id) {
    auto now = now_seconds();
    bsfchat::JwtClaims claims;
    claims.sub = account.id;
    claims.iss = config_.issuer_url;
    claims.aud = client_id;
    claims.iat = now;
    claims.exp = now + 3600; // 1 hour
    claims.name = account.display_name;
    claims.email = account.email.empty() ? std::nullopt : std::optional<std::string>(account.email);
    claims.picture = account.avatar_url.empty() ? std::nullopt : std::optional<std::string>(account.avatar_url);

    return key_manager_.sign_token(claims);
}

std::string OidcHandler::create_access_token() {
    return random_hex(32);
}

} // namespace bsfchat::id
