#include "api/AccountHandler.h"
#include "crypto/PasswordHash.h"
#include "crypto/Totp.h"
#include "core/Logger.h"
#include "core/WebUtil.h"

#include <bsfchat/Identifiers.h>
#include <nlohmann/json.hpp>
#include <openssl/rand.h>

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace bsfchat::id {

namespace {

using json = nlohmann::json;

int64_t now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string generate_uuid() {
    unsigned char bytes[16];
    RAND_bytes(bytes, sizeof(bytes));
    // Set version 4 and variant bits
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 16; ++i) {
        ss << std::setw(2) << static_cast<int>(bytes[i]);
        if (i == 3 || i == 5 || i == 7 || i == 9) ss << '-';
    }
    return ss.str();
}

std::string generate_session_id() {
    unsigned char bytes[32];
    RAND_bytes(bytes, sizeof(bytes));
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 32; ++i) {
        ss << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return ss.str();
}

void json_error(httplib::Response& res, int status, const std::string& error) {
    res.status = status;
    res.set_content(json{{"error", error}}.dump(), "application/json");
}

// Reads the `session` cookie with a real cookie parser. The previous
// `cookie.find("session=")` substring search also matched "mysession=".
std::string extract_session_id(const httplib::Request& req) {
    if (!req.has_header("Cookie")) return "";
    auto value = get_cookie(req.get_header_value("Cookie"), "session");
    return value.value_or("");
}

// Bearer token presented on the request, if any.
std::string extract_bearer_token(const httplib::Request& req) {
    if (!req.has_header("Authorization")) return "";
    auto auth = req.get_header_value("Authorization");
    if (!auth.starts_with("Bearer ")) return "";
    return auth.substr(7);
}

// Scope an OIDC access token must carry to reach the server-membership API.
//
// Ideally this would be a dedicated `bsfchat:servers` scope, but the shipped
// desktop client requests exactly "openid profile" and relies on the resulting
// access token for /api/servers, so requiring a new scope would break it.
// `openid` is therefore the bar here — and only here. Account management,
// session control, 2FA and admin remain browser-session only.
constexpr const char* kServersScope = "openid";

std::string generate_hex_token(int bytes) {
    std::vector<unsigned char> buf(bytes);
    RAND_bytes(buf.data(), bytes);
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < bytes; ++i) {
        ss << std::setw(2) << static_cast<int>(buf[i]);
    }
    return ss.str();
}

} // namespace

AccountHandler::AccountHandler(IdentityStore& store, const Config& config)
    : store_(store)
    , config_(config)
    , login_limiter_(config.login_rate_limit, std::chrono::seconds(config.login_rate_window))
    , login_failures_(config.login_max_failures, std::chrono::seconds(config.login_lockout_seconds))
    , totp_failures_(config.login_max_failures, std::chrono::seconds(config.login_lockout_seconds)) {}

std::string AccountHandler::client_key(const httplib::Request& req) {
    return req.remote_addr.empty() ? std::string("unknown") : req.remote_addr;
}

std::string AccountHandler::session_cookie(const std::string& session_id, int max_age_seconds) const {
    std::string cookie = "session=" + session_id + "; Path=/; HttpOnly; SameSite=Lax; Max-Age="
                       + std::to_string(max_age_seconds);
    if (config_.cookie_secure) cookie += "; Secure";
    return cookie;
}

void AccountHandler::prune_limiters() {
    login_limiter_.prune();
    login_failures_.prune();
    totp_failures_.prune();
}

std::string AccountHandler::get_session_account(const httplib::Request& req) {
    // Browser session cookie.
    auto session_id = extract_session_id(req);
    if (!session_id.empty()) {
        auto session = store_.get_browser_session(session_id);
        if (session && session->expires_at > now_seconds()) {
            return session->account_id;
        }
    }

    // A browser session id may also be presented as a bearer token: /api/login
    // returns it in the JSON body precisely so non-browser callers can use it.
    // get_browser_session() filters on token_type, so an OIDC access token
    // presented here resolves to nothing.
    auto token = extract_bearer_token(req);
    if (!token.empty()) {
        auto session = store_.get_browser_session(token);
        if (session && session->expires_at > now_seconds()) {
            return session->account_id;
        }
    }

    return "";
}

AuthContext AccountHandler::authenticate(const httplib::Request& req, const std::string& required_scope) {
    AuthContext ctx;

    auto browser_account = get_session_account(req);
    if (!browser_account.empty()) {
        ctx.account_id = browser_account;
        ctx.token_type = token_type::kBrowserSession;
        ctx.credential_id = extract_session_id(req);
        if (ctx.credential_id.empty()) ctx.credential_id = extract_bearer_token(req);
        return ctx;
    }

    auto token = extract_bearer_token(req);
    if (!token.empty()) {
        auto access = store_.get_oidc_access_token(token);
        if (access && access->expires_at > now_seconds() &&
            scope_contains(access->scope, required_scope)) {
            ctx.account_id = access->account_id;
            ctx.token_type = token_type::kOidcAccess;
            ctx.credential_id = token;
            ctx.scope = access->scope;
        }
    }

    return ctx;
}

void AccountHandler::handle_register(const httplib::Request& req, httplib::Response& res) {
    auto log = get_logger();

    if (!config_.registration_enabled) {
        json_error(res, 403, "Registration is disabled");
        return;
    }

    // Registration runs a full-cost PBKDF2, so an unauthenticated flood here is
    // a CPU exhaustion vector as well as an account-spam one.
    if (!login_limiter_.allow("register:" + client_key(req))) {
        res.set_header("Retry-After", std::to_string(config_.login_rate_window));
        json_error(res, 429, "Too many registration attempts, please slow down");
        return;
    }

    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        json_error(res, 400, "Invalid JSON");
        return;
    }

    auto username = body.value("username", "");
    auto password = body.value("password", "");
    auto email = body.value("email", "");

    if (username.empty() || password.empty()) {
        json_error(res, 400, "Username and password are required");
        return;
    }

    if (username.size() > 64) {
        json_error(res, 400, "Username too long");
        return;
    }

    if (password.size() < 8) {
        json_error(res, 400, "Password must be at least 8 characters");
        return;
    }

    // Check for existing user
    if (store_.get_account_by_username(username)) {
        json_error(res, 409, "Username already taken");
        return;
    }

    auto now = now_seconds();
    Account account;
    account.id = generate_uuid();
    account.username = username;
    account.email = email;
    account.password_hash = hash_password(password, config_.password_hash_iterations);
    account.display_name = username;
    account.created_at = now;
    account.updated_at = now;

    if (!store_.create_account(account)) {
        json_error(res, 500, "Failed to create account");
        return;
    }

    log->info("Account created: {} ({})", username, account.id);

    // Create a session automatically
    auto session_id = generate_session_id();
    Session session;
    session.session_id = session_id;
    session.account_id = account.id;
    session.created_at = now;
    session.expires_at = now + 86400 * 7; // 7 days
    store_.create_session(session);

    json response = {
        {"user_id", account.id},
        {"username", account.username},
        {"session_id", session_id}
    };

    res.set_header("Set-Cookie", session_cookie(session_id, 604800));
    res.status = 201;
    res.set_content(response.dump(), "application/json");
}

void AccountHandler::handle_login(const httplib::Request& req, httplib::Response& res) {
    auto log = get_logger();

    // Throttle before doing any work, so an unauthenticated caller cannot
    // spend our CPU on PBKDF2 or enumerate accounts at speed.
    auto ip_key = client_key(req);
    if (!login_limiter_.allow("login:" + ip_key)) {
        res.set_header("Retry-After", std::to_string(config_.login_rate_window));
        json_error(res, 429, "Too many login attempts, please slow down");
        return;
    }

    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        json_error(res, 400, "Invalid JSON");
        return;
    }

    auto username = body.value("username", "");
    auto password = body.value("password", "");

    if (username.empty() || password.empty()) {
        json_error(res, 400, "Username and password are required");
        return;
    }

    // Lock out on the account as well as the source address, so a distributed
    // guessing attack against one user still hits a wall.
    const auto ip_failure_key = "login-ip:" + ip_key;
    const auto user_failure_key = "login-user:" + username;
    if (login_failures_.is_locked(ip_failure_key) || login_failures_.is_locked(user_failure_key)) {
        auto retry = std::max(login_failures_.retry_after(ip_failure_key),
                              login_failures_.retry_after(user_failure_key));
        res.set_header("Retry-After", std::to_string(retry));
        json_error(res, 429, "Too many failed attempts, try again later");
        return;
    }

    auto account = store_.get_account_by_username(username);
    if (!account || account->password_hash.empty() ||
        !verify_password(password, account->password_hash)) {
        login_failures_.record_failure(ip_failure_key);
        login_failures_.record_failure(user_failure_key);
        log->warn("Failed login for '{}' from {}", username, ip_key);
        json_error(res, 401, "Invalid username or password");
        return;
    }

    login_failures_.clear(ip_failure_key);
    login_failures_.clear(user_failure_key);

    // Opportunistically upgrade hashes written under the old 4,096-iteration
    // scheme, now that we hold the plaintext and know it is correct.
    if (password_needs_rehash(account->password_hash, config_.password_hash_iterations)) {
        try {
            store_.update_password_hash(account->id, hash_password(password, config_.password_hash_iterations));
            log->info("Upgraded password hash for {}", account->username);
        } catch (const std::exception& e) {
            log->warn("Password hash upgrade failed for {}: {}", account->username, e.what());
        }
    }

    // Check if 2FA is enabled
    auto totp_info = store_.get_totp(account->id);
    if (totp_info && totp_info->enabled) {
        auto login_token = generate_hex_token(32);
        auto now = now_seconds();
        store_.create_login_token(login_token, account->id, now + 300); // 5 minutes

        log->info("Login requires 2FA: {}", username);

        json response = {
            {"requires_2fa", true},
            {"login_token", login_token}
        };
        res.set_content(response.dump(), "application/json");
        return;
    }

    auto now = now_seconds();
    auto session_id = generate_session_id();
    Session session;
    session.session_id = session_id;
    session.account_id = account->id;
    session.created_at = now;
    session.expires_at = now + 86400 * 7;
    store_.create_session(session);

    log->info("Login successful: {}", username);

    json response = {
        {"user_id", account->id},
        {"username", account->username},
        {"session_id", session_id}
    };

    res.set_header("Set-Cookie", session_cookie(session_id, 604800));
    res.set_content(response.dump(), "application/json");
}

void AccountHandler::handle_logout(const httplib::Request& req, httplib::Response& res) {
    auto account_id = get_session_account(req);
    if (account_id.empty()) {
        json_error(res, 401, "Not authenticated");
        return;
    }

    // Delete whichever browser session credential was presented.
    auto session_id = extract_session_id(req);
    if (session_id.empty()) session_id = extract_bearer_token(req);
    if (!session_id.empty()) {
        auto session = store_.get_browser_session(session_id);
        if (session) store_.delete_session(session_id);
    }

    res.set_header("Set-Cookie", session_cookie("", 0));
    res.set_content(json{{"success", true}}.dump(), "application/json");
}

void AccountHandler::handle_get_profile(const httplib::Request& req, httplib::Response& res) {
    auto account_id = get_session_account(req);
    if (account_id.empty()) {
        json_error(res, 401, "Not authenticated");
        return;
    }

    auto account = store_.get_account_by_id(account_id);
    if (!account) {
        json_error(res, 404, "Account not found");
        return;
    }

    json response = {
        {"user_id", account->id},
        {"username", account->username},
        {"display_name", account->display_name},
        {"avatar_url", account->avatar_url},
        {"email", account->email},
        {"is_admin", account->is_admin}
    };
    res.set_content(response.dump(), "application/json");
}

void AccountHandler::handle_update_profile(const httplib::Request& req, httplib::Response& res) {
    auto account_id = get_session_account(req);
    if (account_id.empty()) {
        json_error(res, 401, "Not authenticated");
        return;
    }

    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        json_error(res, 400, "Invalid JSON");
        return;
    }

    auto account = store_.get_account_by_id(account_id);
    if (!account) {
        json_error(res, 404, "Account not found");
        return;
    }

    if (body.contains("display_name")) account->display_name = body["display_name"].get<std::string>();
    if (body.contains("avatar_url")) account->avatar_url = body["avatar_url"].get<std::string>();
    if (body.contains("email")) account->email = body["email"].get<std::string>();

    // Handle password change
    if (body.contains("new_password")) {
        auto old_password = body.value("old_password", "");
        if (old_password.empty() || !verify_password(old_password, account->password_hash)) {
            json_error(res, 403, "Current password is incorrect");
            return;
        }
        auto new_password = body["new_password"].get<std::string>();
        if (new_password.size() < 8) {
            json_error(res, 400, "New password must be at least 8 characters");
            return;
        }
        // update_account() does not write password_hash, so the change has to
        // go through the dedicated statement — previously it was silently
        // discarded and the old password kept working.
        auto new_hash = hash_password(new_password, config_.password_hash_iterations);
        if (!store_.update_password_hash(account->id, new_hash)) {
            json_error(res, 500, "Failed to update password");
            return;
        }
        account->password_hash = new_hash;
    }

    account->updated_at = now_seconds();
    store_.update_account(*account);

    json response = {
        {"user_id", account->id},
        {"username", account->username},
        {"display_name", account->display_name},
        {"avatar_url", account->avatar_url},
        {"email", account->email}
    };
    res.set_content(response.dump(), "application/json");
}

// Session management

void AccountHandler::handle_list_sessions(const httplib::Request& req, httplib::Response& res) {
    auto account_id = get_session_account(req);
    if (account_id.empty()) {
        json_error(res, 401, "Not authenticated");
        return;
    }

    auto current_session_id = extract_session_id(req);
    auto sessions = store_.list_sessions_for_account(account_id);

    json result = json::array();
    for (const auto& s : sessions) {
        result.push_back({
            {"session_id", s.session_id.substr(0, 8) + "..."},
            {"created_at", s.created_at},
            {"expires_at", s.expires_at},
            {"is_current", s.session_id == current_session_id}
        });
    }
    res.set_content(result.dump(), "application/json");
}

void AccountHandler::handle_revoke_session(const httplib::Request& req, httplib::Response& res) {
    auto account_id = get_session_account(req);
    if (account_id.empty()) {
        json_error(res, 401, "Not authenticated");
        return;
    }

    // Extract session_id from path: /api/user/sessions/<id>
    auto target_session_id = req.matches[1].str();
    if (target_session_id.empty()) {
        json_error(res, 400, "Session ID required");
        return;
    }

    // Can't revoke own current session
    auto current_session_id = extract_session_id(req);
    if (target_session_id == current_session_id) {
        json_error(res, 400, "Cannot revoke current session");
        return;
    }

    // Verify the session belongs to the authenticated user. Restricted to
    // browser sessions, which is what handle_list_sessions exposes.
    auto session = store_.get_browser_session(target_session_id);
    if (!session || session->account_id != account_id) {
        json_error(res, 404, "Session not found");
        return;
    }

    store_.delete_session(target_session_id);
    res.set_content(json{{"success", true}}.dump(), "application/json");
}

// 2FA / TOTP

void AccountHandler::handle_2fa_status(const httplib::Request& req, httplib::Response& res) {
    auto account_id = get_session_account(req);
    if (account_id.empty()) {
        json_error(res, 401, "Not authenticated");
        return;
    }

    auto totp = store_.get_totp(account_id);
    bool enabled = totp && totp->enabled;
    res.set_content(json{{"enabled", enabled}}.dump(), "application/json");
}

void AccountHandler::handle_2fa_setup(const httplib::Request& req, httplib::Response& res) {
    auto account_id = get_session_account(req);
    if (account_id.empty()) {
        json_error(res, 401, "Not authenticated");
        return;
    }

    auto account = store_.get_account_by_id(account_id);
    if (!account) {
        json_error(res, 404, "Account not found");
        return;
    }

    // Re-running setup on an account that already has 2FA is a downgrade, not
    // an enrolment: set_totp_secret() does INSERT OR REPLACE with enabled = 0,
    // so a single POST here silently stripped the second factor and left a new
    // unconfirmed secret behind. This endpoint only needs a session cookie,
    // while /2fa/disable deliberately demands the password — so the cheap path
    // to single-factor was the one with no password on it. Turning 2FA off is
    // /2fa/disable's job, and it asks.
    if (auto existing = store_.get_totp(account_id); existing && existing->enabled) {
        json_error(res, 409,
                   "Two-factor authentication is already enabled. Disable it first.");
        return;
    }

    auto secret = bsfchat::generate_totp_secret();
    auto backup_codes = bsfchat::generate_backup_codes(8);
    auto uri = bsfchat::totp_provisioning_uri(secret, account->username, "BSFChat");

    // The store hashes the codes on the way in; this response is the only time
    // they are ever visible.
    store_.set_totp_secret(account_id, secret, backup_codes);

    json response = {
        {"secret", secret},
        {"provisioning_uri", uri},
        {"backup_codes", backup_codes}
    };
    res.set_content(response.dump(), "application/json");
}

void AccountHandler::handle_2fa_verify(const httplib::Request& req, httplib::Response& res) {
    auto account_id = get_session_account(req);
    if (account_id.empty()) {
        json_error(res, 401, "Not authenticated");
        return;
    }

    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        json_error(res, 400, "Invalid JSON");
        return;
    }

    auto code = body.value("code", "");
    if (code.empty()) {
        json_error(res, 400, "Code is required");
        return;
    }

    // Enrolment confirmation is authenticated, but still guessable at 10^6, so
    // it gets the same throttling as the login-time check.
    const auto enrol_key = "2fa-enrol:" + account_id;
    if (totp_failures_.is_locked(enrol_key)) {
        res.set_header("Retry-After", std::to_string(totp_failures_.retry_after(enrol_key)));
        json_error(res, 429, "Too many incorrect codes, try again later");
        return;
    }

    auto totp = store_.get_totp(account_id);
    if (!totp) {
        json_error(res, 400, "2FA not set up - call setup first");
        return;
    }

    if (!bsfchat::verify_totp(totp->secret, code)) {
        totp_failures_.record_failure(enrol_key);
        json_error(res, 400, "Invalid code");
        return;
    }

    totp_failures_.clear(enrol_key);
    store_.enable_totp(account_id);
    res.set_content(json{{"success", true}}.dump(), "application/json");
}

void AccountHandler::handle_2fa_disable(const httplib::Request& req, httplib::Response& res) {
    auto account_id = get_session_account(req);
    if (account_id.empty()) {
        json_error(res, 401, "Not authenticated");
        return;
    }

    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        json_error(res, 400, "Invalid JSON");
        return;
    }

    auto password = body.value("password", "");
    if (password.empty()) {
        json_error(res, 400, "Password is required");
        return;
    }

    auto account = store_.get_account_by_id(account_id);
    if (!account) {
        json_error(res, 404, "Account not found");
        return;
    }

    if (!verify_password(password, account->password_hash)) {
        json_error(res, 403, "Invalid password");
        return;
    }

    store_.disable_totp(account_id);
    res.set_content(json{{"success", true}}.dump(), "application/json");
}

void AccountHandler::handle_login_2fa(const httplib::Request& req, httplib::Response& res) {
    auto log = get_logger();

    auto ip_key = client_key(req);
    if (!login_limiter_.allow("2fa:" + ip_key)) {
        res.set_header("Retry-After", std::to_string(config_.login_rate_window));
        json_error(res, 429, "Too many attempts, please slow down");
        return;
    }

    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        json_error(res, 400, "Invalid JSON");
        return;
    }

    auto login_token = body.value("login_token", "");
    auto code = body.value("code", "");

    if (login_token.empty() || code.empty()) {
        json_error(res, 400, "login_token and code are required");
        return;
    }

    const auto ip_failure_key = "2fa-ip:" + ip_key;
    if (login_failures_.is_locked(ip_failure_key)) {
        res.set_header("Retry-After", std::to_string(login_failures_.retry_after(ip_failure_key)));
        json_error(res, 429, "Too many failed attempts, try again later");
        return;
    }

    auto account_id = store_.validate_login_token(login_token);
    if (!account_id) {
        login_failures_.record_failure(ip_failure_key);
        json_error(res, 401, "Invalid or expired login token");
        return;
    }

    auto totp = store_.get_totp(*account_id);
    if (!totp || !totp->enabled) {
        json_error(res, 400, "2FA not enabled for this account");
        return;
    }

    // Try TOTP code first, then backup code
    bool code_valid = bsfchat::verify_totp(totp->secret, code);
    if (!code_valid) {
        code_valid = store_.consume_backup_code(*account_id, code);
    }
    if (!code_valid) {
        login_failures_.record_failure(ip_failure_key);
        // Burn the login token after a handful of wrong codes. Without this the
        // token stayed usable for its full five minutes, which is more than
        // enough to walk the entire six-digit keyspace in parallel.
        bool destroyed = store_.record_login_token_failure(login_token, config_.totp_max_attempts);
        if (destroyed) {
            log->warn("2FA login token destroyed after {} failed codes (account {}, from {})",
                      config_.totp_max_attempts, *account_id, ip_key);
            json_error(res, 401, "Too many incorrect codes — please sign in again");
            return;
        }
        json_error(res, 401, "Invalid 2FA code");
        return;
    }

    login_failures_.clear(ip_failure_key);

    // Consume the login token
    store_.delete_login_token(login_token);

    // Create session
    auto now = now_seconds();
    auto session_id = generate_session_id();
    Session session;
    session.session_id = session_id;
    session.account_id = *account_id;
    session.created_at = now;
    session.expires_at = now + 86400 * 7;
    store_.create_session(session);

    auto account = store_.get_account_by_id(*account_id);
    log->info("Login 2FA successful: {}", account ? account->username : *account_id);

    json response = {
        {"user_id", *account_id},
        {"username", account ? account->username : ""},
        {"session_id", session_id}
    };

    res.set_header("Set-Cookie", session_cookie(session_id, 604800));
    res.set_content(response.dump(), "application/json");
}

// Server memberships
//
// These are the one API family an OIDC access token may reach, because the
// desktop client legitimately syncs the user's server list with the token it
// receives from the OIDC flow. Everything else on this handler stays behind a
// browser session.

void AccountHandler::handle_list_servers(const httplib::Request& req, httplib::Response& res) {
    auto ctx = authenticate(req, kServersScope);
    if (!ctx.authenticated()) {
        json_error(res, 401, "Not authenticated");
        return;
    }
    const auto& account_id = ctx.account_id;

    auto servers = store_.list_server_memberships(account_id);
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& s : servers) {
        arr.push_back({
            {"id", s.id},
            {"server_url", s.server_url},
            {"server_name", s.server_name},
            {"joined_at", s.joined_at}
        });
    }
    res.set_content(arr.dump(), "application/json");
}

void AccountHandler::handle_add_server(const httplib::Request& req, httplib::Response& res) {
    auto ctx = authenticate(req, kServersScope);
    if (!ctx.authenticated()) {
        json_error(res, 401, "Not authenticated");
        return;
    }
    const auto& account_id = ctx.account_id;

    auto body = nlohmann::json::parse(req.body, nullptr, false);
    if (body.is_discarded() || !body.contains("server_url")) {
        json_error(res, 400, "Missing server_url");
        return;
    }

    std::string url = body["server_url"].get<std::string>();
    std::string name = body.value("server_name", "");
    store_.add_server_membership(account_id, url, name);
    res.set_content(nlohmann::json{{"success", true}}.dump(), "application/json");
}

void AccountHandler::handle_remove_server(const httplib::Request& req, httplib::Response& res) {
    auto ctx = authenticate(req, kServersScope);
    if (!ctx.authenticated()) {
        json_error(res, 401, "Not authenticated");
        return;
    }
    const auto& account_id = ctx.account_id;

    // Accept server_url from query param (for DELETE which may not carry body)
    // or from JSON body.
    std::string url;
    if (req.has_param("server_url")) {
        url = req.get_param_value("server_url");
    } else {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (!body.is_discarded() && body.contains("server_url")) {
            url = body["server_url"].get<std::string>();
        }
    }
    if (url.empty()) {
        json_error(res, 400, "Missing server_url");
        return;
    }

    store_.remove_server_membership(account_id, url);
    res.set_content(nlohmann::json{{"success", true}}.dump(), "application/json");
}

} // namespace bsfchat::id
