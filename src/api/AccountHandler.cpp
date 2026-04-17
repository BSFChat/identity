#include "api/AccountHandler.h"
#include "crypto/PasswordHash.h"
#include "crypto/Totp.h"
#include "core/Logger.h"

#include <bsfchat/Identifiers.h>
#include <nlohmann/json.hpp>
#include <openssl/rand.h>

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

std::string extract_session_id(const httplib::Request& req) {
    if (req.has_header("Cookie")) {
        auto cookie = req.get_header_value("Cookie");
        auto pos = cookie.find("session=");
        if (pos != std::string::npos) {
            auto start = pos + 8;
            auto end = cookie.find(';', start);
            return (end != std::string::npos) ? cookie.substr(start, end - start) : cookie.substr(start);
        }
    }
    return "";
}

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
    : store_(store), config_(config) {}

std::string AccountHandler::get_session_account(const httplib::Request& req) {
    // Check for session cookie
    if (req.has_header("Cookie")) {
        auto cookie = req.get_header_value("Cookie");
        auto pos = cookie.find("session=");
        if (pos != std::string::npos) {
            auto start = pos + 8;
            auto end = cookie.find(';', start);
            auto session_id = (end != std::string::npos) ? cookie.substr(start, end - start) : cookie.substr(start);
            auto session = store_.get_session(session_id);
            if (session && session->expires_at > now_seconds()) {
                return session->account_id;
            }
        }
    }

    // Also check Authorization: Bearer <token> for API access
    if (req.has_header("Authorization")) {
        auto auth = req.get_header_value("Authorization");
        if (auth.starts_with("Bearer ")) {
            auto token = auth.substr(7);
            auto session = store_.get_session(token);
            if (session && session->expires_at > now_seconds()) {
                return session->account_id;
            }
        }
    }

    return "";
}

void AccountHandler::handle_register(const httplib::Request& req, httplib::Response& res) {
    auto log = get_logger();

    if (!config_.registration_enabled) {
        json_error(res, 403, "Registration is disabled");
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
    account.password_hash = hash_password(password, config_.password_hash_cost);
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

    res.set_header("Set-Cookie", "session=" + session_id + "; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800");
    res.status = 201;
    res.set_content(response.dump(), "application/json");
}

void AccountHandler::handle_login(const httplib::Request& req, httplib::Response& res) {
    auto log = get_logger();

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

    auto account = store_.get_account_by_username(username);
    if (!account || account->password_hash.empty()) {
        json_error(res, 401, "Invalid username or password");
        return;
    }

    if (!verify_password(password, account->password_hash)) {
        json_error(res, 401, "Invalid username or password");
        return;
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

    res.set_header("Set-Cookie", "session=" + session_id + "; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800");
    res.set_content(response.dump(), "application/json");
}

void AccountHandler::handle_logout(const httplib::Request& req, httplib::Response& res) {
    auto account_id = get_session_account(req);
    if (account_id.empty()) {
        json_error(res, 401, "Not authenticated");
        return;
    }

    // Delete the session
    if (req.has_header("Cookie")) {
        auto cookie = req.get_header_value("Cookie");
        auto pos = cookie.find("session=");
        if (pos != std::string::npos) {
            auto start = pos + 8;
            auto end = cookie.find(';', start);
            auto session_id = (end != std::string::npos) ? cookie.substr(start, end - start) : cookie.substr(start);
            store_.delete_session(session_id);
        }
    }

    res.set_header("Set-Cookie", "session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
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
        account->password_hash = hash_password(new_password, config_.password_hash_cost);
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

    // Verify the session belongs to the authenticated user
    auto session = store_.get_session(target_session_id);
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

    auto secret = bsfchat::generate_totp_secret();
    auto backup_codes = bsfchat::generate_backup_codes(8);
    auto uri = bsfchat::totp_provisioning_uri(secret, account->username, "BSFChat");

    json codes_json = backup_codes;
    store_.set_totp_secret(account_id, secret, codes_json.dump());

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

    auto totp = store_.get_totp(account_id);
    if (!totp) {
        json_error(res, 400, "2FA not set up - call setup first");
        return;
    }

    if (!bsfchat::verify_totp(totp->secret, code)) {
        json_error(res, 400, "Invalid code");
        return;
    }

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

    auto account_id = store_.validate_login_token(login_token);
    if (!account_id) {
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
        json_error(res, 401, "Invalid 2FA code");
        return;
    }

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

    res.set_header("Set-Cookie", "session=" + session_id + "; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800");
    res.set_content(response.dump(), "application/json");
}

} // namespace bsfchat::id
