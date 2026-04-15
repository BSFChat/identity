#include "api/AccountHandler.h"
#include "crypto/PasswordHash.h"
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

} // namespace bsfchat::id
