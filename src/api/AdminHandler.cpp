#include "api/AdminHandler.h"
#include "core/Logger.h"
#include "core/WebUtil.h"
#include "crypto/Secrets.h"

#include <nlohmann/json.hpp>

#include <chrono>

namespace bsfchat::id {

namespace {

using json = nlohmann::json;

int64_t now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// Checked CSPRNG: an unchecked RAND_bytes failure used to produce an
// all-zero client secret (security audit L3).
std::string random_hex(int bytes) {
    return secure_random_hex(static_cast<size_t>(bytes));
}

// /api/admin/users/{id}/<action>
std::string user_id_from_path(const std::string& path, const std::string& action) {
    auto start = std::string("/api/admin/users/").size();
    auto end = path.find("/" + action, start);
    if (path.rfind("/api/admin/users/", 0) != 0 || end == std::string::npos) return "";
    return path.substr(start, end - start);
}

void json_error(httplib::Response& res, int status, const std::string& error) {
    res.status = status;
    res.set_content(json{{"error", error}}.dump(), "application/json");
}

} // namespace

AdminHandler::AdminHandler(IdentityStore& store, AccountHandler& account_handler, const Config& config)
    : store_(store), account_handler_(account_handler), config_(config) {}

bool AdminHandler::require_admin(const httplib::Request& req, httplib::Response& res) {
    // get_session_account() already refuses a disabled account's session.
    auto account_id = account_handler_.get_session_account(req);
    if (account_id.empty()) {
        json_error(res, 401, "Not authenticated");
        return false;
    }

    auto account = store_.get_account_by_id(account_id);
    if (!account || !account->is_admin) {
        json_error(res, 403, "Admin access required");
        return false;
    }

    return true;
}

void AdminHandler::handle_list_users(const httplib::Request& req, httplib::Response& res) {
    if (!require_admin(req, res)) return;

    auto accounts = store_.list_accounts();
    json users = json::array();
    for (const auto& a : accounts) {
        users.push_back({
            {"id", a.id},
            {"username", a.username},
            {"email", a.email},
            {"display_name", a.display_name},
            {"is_admin", a.is_admin},
            {"created_at", a.created_at},
            {"disabled", a.disabled()},
            {"disabled_at", a.disabled_at}
        });
    }

    res.set_content(json{{"users", users}}.dump(), "application/json");
}

void AdminHandler::handle_disable_user(const httplib::Request& req, httplib::Response& res) {
    if (!require_admin(req, res)) return;
    if (!account_handler_.reject_unsafe_request(req, res, /*body_required=*/false)) return;

    auto user_id = user_id_from_path(req.path, "disable");
    if (user_id.empty()) {
        json_error(res, 400, "Invalid path");
        return;
    }
    // Disabling yourself signs you out in the same transaction and leaves
    // nobody who can undo it from the portal; accounts are made admin only by
    // editing the database.
    if (user_id == account_handler_.get_session_account(req)) {
        json_error(res, 400, "You cannot disable your own account");
        return;
    }

    // Security audit H1: this used to blank the password hash and nothing
    // else, leaving the account's sessions, access tokens and refresh tokens
    // working. disable_account() now marks the account disabled and deletes
    // every credential it holds in one transaction.
    if (store_.disable_account(user_id)) {
        get_logger()->info("Account {} disabled by an administrator; all its credentials revoked", user_id);
        res.set_content(json{{"success", true}}.dump(), "application/json");
    } else {
        json_error(res, 404, "User not found");
    }
}

void AdminHandler::handle_enable_user(const httplib::Request& req, httplib::Response& res) {
    if (!require_admin(req, res)) return;
    if (!account_handler_.reject_unsafe_request(req, res, /*body_required=*/false)) return;

    auto user_id = user_id_from_path(req.path, "enable");
    if (user_id.empty()) {
        json_error(res, 400, "Invalid path");
        return;
    }
    // Only the flag is cleared: the user signs in again with the password
    // they had, and nothing that was revoked comes back.
    if (store_.enable_account(user_id)) {
        get_logger()->info("Account {} re-enabled by an administrator", user_id);
        res.set_content(json{{"success", true}}.dump(), "application/json");
    } else {
        json_error(res, 404, "User not found");
    }
}

void AdminHandler::handle_list_clients(const httplib::Request& req, httplib::Response& res) {
    if (!require_admin(req, res)) return;

    auto clients = store_.list_oauth_clients();
    json result = json::array();
    for (const auto& c : clients) {
        result.push_back({
            {"client_id", c.client_id},
            {"name", c.name},
            {"redirect_uris", c.redirect_uris},
            {"created_at", c.created_at}
        });
    }

    res.set_content(json{{"clients", result}}.dump(), "application/json");
}

void AdminHandler::handle_create_client(const httplib::Request& req, httplib::Response& res) {
    if (!require_admin(req, res)) return;

    if (!account_handler_.reject_unsafe_request(req, res)) return;

    auto log = get_logger();

    auto body = json::parse(req.body, nullptr, false);
    if (body.is_discarded() || !body.is_object()) {
        json_error(res, 400, "Invalid JSON");
        return;
    }

    auto name = body.contains("name") && body["name"].is_string() ? body["name"].get<std::string>() : "";
    auto redirect_uris = body.contains("redirect_uris") && body["redirect_uris"].is_string()
                             ? body["redirect_uris"].get<std::string>() : "";

    if (name.empty() || redirect_uris.empty() || name.size() > 128) {
        json_error(res, 400, "name (1-128 characters) and redirect_uris are required");
        return;
    }

    // /authorize parses this as a JSON array of absolute URIs; a value that is
    // not one used to be stored and then silently match nothing.
    auto uris = json::parse(redirect_uris, nullptr, false);
    bool uris_ok = uris.is_array() && !uris.empty();
    if (uris_ok) {
        for (const auto& u : uris) {
            if (!u.is_string() || !parse_uri(u.get<std::string>()).valid ||
                parse_uri(u.get<std::string>()).has_fragment) {
                uris_ok = false;
                break;
            }
        }
    }
    if (!uris_ok) {
        json_error(res, 400, "redirect_uris must be a JSON array of absolute URIs without fragments");
        return;
    }

    // The store keeps only a digest of the secret (security audit L5); this
    // response is the one time the plaintext exists outside the client.
    const auto secret = random_hex(32);
    OAuthClient client;
    client.client_id = random_hex(16);
    client.client_secret = secret;
    client.name = name;
    client.redirect_uris = redirect_uris;
    client.created_at = now_seconds();

    if (!store_.create_oauth_client(client)) {
        json_error(res, 500, "Failed to create client");
        return;
    }

    log->info("OAuth client created: {}", client.client_id);

    json response = {
        {"client_id", client.client_id},
        {"client_secret", secret},
        {"name", client.name},
        {"redirect_uris", client.redirect_uris}
    };

    res.status = 201;
    res.set_content(response.dump(), "application/json");
}

} // namespace bsfchat::id
