#include "api/AdminHandler.h"
#include "core/Logger.h"

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

std::string random_hex(int bytes) {
    std::vector<unsigned char> buf(bytes);
    RAND_bytes(buf.data(), bytes);
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (auto b : buf) ss << std::setw(2) << static_cast<int>(b);
    return ss.str();
}

void json_error(httplib::Response& res, int status, const std::string& error) {
    res.status = status;
    res.set_content(json{{"error", error}}.dump(), "application/json");
}

} // namespace

AdminHandler::AdminHandler(IdentityStore& store, AccountHandler& account_handler, const Config& config)
    : store_(store), account_handler_(account_handler), config_(config) {}

bool AdminHandler::require_admin(const httplib::Request& req, httplib::Response& res) {
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
            {"created_at", a.created_at}
        });
    }

    res.set_content(json{{"users", users}}.dump(), "application/json");
}

void AdminHandler::handle_disable_user(const httplib::Request& req, httplib::Response& res) {
    if (!require_admin(req, res)) return;

    // Extract user ID from path: /api/admin/users/{id}/disable
    auto path = req.path;
    auto start = std::string("/api/admin/users/").size();
    auto end = path.find("/disable", start);
    if (end == std::string::npos) {
        json_error(res, 400, "Invalid path");
        return;
    }
    auto user_id = path.substr(start, end - start);

    if (store_.disable_account(user_id)) {
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

    auto log = get_logger();

    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        json_error(res, 400, "Invalid JSON");
        return;
    }

    auto name = body.value("name", "");
    auto redirect_uris = body.value("redirect_uris", "");

    if (name.empty() || redirect_uris.empty()) {
        json_error(res, 400, "name and redirect_uris are required");
        return;
    }

    OAuthClient client;
    client.client_id = random_hex(16);
    client.client_secret = random_hex(32);
    client.name = name;
    client.redirect_uris = redirect_uris;
    client.created_at = now_seconds();

    if (!store_.create_oauth_client(client)) {
        json_error(res, 500, "Failed to create client");
        return;
    }

    log->info("OAuth client created: {} ({})", name, client.client_id);

    json response = {
        {"client_id", client.client_id},
        {"client_secret", client.client_secret},
        {"name", client.name},
        {"redirect_uris", client.redirect_uris}
    };

    res.status = 201;
    res.set_content(response.dump(), "application/json");
}

} // namespace bsfchat::id
