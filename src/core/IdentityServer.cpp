#include "core/IdentityServer.h"
#include "core/Logger.h"
#include "api/AccountHandler.h"
#include "api/OidcHandler.h"
#include "api/SsoHandler.h"
#include "api/AdminHandler.h"

#include <chrono>
#include <filesystem>

namespace bsfchat::id {

IdentityServer::IdentityServer(Config config)
    : config_(std::move(config)) {

    // Ensure data directories exist
    auto db_dir = std::filesystem::path(config_.database_path).parent_path();
    if (!db_dir.empty()) std::filesystem::create_directories(db_dir);
    std::filesystem::create_directories(config_.keys_path);

    store_ = std::make_unique<IdentityStore>(config_.database_path);
    store_->initialize();

    // Auto-create the well-known desktop client if it doesn't exist
    if (!store_->get_oauth_client("bsfchat-desktop").has_value()) {
        OAuthClient client;
        client.client_id = "bsfchat-desktop";
        client.client_secret = "";
        client.name = "BSFChat Desktop";
        client.redirect_uris = R"(["http://localhost"])";
        client.created_at = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        store_->create_oauth_client(client);
    }

    key_manager_ = std::make_unique<KeyManager>(config_.keys_path);
    http_server_ = std::make_unique<HttpServer>(config_);

    register_routes();
}

IdentityServer::~IdentityServer() {
    stop();
}

void IdentityServer::register_routes() {
    auto& svr = http_server_->server();

    // Set CORS headers for all responses
    svr.set_pre_routing_handler([](const httplib::Request&, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Authorization, Content-Type");
        return httplib::Server::HandlerResponse::Unhandled;
    });

    // Handle CORS preflight
    svr.Options(R"(.*)", [](const httplib::Request&, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Authorization, Content-Type");
        res.set_content("", "text/plain");
    });

    auto account_handler = std::make_shared<AccountHandler>(*store_, config_);
    auto oidc_handler = std::make_shared<OidcHandler>(*store_, *key_manager_, *account_handler, config_);
    auto sso_handler = std::make_shared<SsoHandler>(*store_, config_);
    auto admin_handler = std::make_shared<AdminHandler>(*store_, *account_handler, config_);

    // Static files — serve web directory
    svr.set_mount_point("/", "web");

    // OIDC discovery
    svr.Get("/.well-known/openid-configuration",
            [h = oidc_handler](const httplib::Request& req, httplib::Response& res) { h->handle_discovery(req, res); });

    // OIDC endpoints
    svr.Get("/authorize",
            [h = oidc_handler](const httplib::Request& req, httplib::Response& res) { h->handle_authorize(req, res); });
    svr.Post("/token",
             [h = oidc_handler](const httplib::Request& req, httplib::Response& res) { h->handle_token(req, res); });
    svr.Get("/userinfo",
            [h = oidc_handler](const httplib::Request& req, httplib::Response& res) { h->handle_userinfo(req, res); });
    svr.Get("/jwks",
            [h = oidc_handler](const httplib::Request& req, httplib::Response& res) { h->handle_jwks(req, res); });
    svr.Post("/token/revoke",
             [h = oidc_handler](const httplib::Request& req, httplib::Response& res) { h->handle_revoke(req, res); });

    // Account endpoints
    svr.Post("/register",
             [h = account_handler](const httplib::Request& req, httplib::Response& res) { h->handle_register(req, res); });
    svr.Post("/api/login",
             [h = account_handler](const httplib::Request& req, httplib::Response& res) { h->handle_login(req, res); });
    svr.Post("/api/login/2fa",
             [h = account_handler](const httplib::Request& req, httplib::Response& res) { h->handle_login_2fa(req, res); });
    svr.Post("/api/logout",
             [h = account_handler](const httplib::Request& req, httplib::Response& res) { h->handle_logout(req, res); });
    svr.Get("/api/profile",
            [h = account_handler](const httplib::Request& req, httplib::Response& res) { h->handle_get_profile(req, res); });
    svr.Put("/api/profile",
            [h = account_handler](const httplib::Request& req, httplib::Response& res) { h->handle_update_profile(req, res); });

    // Session management
    svr.Get("/api/user/sessions",
            [h = account_handler](const httplib::Request& req, httplib::Response& res) { h->handle_list_sessions(req, res); });
    svr.Delete(R"(/api/user/sessions/(.+))",
               [h = account_handler](const httplib::Request& req, httplib::Response& res) { h->handle_revoke_session(req, res); });

    // 2FA endpoints
    svr.Get("/api/user/2fa/status",
            [h = account_handler](const httplib::Request& req, httplib::Response& res) { h->handle_2fa_status(req, res); });
    svr.Post("/api/user/2fa/setup",
             [h = account_handler](const httplib::Request& req, httplib::Response& res) { h->handle_2fa_setup(req, res); });
    svr.Post("/api/user/2fa/verify",
             [h = account_handler](const httplib::Request& req, httplib::Response& res) { h->handle_2fa_verify(req, res); });
    svr.Post("/api/user/2fa/disable",
             [h = account_handler](const httplib::Request& req, httplib::Response& res) { h->handle_2fa_disable(req, res); });

    // Admin endpoints
    svr.Get("/api/admin/users",
            [h = admin_handler](const httplib::Request& req, httplib::Response& res) { h->handle_list_users(req, res); });
    svr.Post(R"(/api/admin/users/([^/]+)/disable)",
             [h = admin_handler](const httplib::Request& req, httplib::Response& res) { h->handle_disable_user(req, res); });
    svr.Get("/api/admin/clients",
            [h = admin_handler](const httplib::Request& req, httplib::Response& res) { h->handle_list_clients(req, res); });
    svr.Post("/api/admin/clients",
             [h = admin_handler](const httplib::Request& req, httplib::Response& res) { h->handle_create_client(req, res); });
}

void IdentityServer::start() {
    auto log = get_logger();
    log->info("BSFChat ID service v{} starting", "0.1.0");
    log->info("Server name: {}", config_.server_name);
    log->info("Issuer URL: {}", config_.issuer_url);
    log->info("Database: {}", config_.database_path);
    log->info("Registration: {}", config_.registration_enabled ? "enabled" : "disabled");

    http_server_->start();
}

void IdentityServer::stop() {
    if (http_server_) http_server_->stop();
}

} // namespace bsfchat::id
