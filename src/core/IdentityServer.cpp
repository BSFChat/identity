#include "core/IdentityServer.h"
#include "core/Logger.h"
#include "api/AccountHandler.h"
#include "api/OidcHandler.h"
#include "api/AdminHandler.h"

#include <chrono>
#include <filesystem>

namespace bsfchat::id {

namespace {

// The desktop client binds an ephemeral loopback port and listens on
// /oauth/callback. Registering the full path (rather than a bare
// "http://localhost") lets redirect_uri_matches() relax only the port.
constexpr const char* kDesktopRedirectUris =
    R"(["http://127.0.0.1/oauth/callback","http://localhost/oauth/callback"])";

// The value shipped previously, which matched any path on any localhost port.
constexpr const char* kLegacyDesktopRedirectUris = R"(["http://localhost"])";

} // namespace

IdentityServer::IdentityServer(Config config)
    : config_(std::move(config)) {
    auto log = get_logger();

    // Ensure data directories exist
    auto db_dir = std::filesystem::path(config_.database_path).parent_path();
    if (!db_dir.empty()) std::filesystem::create_directories(db_dir);
    std::filesystem::create_directories(config_.keys_path);

    store_ = std::make_unique<IdentityStore>(config_.database_path);
    store_->initialize();

    // Auto-create the well-known desktop client if it doesn't exist
    auto desktop = store_->get_oauth_client("bsfchat-desktop");
    if (!desktop.has_value()) {
        OAuthClient client;
        client.client_id = "bsfchat-desktop";
        client.client_secret = ""; // public client — authenticates via PKCE
        client.name = "BSFChat Desktop";
        client.redirect_uris = kDesktopRedirectUris;
        client.created_at = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        store_->create_oauth_client(client);
    } else if (desktop->redirect_uris == kLegacyDesktopRedirectUris) {
        // Narrow the existing registration to the path the client actually
        // uses. Left alone if an operator has customised it.
        store_->update_oauth_client_redirect_uris("bsfchat-desktop", kDesktopRedirectUris);
        log->info("Tightened bsfchat-desktop redirect_uris to the loopback callback path");
    }

    key_manager_ = std::make_unique<KeyManager>(config_.keys_path);
    http_server_ = std::make_unique<HttpServer>(config_);

    register_routes();
    start_sweeper();
}

IdentityServer::~IdentityServer() {
    stop();
    stop_sweeper();
}

void IdentityServer::start_sweeper() {
    sweeper_ = std::thread([this]() {
        auto log = get_logger();
        while (true) {
            std::unique_lock lock(sweeper_mutex_);
            sweeper_cv_.wait_for(lock, std::chrono::seconds(config_.session_sweep_interval),
                                 [this] { return stopping_.load(); });
            if (stopping_.load()) return;
            lock.unlock();

            try {
                store_->sweep_expired();
                if (account_handler_) account_handler_->prune_limiters();
            } catch (const std::exception& e) {
                log->warn("Expiry sweep failed: {}", e.what());
            }
        }
    });
}

void IdentityServer::stop_sweeper() {
    if (!sweeper_.joinable()) return;
    {
        std::lock_guard lock(sweeper_mutex_);
        stopping_ = true;
    }
    sweeper_cv_.notify_all();
    sweeper_.join();
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
    account_handler_ = account_handler;
    auto oidc_handler = std::make_shared<OidcHandler>(*store_, *key_manager_, *account_handler, config_);
    auto admin_handler = std::make_shared<AdminHandler>(*store_, *account_handler, config_);

    // OIDC discovery
    svr.Get("/.well-known/openid-configuration",
            [h = oidc_handler](const httplib::Request& req, httplib::Response& res) { h->handle_discovery(req, res); });

    // OIDC endpoints
    svr.Get("/authorize",
            [h = oidc_handler](const httplib::Request& req, httplib::Response& res) { h->handle_authorize(req, res); });
    svr.Post("/authorize/decision",
             [h = oidc_handler](const httplib::Request& req, httplib::Response& res) { h->handle_authorize_decision(req, res); });
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

    // Server memberships — track which BSFChat servers a user has joined
    // so the client can restore all connections from a single identity login.
    svr.Get("/api/servers",
            [h = account_handler](const httplib::Request& req, httplib::Response& res) { h->handle_list_servers(req, res); });
    svr.Post("/api/servers",
             [h = account_handler](const httplib::Request& req, httplib::Response& res) { h->handle_add_server(req, res); });
    svr.Post("/api/servers/remove",
             [h = account_handler](const httplib::Request& req, httplib::Response& res) { h->handle_remove_server(req, res); });

    // Admin endpoints
    svr.Get("/api/admin/users",
            [h = admin_handler](const httplib::Request& req, httplib::Response& res) { h->handle_list_users(req, res); });
    svr.Post(R"(/api/admin/users/([^/]+)/disable)",
             [h = admin_handler](const httplib::Request& req, httplib::Response& res) { h->handle_disable_user(req, res); });
    svr.Get("/api/admin/clients",
            [h = admin_handler](const httplib::Request& req, httplib::Response& res) { h->handle_list_clients(req, res); });
    svr.Post("/api/admin/clients",
             [h = admin_handler](const httplib::Request& req, httplib::Response& res) { h->handle_create_client(req, res); });

    // Static files — AFTER all route registrations so API handlers take
    // priority over the mount point's 404 for paths like /api/servers.
    svr.set_mount_point("/", "web");
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
