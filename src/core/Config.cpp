#include "core/Config.h"
#include "core/Logger.h"
#include "crypto/PasswordHash.h"

#include <toml++/toml.hpp>
#include <stdexcept>

namespace bsfchat::id {

namespace {

// toml::table::get() returns a null node* for an absent key, so the
// `table->get("x")->value_or(default)` idiom segfaults on any config that omits
// an optional setting. Read through this helper instead.
template <typename T>
void read_into(const toml::table* table, std::string_view key, T& out) {
    if (!table) return;
    if (auto node = table->get(key)) {
        out = node->value_or(out);
    }
}

} // namespace

Config Config::load(const std::string& path) {
    Config cfg;

    try {
        auto tbl = toml::parse_file(path);

        // [server]
        if (auto server = tbl["server"].as_table()) {
            read_into(server, "name", cfg.server_name);
            read_into(server, "bind_address", cfg.bind_address);
            read_into(server, "port", cfg.port);
            read_into(server, "issuer_url", cfg.issuer_url);
        }

        // [database]
        if (auto db = tbl["database"].as_table()) {
            read_into(db, "path", cfg.database_path);
        }

        // [keys]
        if (auto keys = tbl["keys"].as_table()) {
            read_into(keys, "path", cfg.keys_path);
        }

        // [auth]
        if (auto auth = tbl["auth"].as_table()) {
            read_into(auth, "registration_enabled", cfg.registration_enabled);
            read_into(auth, "password_hash_iterations", cfg.password_hash_iterations);
            read_into(auth, "cookie_secure", cfg.cookie_secure);
            read_into(auth, "login_rate_limit", cfg.login_rate_limit);
            read_into(auth, "login_rate_window", cfg.login_rate_window);
            read_into(auth, "login_max_failures", cfg.login_max_failures);
            read_into(auth, "login_lockout_seconds", cfg.login_lockout_seconds);
            read_into(auth, "totp_max_attempts", cfg.totp_max_attempts);

            // `password_hash_cost` was a log2 exponent whose shipped default of
            // 12 meant only 4,096 iterations. Refuse to honour it silently.
            if (auth->contains("password_hash_cost")) {
                get_logger()->warn(
                    "[auth] password_hash_cost is obsolete and ignored; "
                    "use password_hash_iterations (currently {})", cfg.password_hash_iterations);
            }
        }

        // [tls] used to be parsed here and never used for anything. TLS is
        // terminated by the reverse proxy; warn rather than pretend.
        if (tbl.contains("tls")) {
            get_logger()->warn(
                "[tls] is not supported by this service and is ignored — "
                "terminate TLS at your reverse proxy");
        }

        // [housekeeping]
        if (auto hk = tbl["housekeeping"].as_table()) {
            read_into(hk, "session_sweep_interval", cfg.session_sweep_interval);
        }

    } catch (const toml::parse_error& e) {
        throw std::runtime_error(std::string("Failed to parse config: ") + e.what());
    }

    if (cfg.password_hash_iterations < kMinPbkdf2Iterations) {
        get_logger()->warn("password_hash_iterations={} is below the {} minimum; clamping",
                           cfg.password_hash_iterations, kMinPbkdf2Iterations);
        cfg.password_hash_iterations = kMinPbkdf2Iterations;
    }
    if (cfg.session_sweep_interval < 60) cfg.session_sweep_interval = 60;
    if (cfg.login_rate_limit < 1) cfg.login_rate_limit = 1;
    if (cfg.login_rate_window < 1) cfg.login_rate_window = 1;
    if (cfg.login_max_failures < 1) cfg.login_max_failures = 1;
    if (cfg.login_lockout_seconds < 1) cfg.login_lockout_seconds = 1;
    if (cfg.totp_max_attempts < 1) cfg.totp_max_attempts = 1;

    return cfg;
}

Config Config::defaults() {
    return Config{};
}

} // namespace bsfchat::id
