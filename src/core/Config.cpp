#include "core/Config.h"
#include "core/Logger.h"

#include <toml++/toml.hpp>
#include <stdexcept>

namespace bsfchat::id {

Config Config::load(const std::string& path) {
    Config cfg;

    try {
        auto tbl = toml::parse_file(path);

        // [server]
        if (auto server = tbl["server"].as_table()) {
            cfg.server_name = server->get("name")->value_or(cfg.server_name);
            cfg.bind_address = server->get("bind_address")->value_or(cfg.bind_address);
            cfg.port = server->get("port")->value_or(cfg.port);
            cfg.issuer_url = server->get("issuer_url")->value_or(cfg.issuer_url);
        }

        // [database]
        if (auto db = tbl["database"].as_table()) {
            cfg.database_path = db->get("path")->value_or(cfg.database_path);
        }

        // [keys]
        if (auto keys = tbl["keys"].as_table()) {
            cfg.keys_path = keys->get("path")->value_or(cfg.keys_path);
        }

        // [auth]
        if (auto auth = tbl["auth"].as_table()) {
            cfg.registration_enabled = auth->get("registration_enabled")->value_or(cfg.registration_enabled);
            cfg.password_hash_cost = auth->get("password_hash_cost")->value_or(cfg.password_hash_cost);
        }

        // [tls]
        if (auto tls = tbl["tls"].as_table()) {
            cfg.tls_enabled = tls->get("enabled")->value_or(cfg.tls_enabled);
            cfg.tls_cert_file = tls->get("cert_file")->value_or(std::string{});
            cfg.tls_key_file = tls->get("key_file")->value_or(std::string{});
        }

    } catch (const toml::parse_error& e) {
        throw std::runtime_error(std::string("Failed to parse config: ") + e.what());
    }

    return cfg;
}

Config Config::defaults() {
    return Config{};
}

} // namespace bsfchat::id
