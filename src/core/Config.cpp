#include "core/Config.h"
#include "core/ClientAddress.h"
#include "core/Logger.h"
#include "crypto/PasswordHash.h"

#include <toml++/toml.hpp>
#include <algorithm>
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

// Reads a string-or-array setting. Present-but-empty means "trust nothing",
// so the value replaces the default rather than appending to it.
void read_list(const toml::table* table, std::string_view key, std::vector<std::string>& out) {
    if (!table) return;
    auto node = table->get(key);
    if (!node) return;
    out.clear();
    if (auto arr = node->as_array()) {
        for (const auto& el : *arr) {
            if (auto s = el.value<std::string>()) out.push_back(*s);
        }
    } else if (auto s = node->value<std::string>()) {
        out.push_back(*s);
    }
}

// Parses every trusted-proxy entry (a typo must fail startup, not silently
// drop the one entry that separates per-client limits from one shared
// bucket), merges the acknowledged public ranges in, and warns about ranges
// that reach into public address space. A condensed version of the chat
// server's Config::validate() check for the same keys.
void validate_trusted_proxies(Config& cfg) {
    auto log = get_logger();
    struct Entry {
        std::string text;
        IpNetwork net;
        bool acknowledged;
    };
    std::vector<Entry> entries;
    const auto parse_all = [&](const std::vector<std::string>& list, const char* key,
                               bool acknowledged) {
        for (const auto& text : list) {
            auto net = IpNetwork::parse(text);
            if (!net) {
                throw std::runtime_error(std::string("auth.") + key + ": '" + text +
                                         "' is not an IP address or CIDR network");
            }
            entries.push_back({text, *net, acknowledged});
        }
    };
    parse_all(cfg.trusted_proxies, "trusted_proxies", false);
    parse_all(cfg.trusted_public_proxies, "trusted_public_proxies", true);
    for (const auto& text : cfg.trusted_public_proxies) {
        if (std::find(cfg.trusted_proxies.begin(), cfg.trusted_proxies.end(), text) ==
            cfg.trusted_proxies.end()) {
            cfg.trusted_proxies.push_back(text);
        }
    }

    // Trusting a network is believing its X-Forwarded-For: anything inside a
    // trusted public range picks its own rate-limit identity per request.
    // Warned rather than refused, as on the chat server, so an upgrade over a
    // working configuration cannot turn into an outage.
    const bool have_reason =
        cfg.trusted_public_proxies_reason.find_first_not_of(" \t\r\n") != std::string::npos;
    std::string unexplained;
    for (const auto& e : entries) {
        if (is_private_or_loopback_network(e.net)) continue;
        if (is_too_wide_to_be_a_proxy_fleet(e.net)) {
            log->warn("auth.{} contains '{}', which is not a proxy fleet but most of the "
                      "internet: every client inside it chooses its own X-Forwarded-For and so "
                      "escapes the per-address login limits. Replace it with the addresses your "
                      "proxy actually speaks from.",
                      e.acknowledged ? "trusted_public_proxies" : "trusted_proxies", e.text);
            continue;
        }
        if (!e.acknowledged) {
            if (!unexplained.empty()) unexplained += ", ";
            unexplained += e.text;
        } else if (!have_reason) {
            log->warn("auth.trusted_public_proxies lists '{}' but "
                      "auth.trusted_public_proxies_reason is empty; say whose ranges these are "
                      "and when you last refreshed them.", e.text);
        }
    }
    if (!unexplained.empty()) {
        log->warn("auth.trusted_proxies trusts public address space ({}). Every client inside "
                  "those ranges chooses its own rate-limit identity. If they are a CDN in front "
                  "of the origin, move them to auth.trusted_public_proxies with a "
                  "trusted_public_proxies_reason; otherwise remove them.", unexplained);
    }
    if (have_reason && !cfg.trusted_public_proxies.empty()) {
        log->info("Trusting {} public proxy range(s): {}", cfg.trusted_public_proxies.size(),
                  cfg.trusted_public_proxies_reason);
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
            read_list(auth, "trusted_proxies", cfg.trusted_proxies);
            read_list(auth, "trusted_public_proxies", cfg.trusted_public_proxies);
            read_into(auth, "trusted_public_proxies_reason", cfg.trusted_public_proxies_reason);
            read_into(auth, "refresh_token_idle_days", cfg.refresh_token_idle_days);
            read_into(auth, "refresh_token_max_lifetime_days", cfg.refresh_token_max_lifetime_days);

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
    if (cfg.refresh_token_max_lifetime_days < 1) cfg.refresh_token_max_lifetime_days = 1;
    if (cfg.refresh_token_idle_days < 1) cfg.refresh_token_idle_days = 1;
    if (cfg.refresh_token_idle_days > cfg.refresh_token_max_lifetime_days) {
        cfg.refresh_token_idle_days = cfg.refresh_token_max_lifetime_days;
    }

    validate_trusted_proxies(cfg);

    return cfg;
}

Config Config::defaults() {
    return Config{};
}

} // namespace bsfchat::id
