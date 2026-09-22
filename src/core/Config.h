#pragma once

#include <string>
#include <vector>

namespace bsfchat::id {

struct Config {
    // Server
    std::string server_name = "id.bsfchat.local";
    std::string bind_address = "0.0.0.0";
    int port = 8480;
    std::string issuer_url = "http://localhost:8480";

    // Database
    std::string database_path = "./data/identity.db";

    // Keys
    std::string keys_path = "./data/keys/";

    // Auth
    bool registration_enabled = true;
    // PBKDF2-HMAC-SHA256 iteration count for newly stored passwords. Existing
    // hashes record their own cost and keep verifying regardless of this value.
    int password_hash_iterations = 600000;
    // Emit `Secure` on the session cookie. Browsers treat http://localhost as a
    // trustworthy origin, so this stays safe for local development; only turn
    // it off when serving plain HTTP on a non-loopback hostname.
    bool cookie_secure = true;

    // Anti-bruteforce
    int login_rate_limit = 10;        // login attempts per window, per client IP
    int login_rate_window = 300;      // seconds
    int login_max_failures = 8;       // consecutive failures before lockout
    int login_lockout_seconds = 900;
    int totp_max_attempts = 5;        // wrong codes before the login token dies

    // Reverse proxies whose X-Forwarded-For is believed (security audit H2).
    //
    // Behind a proxy the socket peer is the proxy for every request, so
    // without this list every per-address limit above puts the whole internet
    // in one bucket. core/ClientAddress.h says how the client is derived; the
    // semantics are the chat server's `auth.trusted_proxies`, deliberately, so
    // one deployment note covers both services.
    //
    // EMPTY by default — trust nothing, not even loopback. That is stricter
    // than the chat server (which trusts loopback) because this service is
    // normally reached through Docker's port publishing, where the peer is the
    // bridge gateway rather than loopback, so a loopback default would buy
    // nothing and would still be one more thing trusted without being asked
    // for. An unset list degrades to "everyone behind the proxy shares a
    // bucket" and the service warns about it; it never believes the header.
    std::vector<std::string> trusted_proxies;
    // Public ranges trusted on purpose (a CDN in front of the origin), with a
    // stated reason. Merged into trusted_proxies at load; kept apart so the
    // startup check can tell an acknowledged range from one that turned up.
    std::vector<std::string> trusted_public_proxies;
    std::string trusted_public_proxies_reason;

    // OAuth refresh tokens (security audit H4). A refresh token rotates on
    // every use; each rotation extends it by the idle lifetime but never past
    // the absolute lifetime of the grant it descends from. Before, rotation
    // reset a 30-day clock every time, so a token in regular use never expired.
    int refresh_token_idle_days = 30;
    int refresh_token_max_lifetime_days = 90;

    // Housekeeping
    int session_sweep_interval = 3600; // seconds between expiry sweeps

    // NOTE: TLS is intentionally not handled here. The service speaks plain
    // HTTP and expects TLS termination at the reverse proxy in front of it.

    static Config load(const std::string& path);
    static Config defaults();
};

} // namespace bsfchat::id
