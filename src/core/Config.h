#pragma once

#include <string>

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

    // Housekeeping
    int session_sweep_interval = 3600; // seconds between expiry sweeps

    // NOTE: TLS is intentionally not handled here. The service speaks plain
    // HTTP and expects TLS termination at the reverse proxy in front of it.

    static Config load(const std::string& path);
    static Config defaults();
};

} // namespace bsfchat::id
