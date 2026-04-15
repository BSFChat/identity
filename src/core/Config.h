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
    int password_hash_cost = 12;

    // TLS
    bool tls_enabled = false;
    std::string tls_cert_file;
    std::string tls_key_file;

    static Config load(const std::string& path);
    static Config defaults();
};

} // namespace bsfchat::id
